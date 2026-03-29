"""OSINT intelligence engines — VirusTotal, WHOIS, IP, and screenshots.

All network-bound operations live here so the rest of the codebase
never touches ``requests`` directly.
"""

import base64
import re
import socket
import subprocess
import time
import urllib.parse
from typing import Dict, Optional, Tuple

import requests
import streamlit as st
import tldextract

from core.config import AppConfig


class OSINTEngine:
    """Performs all external intelligence-gathering operations.

    Owns its own ``requests.Session`` with connection pooling and
    automatic retries.

    Args:
        config: An ``AppConfig`` instance providing the VT API key
                and domain whitelist.
    """

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._session: Optional[requests.Session] = None

    # ── HTTP session (lazy-initialised, reusable) ──────────────────

    def _get_session(self) -> requests.Session:
        """Return (or create) a pooled HTTP session."""
        if self._session is None:
            session = requests.Session()
            session.headers.update({"User-Agent": "PhishingHunter/1.0"})
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=5,
                pool_maxsize=10,
                max_retries=requests.adapters.Retry(total=2, backoff_factor=0.3),
            )
            session.mount("https://", adapter)
            session.mount("http://", adapter)
            self._session = session
        return self._session

    # ── Public intelligence methods ────────────────────────────────

    @st.cache_data(ttl=3600, show_spinner=False)
    def get_screenshot(_self, url: str) -> Optional[str]:
        """Capture a remote screenshot via the Microlink API."""
        try:
            session = _self._get_session()
            res = session.get(
                f"https://api.microlink.io/?url={url}&screenshot=true&meta=false",
                timeout=10,
            )
            if res.status_code == 200:
                return res.json().get("data", {}).get("screenshot", {}).get("url")
        except Exception:
            pass
        return None

    @st.cache_data(ttl=3600, show_spinner=False)
    def get_hosting_ip(_self, url: str) -> Tuple[str, str]:
        """Resolve the URL's IP address and hosting organisation."""
        try:
            hostname = urllib.parse.urlparse(url).netloc or url
            ip_address = socket.gethostbyname(hostname)
            session = _self._get_session()
            res = session.get(f"https://ipinfo.io/{ip_address}/json", timeout=5)
            org = (
                res.json().get("org", "Not Found")
                if res.status_code == 200
                else "Detection Failed"
            )
            return ip_address, org
        except Exception:
            return "Detection Failed", "Detection Failed"

    @st.cache_data(ttl=3600, show_spinner=False)
    def get_whois_data(_self, domain: str) -> Dict[str, str]:
        """Run a system ``whois`` lookup and extract key fields."""
        data = {
            "registrar": "Not Found",
            "abuse_email": "",
            "creation_date": "Not Found",
            "expiry_date": "Not Found",
        }
        try:
            d = domain.replace("https://", "").replace("http://", "").split("/")[0]
            result = subprocess.run(
                ["whois", d], capture_output=True, text=True, timeout=10
            )
            raw = result.stdout

            reg = re.search(r"(?i)Registrar:\s*(.+)", raw)
            if reg:
                data["registrar"] = reg.group(1).strip()

            c_date = re.search(
                r"(?i)(Creation Date|Created On|Registration Time):\s*([^\n]+)", raw
            )
            if c_date:
                data["creation_date"] = c_date.group(2).strip()[:10]

            e_date = re.search(
                r"(?i)(Registry Expiry Date|Expiration Date):\s*([^\n]+)", raw
            )
            if e_date:
                data["expiry_date"] = e_date.group(2).strip()[:10]

            ab_email = re.search(
                r"(?i)Registrar Abuse Contact Email:\s*([^\s]+)", raw
            )
            if ab_email:
                data["abuse_email"] = ab_email.group(1).strip()
            else:
                emails = re.findall(
                    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", raw
                )
                abuse_list = [e for e in emails if "abuse" in e.lower()]
                if abuse_list:
                    data["abuse_email"] = abuse_list[0]
        except Exception:
            pass
        return data

    def scan_url(self, url: str, status_callback=None) -> dict:
        """Run the full VirusTotal scan pipeline for a URL.

        Args:
            url: The suspect URL to analyse.
            status_callback: Optional callable receiving status strings.

        Returns:
            A dict with keys: url, domain, threat, ip, hosting, whois,
            abuse_email, image.
        """
        _cb = status_callback or (lambda msg: None)
        session = self._get_session()
        api_key = self._config.vt_api_key

        extracted = tldextract.extract(url)
        root_domain = f"{extracted.domain}.{extracted.suffix}"
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        # --- VirusTotal ---
        _cb("📡 Querying VirusTotal threat intelligence database...")
        threat = "Under Evaluation"
        try:
            res = session.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": api_key},
                timeout=5,
            )
            if res.status_code == 404:
                _cb("⚠️ Unknown domain — submitting for deep cloud analysis (15s)...")
                session.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers={
                        "x-apikey": api_key,
                        "content-type": "application/x-www-form-urlencoded",
                    },
                    data={"url": url},
                )
                time.sleep(15)
                res = session.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers={"x-apikey": api_key},
                    timeout=5,
                )

            if res.status_code == 200:
                stats = res.json()["data"]["attributes"]["last_analysis_stats"]
                mal = stats.get("malicious", 0)
                sus = stats.get("suspicious", 0)
                if mal > 0 or sus > 0:
                    threat = f"DANGEROUS ({mal} Malicious, {sus} Spam/Suspicious)"
                else:
                    threat = "Clean / Zero-Day (0 Detections)"
            else:
                threat = "VT Analysis Pending/Error"
        except Exception:
            threat = "Global Network Error"

        # --- WHOIS & IP ---
        _cb("🔎 Running WHOIS & RDAP reconnaissance...")
        ip_addr, hosting_org = self.get_hosting_ip(url)
        whois_data = self.get_whois_data(root_domain)

        abuse_email = whois_data["abuse_email"]
        if not abuse_email:
            abuse_email = (
                "abuse@cloudflare.com"
                if "cloudflare" in hosting_org.lower()
                else f"abuse@{root_domain}"
            )

        # --- Screenshot ---
        _cb("📸 Capturing visual evidence via stealth screenshot...")
        img_url = self.get_screenshot(url)

        return {
            "url": url,
            "domain": root_domain,
            "threat": threat,
            "ip": ip_addr,
            "hosting": hosting_org,
            "whois": whois_data,
            "abuse_email": abuse_email,
            "image": img_url,
        }
