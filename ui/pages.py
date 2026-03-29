"""Page renderers — each public method draws one page of the application.

All Streamlit widget calls are localised here so the main entry point
stays declarative.
"""

import random
import string
from typing import Optional

import streamlit as st

from core.config import AppConfig
from core.database import DatabaseManager
from core.osint import OSINTEngine
from ui.components import UIComponents


class PageRenderer:
    """Renders the four public pages: home, educate, report, donate.

    Args:
        config:     Application configuration.
        db:         Database manager for stats/reports.
        osint:      OSINT engine for URL scanning.
        components: Shared UI component factory.
    """

    def __init__(
        self,
        config: AppConfig,
        db: DatabaseManager,
        osint: OSINTEngine,
        components: UIComponents,
    ) -> None:
        self._config = config
        self._db = db
        self._osint = osint
        self._ui = components

        # ── Initialise session state ───────────────────────────────
        if "scan_result" not in st.session_state:
            st.session_state.scan_result = None
        if "captcha_code" not in st.session_state:
            st.session_state.captcha_code = self._generate_captcha()

    # ── Helpers ────────────────────────────────────────────────────

    @staticmethod
    def _generate_captcha(length: int = 5) -> str:
        """Return a random alphanumeric captcha code."""
        return "".join(
            random.choices(string.ascii_uppercase + string.digits, k=length)
        )

    # ── Page: Home ─────────────────────────────────────────────────

    def render_home(self) -> None:
        """Display the hero section and live threat-statistics dashboard."""
        st.markdown(self._ui.hero(), unsafe_allow_html=True)

        total_reports, total_success = self._db.get_stats()
        kill_rate = (
            round((total_success / total_reports) * 100, 1)
            if total_reports > 0
            else 0
        )
        st.markdown(
            self._ui.stats_grid(total_reports, total_success, kill_rate),
            unsafe_allow_html=True,
        )

    # ── Page: Educate ──────────────────────────────────────────────

    def render_educate(self) -> None:
        """Display phishing-awareness educational content."""
        st.markdown(self._ui.educate_section(), unsafe_allow_html=True)

    # ── Page: Report (scan + results) ──────────────────────────────

    def render_report(self) -> None:
        """Display the URL scanner, captcha, and scan results."""
        st.markdown(self._ui.report_header(), unsafe_allow_html=True)

        # --- Input form ---
        with st.container():
            url_input = st.text_input(
                "Scan a suspect URL",
                placeholder="Enter a URL to analyse — e.g. https://suspicious-site.com",
                label_visibility="collapsed",
            ).strip()
            if url_input and not url_input.startswith("http"):
                url_input = "https://" + url_input

            c_cap1, c_cap2 = st.columns([1, 2])
            c_cap1.info(
                f"**Security Verification:**\n### {st.session_state.captcha_code}"
            )
            user_captcha = (
                c_cap2.text_input("Enter verification code to proceed:", max_chars=5)
                .strip()
                .upper()
            )

            if st.button(
                "⚡ LAUNCH THREAT ANALYSIS",
                use_container_width=True,
                type="primary",
            ):
                self._handle_scan(url_input, user_captcha)

        # --- Results ---
        self._render_scan_results()

    def _handle_scan(self, url_input: str, user_captcha: str) -> None:
        """Validate captcha, run the OSINT scan, and save the report."""
        if not url_input:
            st.warning("⚠️ Target URL required — please provide a suspect domain.")
            return

        if user_captcha != st.session_state.captcha_code:
            st.error("❌ Verification failed. Generating new security token...")
            st.session_state.captcha_code = self._generate_captcha()
            st.rerun()

        # Captcha passed — regenerate for next use
        st.session_state.captcha_code = self._generate_captcha()

        import tldextract

        extracted = tldextract.extract(url_input)
        root_domain = f"{extracted.domain}.{extracted.suffix}"

        if self._config.is_whitelisted(root_domain):
            st.success("✅ Domain is verified legitimate — no action required.")
            st.session_state.scan_result = None
            return

        with st.status(
            "Executing threat analysis pipeline...", expanded=True
        ) as status:
            result = self._osint.scan_url(url_input, status_callback=st.write)
            status.update(
                label="✅ Analysis complete — intelligence report ready",
                state="complete",
                expanded=False,
            )

        st.session_state.scan_result = result
        self._db.save_report(result["url"], result["domain"], result["threat"])
        st.rerun()

    def _render_scan_results(self) -> None:
        """Display the intelligence report if a scan result exists."""
        result: Optional[dict] = st.session_state.scan_result
        if not result:
            return

        st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)
        st.markdown(
            self._ui.threat_banner(result["threat"]), unsafe_allow_html=True
        )

        col_res1, col_res2 = st.columns([1.5, 1])

        with col_res1:
            with st.expander(
                "📌 Infrastructure & Registration Intelligence", expanded=True
            ):
                st.markdown(
                    f"""
                    | Field | Value |
                    |---|---|
                    | **Resolved IP** | `{result['ip']}` |
                    | **Hosting Provider** | {result['hosting']} |
                    | **Domain Registrar** | {result['whois']['registrar']} |
                    | **Registration Date** | {result['whois']['creation_date']} |
                    | **Expiry Date** | {result['whois']['expiry_date']} |
                    """
                )
            st.info(f"**Abuse Contact:** 📧 `{result['abuse_email']}`")

            mailto = self._ui.build_takedown_mailto(result)
            st.link_button(
                "📨 Submit Takedown Request",
                mailto,
                type="primary",
                use_container_width=True,
            )

        with col_res2:
            st.markdown(
                "<p class='section-label'>Visual Evidence</p>",
                unsafe_allow_html=True,
            )
            if result["image"]:
                st.image(
                    result["image"],
                    use_container_width=True,
                    caption="Automated screenshot capture",
                )
            else:
                st.error("Screenshot blocked — target has anti-bot protection.")

    # ── Page: Donate ───────────────────────────────────────────────

    def render_donate(self) -> None:
        """Display the donation/support section."""
        st.markdown(self._ui.donate_section(), unsafe_allow_html=True)
