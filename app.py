import streamlit as st
import requests
import base64
import tldextract
import urllib.parse
import time
import re
import random
import string
import socket
import subprocess
import sqlite3
import hashlib
import hmac
import pandas as pd
from datetime import datetime
from contextlib import contextmanager
import os

# --- KONFIGURASI ---
VT_API_KEY = os.environ.get("VT_API_KEY", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
# FIX #4: Admin access via hashed session token instead of URL query param
# The admin enters a secret passphrase in the sidebar — never visible in the URL bar
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")
WHITELIST = frozenset(["touchngo.com.my", "tngdigital.com.my", "maybank2u.com.my", "cimbclicks.com.my", "google.com", "facebook.com", "gov.my", "bankrakyat.com.my", "rhbgroup.com", "ambank.com.my", "pbebank.com", "hlb.com.my"])
DB_PATH = 'phishing_hunter.db'

# --- FRONTEND ---
st.set_page_config(page_title="Phishing Hunter — Threat Intelligence Platform", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.markdown('<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>', unsafe_allow_html=True)

# FIX #2: CSS is READABLE in source but MINIFIED at runtime
# Edit this block normally — Python does the compression before injecting

_CSS_RAW = """
@import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600;700&family=Orbitron:wght@600;700;800;900&family=Share+Tech+Mono&family=Inter:wght@400;500;600;700&display=swap');
:root {
    --n: #00ff41;
    --nd: #00cc33;
    --bgd: #060a0e;
    --bgc: #0d1219;
    --bge: #111820;
    --tp: #c9d1d9;
    --tm: #5a6672;
    --b: rgba(0, 255, 65, .12);
    --bh: rgba(0, 255, 65, .3);
}
.stApp, [data-testid=stAppViewContainer] {
    background: var(--bgd) !important;
    color: var(--tp) !important;
}
.stApp::after {
    content: '';
    position: fixed;
    inset: 0;
    pointer-events: none;
    z-index: 1;
    background: repeating-linear-gradient(0deg, transparent, transparent 3px, rgba(0,255,65,.012) 3px, rgba(0,255,65,.012) 4px);
}
[data-testid=stHeader] { background: 0 0 !important; }
div[data-testid=metric-container] {
    background: linear-gradient(145deg, var(--bgc), var(--bge)) !important;
    border: 1px solid var(--b) !important;
    border-left: 3px solid var(--n) !important;
    border-radius: 12px !important;
    padding: 20px 16px !important;
    box-shadow: 0 0 20px rgba(0,255,65,.04), inset 0 1px 0 rgba(0,255,65,.03) !important;
    transition: all .3s ease !important;
}
div[data-testid=metric-container]:hover {
    box-shadow: 0 0 30px rgba(0,255,65,.1), 0 0 60px rgba(0,255,65,.03) !important;
    border-color: var(--bh) !important;
    transform: translateY(-2px) !important;
}
div[data-testid=metric-container] label {
    color: var(--n) !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: .78rem !important;
    letter-spacing: 1.5px !important;
    text-transform: uppercase !important;
    text-shadow: 0 0 6px rgba(0,255,65,.25) !important;
}
div[data-testid=metric-container] [data-testid=stMetricValue] {
    color: #fff !important;
    font-family: Orbitron, sans-serif !important;
    font-weight: 700 !important;
    font-size: 1.8rem !important;
}
.stButton>button {
    background: rgba(0,255,65,.06) !important;
    color: var(--n) !important;
    border: 1px solid rgba(0,255,65,.25) !important;
    border-radius: 8px !important;
    font-family: Inter, sans-serif !important;
    font-weight: 700 !important;
    font-size: .82rem !important;
    letter-spacing: 1px !important;
    text-transform: uppercase !important;
    padding: 10px 20px !important;
    transition: all .3s ease !important;
    text-shadow: 0 0 4px rgba(0,255,65,.3) !important;
}
.stButton>button:hover {
    background: rgba(0,255,65,.14) !important;
    box-shadow: 0 0 20px rgba(0,255,65,.2), 0 0 40px rgba(0,255,65,.06) !important;
    transform: translateY(-1px) !important;
    color: #fff !important;
}
button[data-testid=stBaseButton-primary] {
    background: linear-gradient(135deg, var(--n), var(--nd)) !important;
    color: #000 !important;
    font-weight: 800 !important;
    text-shadow: none !important;
    border: none !important;
    box-shadow: 0 0 18px rgba(0,255,65,.2) !important;
}
button[data-testid=stBaseButton-primary]:hover {
    box-shadow: 0 0 30px rgba(0,255,65,.4), 0 0 60px rgba(0,255,65,.1) !important;
    color: #000 !important;
}
a[data-testid=stBaseLinkButton-primary] {
    background: linear-gradient(135deg, var(--n), var(--nd)) !important;
    color: #000 !important;
    border-radius: 8px !important;
    font-family: Inter, sans-serif !important;
    font-weight: 700 !important;
    letter-spacing: 1px !important;
    text-transform: uppercase !important;
    box-shadow: 0 0 18px rgba(0,255,65,.2) !important;
    transition: all .3s ease !important;
}
a[data-testid=stBaseLinkButton-primary]:hover {
    box-shadow: 0 0 30px rgba(0,255,65,.4), 0 0 60px rgba(0,255,65,.1) !important;
    transform: translateY(-1px) !important;
}
.stTextInput>div>div>input {
    background: var(--bgc) !important;
    color: var(--n) !important;
    border: 1px solid var(--b) !important;
    border-radius: 8px !important;
    font-family: 'Fira Code', monospace !important;
    font-size: .92rem !important;
    padding: 12px 14px !important;
    caret-color: var(--n) !important;
    transition: all .25s ease !important;
}
.stTextInput>div>div>input:focus {
    border-color: var(--n) !important;
    box-shadow: 0 0 12px rgba(0,255,65,.12) !important;
}
.stTextInput>div>div>input::placeholder { color: var(--tm) !important; }
.stTextInput>label, .stNumberInput>label {
    color: var(--tp) !important;
    font-family: Inter, sans-serif !important;
    font-size: .88rem !important;
}
.stNumberInput>div>div>input {
    background: var(--bgc) !important;
    color: var(--n) !important;
    border: 1px solid var(--b) !important;
    border-radius: 8px !important;
    font-family: 'Fira Code', monospace !important;
}
[data-testid=stExpander] {
    border: 1px solid var(--b) !important;
    border-radius: 10px !important;
    background: var(--bgc) !important;
}
.stTabs [data-baseweb=tab-list] {
    gap: 0 !important;
    background: var(--bgc) !important;
    border-radius: 10px !important;
    padding: 3px !important;
    border: 1px solid var(--b) !important;
}
.stTabs [data-baseweb=tab] {
    background: 0 0 !important;
    color: var(--tm) !important;
    border-radius: 7px !important;
    font-family: Inter, sans-serif !important;
    font-weight: 600 !important;
    font-size: .82rem !important;
    letter-spacing: .5px !important;
    padding: 10px 18px !important;
    transition: all .25s ease !important;
}
.stTabs [aria-selected=true] {
    background: rgba(0,255,65,.08) !important;
    color: var(--n) !important;
    text-shadow: 0 0 6px rgba(0,255,65,.2) !important;
}
.stTabs [data-baseweb=tab-highlight] {
    background-color: var(--n) !important;
    box-shadow: 0 0 6px var(--n) !important;
}
.stTabs [data-baseweb=tab-border] { display: none !important; }
[data-testid=stDataFrame] {
    border: 1px solid var(--b) !important;
    border-radius: 10px !important;
}
div[data-testid=stAlert] {
    border-radius: 8px !important;
    font-family: Inter, sans-serif !important;
}
hr { border-color: var(--b) !important; }
.stMarkdown, .stMarkdown p { color: var(--tp) !important; }
code {
    color: var(--n) !important;
    background: rgba(0,255,65,.06) !important;
    border-radius: 4px !important;
    padding: 2px 6px !important;
}
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: var(--bgd); }
::-webkit-scrollbar-thumb { background: var(--b); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--nd); }
#MainMenu { visibility: hidden; }
footer { visibility: hidden; }
header [data-testid="stToolbar"] { visibility: hidden; }
/* TAMBAHAN ANTI-GEGAR */
html, body, [data-testid="stAppViewContainer"] {
    overflow-y: scroll !important;
    overflow-x: hidden !important;
}
.main .block-container {
    padding-bottom: 80px !important;
}
"""

def _minify_css(css):
    """Runtime CSS minifier — keeps source readable, serves compressed."""
    css = re.sub(r'/\*.*?\*/', '', css, flags=re.DOTALL)  # strip comments
    css = re.sub(r'\s+', ' ', css)                         # collapse whitespace
    css = re.sub(r'\s*([{}:;,>~+])\s*', r'\1', css)       # strip around symbols
    css = re.sub(r';}', '}', css)                          # remove trailing semicolons
    return css.strip()

st.markdown(f"<style>{_minify_css(_CSS_RAW)}</style>", unsafe_allow_html=True)

# --- FIX #1: Proper DB connections — open/close per operation, no thread-local leak ---
def _get_conn():
    """Create a fresh connection with optimized PRAGMAs. Always close after use."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-8000")
    conn.execute("PRAGMA temp_store=MEMORY")
    return conn

@contextmanager
def get_db():
    """Context manager that guarantees connection is closed after every operation.
    No more leaked connections in Streamlit's random thread pool."""
    conn = _get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()  # <-- THE FIX: always close, no matter what

# --- DATABASE ENGINE (Optimized with indexes + safe connection lifecycle) ---
@st.cache_resource(show_spinner=False)
def init_db():
    """Jalankan fungsi ini SEKALI SAHAJA sewaktu server mula dihidupkan"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, domain TEXT, threat TEXT, report_date TEXT, status TEXT)''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_reports_url ON reports(url)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_reports_domain ON reports(domain)')
    return True # Penanda bahawa DB dah siap setup

def save_report(url, domain, threat):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT 1 FROM reports WHERE url=? LIMIT 1", (url,))
        if not c.fetchone():
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute("INSERT INTO reports (url, domain, threat, report_date, status) VALUES (?, ?, ?, ?, ?)", (url, domain, threat, now, "Pending Action"))

def get_stats():
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) AS total, SUM(CASE WHEN status='TAKEDOWN SUCCESSFUL' THEN 1 ELSE 0 END) AS success FROM reports")
        row = c.fetchone()
        return row[0], row[1] or 0

def get_all_reports():
    with get_db() as conn:
        df = pd.read_sql_query("SELECT id, url, domain, threat, report_date, status FROM reports ORDER BY id DESC", conn)
    return df

def update_status(report_id, new_status):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("UPDATE reports SET status=? WHERE id=?", (new_status, report_id))

def delete_report(report_id):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM reports WHERE id=?", (report_id,))

init_db()

# --- OSINT ENGINES (Optimized caching + reusable HTTP session) ---
@st.cache_resource
def _get_http_session():
    session = requests.Session()
    session.headers.update({"User-Agent": "PhishingHunter/1.0"})
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=5,
        pool_maxsize=10,
        max_retries=requests.adapters.Retry(total=2, backoff_factor=0.3)
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

@st.cache_data(ttl=3600, show_spinner=False)
def get_image(url):
    try:
        session = _get_http_session()
        res = session.get(f"https://api.microlink.io/?url={url}&screenshot=true&meta=false", timeout=10)
        return res.json().get("data", {}).get("screenshot", {}).get("url") if res.status_code == 200 else None
    except: return None

@st.cache_data(ttl=3600, show_spinner=False)
def get_hosting_ip(url):
    try:
        hostname = urllib.parse.urlparse(url).netloc or url
        ip_address = socket.gethostbyname(hostname)
        session = _get_http_session()
        res = session.get(f"https://ipinfo.io/{ip_address}/json", timeout=5)
        return ip_address, res.json().get('org', 'Not Found') if res.status_code == 200 else "Detection Failed"
    except: return "Detection Failed", "Detection Failed"

@st.cache_data(ttl=3600, show_spinner=False)
def get_whois_data(domain):
    """Fungsi WHOIS Gred Tentera - Guna Terminal Sebenar!"""
    data = {"registrar": "Not Found", "abuse_email": "", 
            "creation_date": "Not Found", "expiry_date": "Not Found"}
    try:
        import subprocess
        import re
        
        # Bersihkan domain
        d = domain.replace("https://", "").replace("http://", "").split('/')[0]
        
        # Tembak arahan 'whois' terus ke terminal Linux!
        result = subprocess.run(['whois', d], capture_output=True, text=True, timeout=10)
        raw = result.stdout
        
        # 1. Cari Registrar
        reg = re.search(r'(?i)Registrar:\s*(.+)', raw)
        if reg: data["registrar"] = reg.group(1).strip()
        
        # 2. Cari Tarikh (Kita ambil 10 huruf pertama untuk format YYYY-MM-DD)
        c_date = re.search(r'(?i)(Creation Date|Created On|Registration Time):\s*([^\n]+)', raw)
        if c_date: data["creation_date"] = c_date.group(2).strip()[:10]
        
        e_date = re.search(r'(?i)(Registry Expiry Date|Expiration Date):\s*([^\n]+)', raw)
        if e_date: data["expiry_date"] = e_date.group(2).strip()[:10]
        
        # 3. Cari Email Abuse (Sangat penting!)
        ab_email = re.search(r'(?i)Registrar Abuse Contact Email:\s*([^\s]+)', raw)
        if ab_email:
            data["abuse_email"] = ab_email.group(1).strip()
        else:
            # Teknik Sapu Bersih: Cari apa-apa email yang ada perkataan 'abuse' dalam teks terminal
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', raw)
            abuse_list = [e for e in emails if 'abuse' in e.lower()]
            if abuse_list: data["abuse_email"] = abuse_list[0]
            
    except Exception as e:
        pass
        
    return data

def _is_whitelisted(root_domain):
    return any(root_domain.endswith(ds) for ds in WHITELIST)

# --- Admin access via session state ---
# No more ?access=godmode in the URL — nothing to leak in screenshots/recordings
if 'admin_authenticated' not in st.session_state:
    st.session_state.admin_authenticated = False

is_admin = st.session_state.admin_authenticated

if 'scan_result' not in st.session_state: st.session_state.scan_result = None
if 'captcha_code' not in st.session_state: st.session_state.captcha_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))

# Header
st.markdown("<h1 style='text-align:center;font-family:Orbitron,sans-serif;font-weight:900;color:#00ff41;letter-spacing:4px;text-shadow:0 0 15px rgba(0,255,65,.5),0 0 30px rgba(0,255,65,.3);margin-bottom:0'>🛡️ PHISHING HUNTER</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align:center;font-family:Share Tech Mono,monospace;font-size:14px;color:#5a6672;letter-spacing:3px;text-transform:uppercase;margin-top:0'>Threat Intelligence & Domain Takedown Platform</p>", unsafe_allow_html=True)
st.divider()

# --- Tab layout ---
if is_admin:
    tab_scan, tab_admin = st.tabs(["🔍 Threat Scanner", "🗄️ Command Center"])
    active_container = tab_scan
else:
    active_container = st.container()

with active_container:
    # --- DASHBOARD ---
    total_lapor, total_berjaya = get_stats()
    col1, col2, col3 = st.columns(3)
    col1.metric("🚨 Threats Identified", total_lapor)
    col2.metric("💀 Domains Neutralized", total_berjaya)
    col3.metric("📈 Kill Rate", f"{round((total_berjaya/total_lapor)*100, 1) if total_lapor > 0 else 0}%")
    st.write("")

    # --- INPUT ---
    with st.container():
        st.markdown("### 🎯 Target Acquisition")
        url_input = st.text_input("Paste suspect URL for deep analysis:", placeholder="https://suspicious-domain.example.com").strip()
        if url_input and not url_input.startswith("http"): url_input = "https://" + url_input

        c_cap1, c_cap2 = st.columns([1, 2])
        c_cap1.info(f"**Security Verification:**\n### {st.session_state.captcha_code}")
        user_captcha = c_cap2.text_input("Enter verification code to proceed:", max_chars=5).strip().upper()

        if st.button("⚡ LAUNCH THREAT ANALYSIS", use_container_width=True, type="primary"):
            if not url_input: st.warning("⚠️ Target URL required — please provide a suspect domain.")
            elif user_captcha != st.session_state.captcha_code:
                st.error("❌ Verification failed. Generating new security token...")
                st.session_state.captcha_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
                st.rerun()
            else:
                st.session_state.captcha_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5)) 
                extracted = tldextract.extract(url_input)
                root_domain = f"{extracted.domain}.{extracted.suffix}"
                
                if _is_whitelisted(root_domain):
                    st.success("✅ Domain is verified legitimate — no action required.")
                    st.session_state.scan_result = None
                else:
                    threat = "Under Evaluation"
                    url_id = base64.urlsafe_b64encode(url_input.encode()).decode().strip("=")
                    session = _get_http_session()
                    
                    with st.status("Executing threat analysis pipeline...", expanded=True) as status:
                        st.write("📡 Querying VirusTotal threat intelligence database...")
                        try:
                            res = session.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": VT_API_KEY}, timeout=5)
                            if res.status_code == 404:
                                st.write("⚠️ Unknown domain — submitting for deep cloud analysis (15s)...")
                                session.post("https://www.virustotal.com/api/v3/urls", headers={"x-apikey": VT_API_KEY, "content-type": "application/x-www-form-urlencoded"}, data={"url": url_input})
                                time.sleep(15)
                                res = session.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": VT_API_KEY}, timeout=5)

                            if res.status_code == 200:
                                stats = res.json()['data']['attributes']['last_analysis_stats']
                                if stats.get('malicious', 0) > 0 or stats.get('suspicious', 0) > 0:
                                    threat = f"DANGEROUS ({stats.get('malicious', 0)} Malicious, {stats.get('suspicious', 0)} Spam/Suspicious)"
                                else: threat = "Clean / Zero-Day (0 Detections)"
                            else: threat = "VT Analysis Pending/Error"
                        except: threat = "Global Network Error"
                        
                        st.write("🔎 Running WHOIS & RDAP reconnaissance...")
                        ip_addr, hosting_org = get_hosting_ip(url_input)
                        whois_data = get_whois_data(root_domain)
                        
                        abuse_email = whois_data['abuse_email']
                        if not abuse_email: abuse_email = "abuse@cloudflare.com" if "cloudflare" in hosting_org.lower() else f"abuse@{root_domain}"
                        
                        st.write("📸 Capturing visual evidence via stealth screenshot...")
                        img_url = get_image(url_input)
                        
                        status.update(label="✅ Analysis complete — intelligence report ready", state="complete", expanded=False)

                    st.session_state.scan_result = {
                        "url": url_input, "domain": root_domain, "threat": threat,
                        "ip": ip_addr, "hosting": hosting_org, "whois": whois_data,
                        "abuse_email": abuse_email, "image": img_url
                    }
                    save_report(url_input, root_domain, threat)
                    st.rerun()

    # --- RESULTS ---
    if st.session_state.scan_result:
        res = st.session_state.scan_result
        st.divider()
        if "DANGEROUS" in res['threat']: st.error(f"🚨 **THREAT CONFIRMED:** {res['threat']}")
        else: st.warning(f"⚠️ **{res['threat']}** — Manual review recommended.")
        
        col_res1, col_res2 = st.columns([1.5, 1])
        with col_res1:
            with st.expander("📌 Infrastructure & Registration Intelligence", expanded=True):
                st.markdown(f"""
                - **Resolved IP:** `{res['ip']}`
                - **Hosting Provider:** {res['hosting']}
                - **Domain Registrar:** {res['whois']['registrar']}
                - **Registration Date:** {res['whois']['creation_date']}
                - **Expiry Date:** {res['whois']['expiry_date']}
                """)
            st.info(f"**Abuse Contact:** 📧 `{res['abuse_email']}`")
            
            # TAKEDOWN BUTTON
            subj = urllib.parse.quote(f"URGENT: Phishing Abuse Report - {res['domain']}")
            body = urllib.parse.quote(f"Hello Abuse Desk,\n\nI am reporting a malicious phishing website hosted/registered on your network.\n\nMalicious URL: {res['url']}\nIP Address: {res['ip']}\nHosting: {res['hosting']}\nCreation Date: {res['whois']['creation_date']}\nThreat Status: {res['threat']}\nScreenshot Evidence: {res['image']}\n\nPlease investigate and suspend this domain immediately.\n\nRegards,\nReported via Phishing Hunter")
            st.link_button("📨 SUBMIT TAKEDOWN REQUEST", f"mailto:{res['abuse_email']}?subject={subj}&body={body}", type="primary", use_container_width=True)
            
        with col_res2:
            # FIX #3: Restored st.image() for Streamlit's built-in image safety
            st.markdown("**📸 Visual Evidence:**")
            if res['image']:
                st.image(res['image'], use_container_width=True, caption="Automated screenshot capture")
            else: st.error("Screenshot blocked — target has anti-bot protection.")

# --- ADMIN PANEL (now behind session-state auth, not URL param) ---
if is_admin:
    with tab_admin:
        st.markdown("### 🔐 Threat Database Management")
        pwd_input = st.text_input("Authenticate to access classified records:", type="password")
        
        if pwd_input == ADMIN_PASSWORD:
            df = get_all_reports()
            if not df.empty:
                st.dataframe(df, use_container_width=True, hide_index=True)
                
                st.markdown("#### ⚙️ Record Operations")
                c_id, c_act = st.columns([1, 3])
                with c_id: target_id = st.number_input("Report ID:", min_value=1, step=1)
                with c_act:
                    st.write("Select action:")
                    b1, b2, b3 = st.columns(3)
                    if b1.button("✅ Mark Neutralized"): update_status(target_id, 'TAKEDOWN SUCCESSFUL'); st.rerun()
                    if b2.button("↩️ Reset to Pending"): update_status(target_id, 'Pending Action'); st.rerun()
                    if b3.button("🗑️ Delete Record"): delete_report(target_id); st.rerun()
            else: st.info("No threat records found in the database.")

# --- Bottom Operator Authentication ---
st.markdown("<br><br><br>", unsafe_allow_html=True)
with st.expander("⚙️ System Configuration"):
    _admin_phrase = st.text_input("Enter operator passphrase:", type="password", key="bottom_admin_passphrase")
    if _admin_phrase:
        if hmac.compare_digest(_admin_phrase.encode('utf-8'), ADMIN_SECRET.encode('utf-8')):
            if not st.session_state.admin_authenticated:
                st.session_state.admin_authenticated = True
                st.rerun()
            st.success("🟢 Operator access granted")
        else:
            if st.session_state.admin_authenticated:
                st.session_state.admin_authenticated = False
                st.rerun()
            st.error("🔴 Invalid passphrase")
    if st.session_state.admin_authenticated:
        if st.button("🔓 Revoke Access", use_container_width=True):
            st.session_state.admin_authenticated = False
            st.rerun()
st.markdown("<div style='height: 50px;'></div>", unsafe_allow_html=True)