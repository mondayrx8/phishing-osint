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
from dotenv import load_dotenv

load_dotenv()

# --- KONFIGURASI ---
VT_API_KEY = os.environ.get("VT_API_KEY", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "k")
# FIX #4: Admin access via hashed session token instead of URL query param
# The admin enters a secret passphrase in the sidebar — never visible in the URL bar
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "k")
WHITELIST = frozenset(["touchngo.com.my", "tngdigital.com.my", "maybank2u.com.my", "cimbclicks.com.my", "google.com", "facebook.com", "gov.my", "bankrakyat.com.my", "rhbgroup.com", "ambank.com.my", "pbebank.com", "hlb.com.my"])
DB_PATH = 'phishing_hunter.db'

# --- FRONTEND ---
st.set_page_config(page_title="Phishing Hunter — Threat Intelligence Platform", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.markdown('<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>', unsafe_allow_html=True)

# FIX #2: CSS is READABLE in source but MINIFIED at runtime
# Edit this block normally — Python does the compression before injecting

def _get_falcon_b64():
    import os, base64
    if os.path.exists("FalconO.png"):
        with open("FalconO.png", "rb") as f:
            return base64.b64encode(f.read()).decode()
    return ""

_bg_b64 = _get_falcon_b64()
_bg_css = f"url('data:image/png;base64,{_bg_b64}')" if _bg_b64 else "none"

_CSS_RAW = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');

/* ── Design Tokens ───────────────────────────────────── */
:root {
    --bg-page: #0B111D;
    --bg-card: rgba(15, 23, 42, 0.45);
    --text-primary: #F8FAFC;
    --text-secondary: #CBD5E1;
    --text-muted: #94A3B8;
    --accent: #3B82F6;
    --accent-hover: #60A5FA;
    --accent-light: rgba(59, 130, 246, 0.15);
    --danger: #EF4444;
    --danger-light: rgba(239, 68, 68, 0.15);
    --warning-bg: rgba(245, 158, 11, 0.1);
    --warning-border: #F59E0B;
    --border: rgba(255, 255, 255, 0.15);
    --border-focus: #3B82F6;
    --shadow-sm: 0 4px 6px rgba(0,0,0,0.3);
    --shadow-card: 0 8px 32px rgba(0,0,0,0.5);
    --shadow-hover: 0 12px 48px rgba(0,0,0,0.7);
    --radius-sm: 8px;
    --radius-md: 12px;
    --radius-lg: 16px;
    --radius-pill: 50px;
    --font: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
}

/* ── Global Base ─────────────────────────────────────── */
html, body, .stApp, [data-testid="stAppViewContainer"] {
    background-color: var(--bg-page) !important;
    background-image: __BG_IMG_PLACEHOLDER__ !important;
    background-size: cover !important;
    background-position: center !important;
    background-attachment: fixed !important;
    background-repeat: no-repeat !important;
    color: var(--text-primary) !important;
    font-family: var(--font) !important;
}

[data-testid="stAppViewContainer"]::before {
    content: '';
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: radial-gradient(circle at center, rgba(11, 17, 29, 0.4) 0%, rgba(11, 17, 29, 0.9) 100%);
    pointer-events: none;
    z-index: 0;
}

.stApp p, .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6, .stApp button, .stApp input, .stApp label, .stApp div[data-testid="stMarkdownContainer"] { 
    font-family: var(--font) !important; 
}

.main .block-container {
    position: relative;
    z-index: 1;
    max-width: 1100px !important;
    padding: 2rem 1.5rem 5rem !important;
}

/* ── Eradicate Streamlit Branding ────────────────────── */
[data-testid="stHeader"],
#MainMenu,
footer,
header [data-testid="stToolbar"] {
    display: none !important;
    visibility: hidden !important;
    height: 0 !important;
}

/* ── Hero Heading ────────────────────────────────────── */
.hero-title {
    text-align: center !important;
    font-size: clamp(2rem, 5vw, 2.8rem) !important;
    font-weight: 900 !important;
    color: var(--text-primary) !important;
    letter-spacing: -0.02em !important;
    line-height: 1.2 !important;
    margin: 1.5rem 0 0.5rem !important;
}
.hero-subtitle {
    text-align: center !important;
    font-size: 1.05rem !important;
    font-weight: 400 !important;
    color: var(--text-secondary) !important;
    max-width: 600px !important;
    margin: 0 auto 2rem !important;
    line-height: 1.6 !important;
}

/* ── Section Labels ──────────────────────────────────── */
.section-label {
    font-size: 0.8rem !important;
    font-weight: 700 !important;
    color: var(--text-muted) !important;
    text-transform: uppercase !important;
    letter-spacing: 1.5px !important;
    margin-bottom: 0.5rem !important;
}

/* ── Metrics ─────────────────────────────────────────── */
div[data-testid="metric-container"] {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-lg) !important;
    padding: 1.5rem 1.25rem !important;
    box-shadow: var(--shadow-card) !important;
    text-align: center !important;
    transition: all 0.25s ease !important;
    display: flex !important;
    flex-direction: column !important;
    align-items: center !important;
    justify-content: center !important;
}
div[data-testid="metric-container"]:hover {
    box-shadow: var(--shadow-hover) !important;
    transform: translateY(-3px) !important;
}
div[data-testid="metric-container"] label {
    color: var(--text-secondary) !important;
    font-size: 0.78rem !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 1px !important;
    text-align: center !important;
    width: 100% !important;
}
div[data-testid="metric-container"] [data-testid="stMetricValue"] {
    color: var(--text-primary) !important;
    font-weight: 800 !important;
    font-size: 2rem !important;
    text-align: center !important;
    justify-content: center !important;
}
div[data-testid="metric-container"] [data-testid="stMetricValue"] > div {
    width: 100% !important;
    text-align: center !important;
    justify-content: center !important;
}

/* ── Custom Stat Cards (HTML-based) ──────────────────── */
.stat-card {
    flex: 1;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 1.5rem 1rem;
    box-shadow: var(--shadow-card);
    text-align: center;
    transition: all 0.25s ease;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.4rem;
}
.stat-card:hover {
    box-shadow: var(--shadow-hover);
    transform: translateY(-3px);
}
.stat-label {
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 1px;
}
.stat-value {
    font-size: 2.2rem;
    font-weight: 800;
    color: var(--text-primary);
    line-height: 1;
}
.stat-value--danger {
    color: var(--danger) !important;
}

/* ── Search / Text Inputs ────────────────────────────── */
.stTextInput>div>div>input {
    background: var(--bg-card) !important;
    color: var(--text-primary) !important;
    border: 1.5px solid var(--border) !important;
    border-radius: var(--radius-pill) !important;
    font-size: 1rem !important;
    padding: 14px 22px !important;
    transition: all 0.2s ease !important;
    box-shadow: var(--shadow-sm) !important;
}
.stTextInput>div>div>input:focus {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 3px rgba(37,99,235,.15) !important;
    outline: none !important;
}
.stTextInput>div>div>input::placeholder {
    color: var(--text-muted) !important;
}
.stTextInput>label, .stNumberInput>label {
    color: var(--text-secondary) !important;
    font-size: 0.88rem !important;
    font-weight: 500 !important;
}
.stNumberInput>div>div>input {
    background: var(--bg-card) !important;
    color: var(--text-primary) !important;
    border: 1.5px solid var(--border) !important;
    border-radius: var(--radius-sm) !important;
}

/* ── Buttons ─────────────────────────────────────────── */
.stButton>button {
    background: var(--bg-card) !important;
    color: var(--accent) !important;
    border: 1.5px solid var(--border) !important;
    border-radius: var(--radius-sm) !important;
    font-weight: 600 !important;
    font-size: 0.88rem !important;
    padding: 10px 24px !important;
    transition: all 0.2s ease !important;
    text-shadow: none !important;
}
.stButton>button:hover {
    background: var(--accent-light) !important;
    border-color: var(--accent) !important;
    transform: translateY(-1px) !important;
    box-shadow: var(--shadow-card) !important;
    color: var(--accent) !important;
}
button[data-testid="stBaseButton-primary"] {
    background: var(--accent) !important;
    color: #FFFFFF !important;
    border: none !important;
    border-radius: var(--radius-sm) !important;
    font-weight: 700 !important;
    box-shadow: 0 2px 8px rgba(37,99,235,.25) !important;
}
button[data-testid="stBaseButton-primary"]:hover {
    background: var(--accent-hover) !important;
    box-shadow: 0 6px 20px rgba(37,99,235,.3) !important;
    transform: translateY(-2px) !important;
    color: #FFFFFF !important;
}

/* ── Link Buttons ────────────────────────────────────── */
a[data-testid="stBaseLinkButton-primary"] {
    background: var(--accent) !important;
    color: #FFFFFF !important;
    border-radius: var(--radius-sm) !important;
    font-weight: 700 !important;
    box-shadow: 0 2px 8px rgba(37,99,235,.25) !important;
    transition: all 0.2s ease !important;
}
a[data-testid="stBaseLinkButton-primary"]:hover {
    background: var(--accent-hover) !important;
    box-shadow: 0 6px 20px rgba(37,99,235,.3) !important;
    transform: translateY(-2px) !important;
}

/* ── Cards / Expanders ───────────────────────────────── */
[data-testid="stExpander"] {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-lg) !important;
    box-shadow: var(--shadow-card) !important;
    overflow: hidden !important;
}
[data-testid="stExpander"] summary {
    font-weight: 600 !important;
    color: var(--text-primary) !important;
}

/* ── Tabs ────────────────────────────────────────────── */
.stTabs [data-baseweb="tab-list"] {
    gap: 0 !important;
    background: var(--bg-card) !important;
    border-radius: var(--radius-md) !important;
    padding: 4px !important;
    border: 1px solid var(--border) !important;
    box-shadow: var(--shadow-sm) !important;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    color: var(--text-muted) !important;
    border-radius: var(--radius-sm) !important;
    font-weight: 600 !important;
    font-size: 0.85rem !important;
    padding: 10px 20px !important;
    transition: all 0.2s ease !important;
}
.stTabs [aria-selected="true"] {
    background: var(--accent-light) !important;
    color: var(--accent) !important;
}
.stTabs [data-baseweb="tab-highlight"] {
    background-color: var(--accent) !important;
}
.stTabs [data-baseweb="tab-border"] { display: none !important; }

/* ── Data Tables ─────────────────────────────────────── */
[data-testid="stDataFrame"] {
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-md) !important;
    box-shadow: var(--shadow-sm) !important;
}

/* ── Alerts ───────────────────────────────────────────── */
div[data-testid="stAlert"] {
    border-radius: var(--radius-sm) !important;
}

/* ── Threat Banners ──────────────────────────────────── */
.threat-banner-danger {
    background: var(--danger-light) !important;
    border: 1px solid var(--danger) !important;
    border-left: 4px solid var(--danger) !important;
    border-radius: var(--radius-sm) !important;
    padding: 1rem 1.25rem !important;
    margin-bottom: 1rem !important;
}
.threat-banner-danger p {
    color: var(--danger) !important;
    font-weight: 700 !important;
    font-size: 0.95rem !important;
    margin: 0 !important;
}
.threat-banner-warning {
    background: var(--warning-bg) !important;
    border: 1px solid var(--warning-border) !important;
    border-left: 4px solid var(--warning-border) !important;
    border-radius: var(--radius-sm) !important;
    padding: 1rem 1.25rem !important;
    margin-bottom: 1rem !important;
}
.threat-banner-warning p {
    color: #92400E !important;
    font-weight: 700 !important;
    font-size: 0.95rem !important;
    margin: 0 !important;
}

/* ── Markdown / Typography ───────────────────────────── */
.stMarkdown, .stMarkdown p { color: var(--text-primary) !important; }
.stMarkdown h1, .stMarkdown h2, .stMarkdown h3 {
    color: var(--text-primary) !important;
    font-weight: 700 !important;
}
hr { border-color: var(--border) !important; }
code {
    color: var(--accent) !important;
    background: var(--accent-light) !important;
    border-radius: 4px !important;
    padding: 2px 6px !important;
    font-size: 0.88em !important;
}
a { color: var(--accent) !important; }
a:hover { color: var(--accent-hover) !important; }

/* ── Scrollbar ───────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-page); }
::-webkit-scrollbar-thumb { background: #CBD5E1; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #94A3B8; }

/* ── Glassmorphism & Glitch Fixes ────────────────────── */
.stat-card, div[data-testid="metric-container"], [data-testid="stExpander"], 
.stTextInput>div>div>input, .stNumberInput>div>div>input, .stButton>button, 
[data-testid="stDataFrame"], .threat-banner-danger, .threat-banner-warning {
    backdrop-filter: blur(12px) !important;
    -webkit-backdrop-filter: blur(12px) !important;
}

div[data-baseweb="input"] {
    background: transparent !important;
    border: none !important;
    box-shadow: none !important;
}

/* ── Anti-Jitter Fix ─────────────────────────────────── */
html, body, [data-testid="stAppViewContainer"] {
    overflow-y: scroll !important;
    overflow-x: hidden !important;
}
"""

def _minify_css(css):
    """Runtime CSS minifier — keeps source readable, serves compressed."""
    css = re.sub(r'/\*.*?\*/', '', css, flags=re.DOTALL)  # strip comments
    css = re.sub(r'\s+', ' ', css)                         # collapse whitespace
    css = re.sub(r'\s*([{}:;,>~+])\s*', r'\1', css)       # strip around symbols
    css = re.sub(r';}', '}', css)                          # remove trailing semicolons
    return css.strip()

_CSS_INJECT = _CSS_RAW.replace("__BG_IMG_PLACEHOLDER__", _bg_css)
st.markdown(f"<style>{_minify_css(_CSS_INJECT)}</style>", unsafe_allow_html=True)


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
st.markdown("<h1 class='hero-title'>🛡️ Know who you're dealing with.</h1>", unsafe_allow_html=True)
st.markdown("<p class='hero-subtitle'>Phishing Hunter — Community-powered threat intelligence. Scan domains, expose phishing, and protect what matters.</p>", unsafe_allow_html=True)

# --- Tab layout ---
if is_admin:
    tab_scan, tab_admin = st.tabs(["🔍 Threat Scanner", "🗄️ Command Center"])
    active_container = tab_scan
else:
    active_container = st.container()

with active_container:
    # --- DASHBOARD ---
    total_lapor, total_berjaya = get_stats()
    kill_rate = round((total_berjaya/total_lapor)*100, 1) if total_lapor > 0 else 0

    st.markdown(f"""
    <div style="display:flex;gap:1rem;margin-bottom:2rem;">
        <div class="stat-card">
            <span class="stat-label">Threats Identified</span>
            <span class="stat-value stat-value--danger">{total_lapor}</span>
        </div>
        <div class="stat-card">
            <span class="stat-label">Domains Neutralized</span>
            <span class="stat-value">{total_berjaya}</span>
        </div>
        <div class="stat-card">
            <span class="stat-label">Success Rate</span>
            <span class="stat-value">{kill_rate}%</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # --- INPUT ---
    with st.container():
        st.markdown("<p class='section-label'>Domain Scanner</p>", unsafe_allow_html=True)
        url_input = st.text_input("Scan a suspect URL", placeholder="Enter a URL to analyse — e.g. https://suspicious-site.com", label_visibility="collapsed").strip()
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
        st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)

        # Threat banner
        if "DANGEROUS" in res['threat']:
            st.markdown(f"<div class='threat-banner-danger'><p>🚨 THREAT CONFIRMED — {res['threat']}</p></div>", unsafe_allow_html=True)
        else:
            st.markdown(f"<div class='threat-banner-warning'><p>⚠️ {res['threat']} — Manual review recommended</p></div>", unsafe_allow_html=True)

        col_res1, col_res2 = st.columns([1.5, 1])
        with col_res1:
            with st.expander("📌 Infrastructure & Registration Intelligence", expanded=True):
                st.markdown(f"""
                | Field | Value |
                |---|---|
                | **Resolved IP** | `{res['ip']}` |
                | **Hosting Provider** | {res['hosting']} |
                | **Domain Registrar** | {res['whois']['registrar']} |
                | **Registration Date** | {res['whois']['creation_date']} |
                | **Expiry Date** | {res['whois']['expiry_date']} |
                """)
            st.info(f"**Abuse Contact:** 📧 `{res['abuse_email']}`")

            # TAKEDOWN BUTTON
            subj = urllib.parse.quote(f"URGENT: Phishing Abuse Report - {res['domain']}")
            body = urllib.parse.quote(f"Hello Abuse Desk,\n\nI am reporting a malicious phishing website hosted/registered on your network.\n\nMalicious URL: {res['url']}\nIP Address: {res['ip']}\nHosting: {res['hosting']}\nCreation Date: {res['whois']['creation_date']}\nThreat Status: {res['threat']}\nScreenshot Evidence: {res['image']}\n\nPlease investigate and suspend this domain immediately.\n\nRegards,\nReported via Phishing Hunter")
            st.link_button("📨 Submit Takedown Request", f"mailto:{res['abuse_email']}?subject={subj}&body={body}", type="primary", use_container_width=True)

        with col_res2:
            # FIX #3: Restored st.image() for Streamlit's built-in image safety
            st.markdown("<p class='section-label'>Visual Evidence</p>", unsafe_allow_html=True)
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
st.markdown("<div style='height: 4rem;'></div>", unsafe_allow_html=True)
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
st.markdown("<div style='height: 2rem;'></div>", unsafe_allow_html=True)