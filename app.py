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
st.set_page_config(page_title="ZERO TRUST — Threat Intelligence Platform", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

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

def _get_logo_b64():
    import os, base64
    if os.path.exists("BudakNoob2.png"):
        with open("BudakNoob2.png", "rb") as f:
            return base64.b64encode(f.read()).decode()
    return ""

_logo_b64 = _get_logo_b64()
_logo_src = f"data:image/png;base64,{_logo_b64}" if _logo_b64 else ""


_CSS_RAW = """
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Inter:wght@400;500;600;700;800;900&display=swap');

/* ── Design Tokens ───────────────────────────────────── */
:root {
    --bg-page: #030712;
    --bg-card: rgba(15, 23, 42, 0.6);
    --text-primary: #F8FAFC;
    --text-secondary: #94A3B8;
    --text-muted: #64748B;
    --accent: #10B981; 
    --accent-hover: #059669;
    --accent-light: rgba(16, 185, 129, 0.15);
    --danger: #EF4444;
    --danger-light: rgba(239, 68, 68, 0.15);
    --warning-bg: rgba(245, 158, 11, 0.1);
    --warning-border: #F59E0B;
    --border: rgba(255, 255, 255, 0.1);
    --border-focus: #10B981;
    --shadow-sm: 0 4px 6px -1px rgba(0,0,0,0.5);
    --shadow-card: 0 10px 15px -3px rgba(0,0,0,0.5), 0 4px 6px -2px rgba(0,0,0,0.3);
    --shadow-hover: 0 20px 25px -5px rgba(0,0,0,0.5), 0 10px 10px -5px rgba(0,0,0,0.3), 0 0 20px rgba(16, 185, 129, 0.2);
    --radius-sm: 8px;
    --radius-md: 12px;
    --radius-lg: 16px;
    --radius-pill: 9999px;
    --font: 'Inter', system-ui, sans-serif;
    --font-head: 'Space Grotesk', system-ui, sans-serif;
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
    background: radial-gradient(circle at center, rgba(3, 7, 18, 0.6) 0%, rgba(3, 7, 18, 0.95) 100%);
    pointer-events: none;
    z-index: 0;
}

.stApp p, .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6, .stApp button, .stApp input, .stApp label, .stApp div[data-testid="stMarkdownContainer"] { 
    font-family: var(--font) !important; 
}
.stApp h1, .stApp h2, .stApp h3 {
    font-family: var(--font-head) !important;
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

/* ── Navbar & Footer ─────────────────────────────────── */
.custom-navbar {
    position: fixed;
    top: 0; left: 0; right: 0;
    height: 70px;
    background: rgba(3, 7, 18, 0.85);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 5%;
    z-index: 999999;
}
.nav-brand {
    display: flex;
    align-items: center;
    gap: 1rem;
    font-family: var(--font-head);
    font-weight: 700;
    font-size: 1.3rem;
    color: var(--text-primary);
    text-transform: uppercase;
    letter-spacing: 1px;
}
.nav-brand img {
    height: 40px;
    width: auto;
    border-radius: 5px;
}
.nav-links {
    display: flex;
    gap: 2rem;
}
.nav-links a {
    color: var(--text-secondary);
    text-decoration: none;
    font-weight: 600;
    font-size: 0.95rem;
    transition: all 0.2s;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.nav-links a:hover {
    color: var(--accent);
    text-shadow: 0 0 10px rgba(16, 185, 129, 0.5);
}

.custom-footer {
    position: fixed;
    bottom: 0; left: 0; right: 0;
    height: 60px;
    background: rgba(3, 7, 18, 0.95);
    border-top: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 999999;
    color: var(--text-muted);
    font-size: 0.85rem;
}
.custom-footer p { margin: 0; font-family: var(--font); }
.custom-footer a { color: var(--accent); text-decoration: none; font-weight: 600; }
.custom-footer a:hover { text-decoration: underline; color: var(--accent-hover); }

/* Adjust main container to avoid overlap with navbar and footer */
.main .block-container {
    padding-top: 100px !important;
    padding-bottom: 100px !important;
}

/* ── Hero Section ────────────────────────────────────── */
.hero-container {
    position: relative;
    text-align: center;
    padding: 4rem 1rem 3rem;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    overflow: hidden;
    margin-top: 2rem;
}

.hero-glow {
    position: absolute;
    width: 60px;
    height: 40px;
    background: radial-gradient(circle, rgba(16, 185, 129, 0.4) 0%, transparent 60%);
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    z-index: 0;
    pointer-events: none;
    filter: blur(50px);
}

.hero-badge {
    position: relative;
    z-index: 1;
    background: rgba(16, 185, 129, 0.1);
    border: 1px solid rgba(16, 185, 129, 0.3);
    color: var(--accent);
    padding: 0.6rem 1.2rem;
    border-radius: var(--radius-pill);
    font-size: 0.85rem;
    font-weight: 600;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    margin-bottom: 2rem;
    box-shadow: 0 0 20px rgba(16, 185, 129, 0.2);
}

.hero-title {
    position: relative;
    z-index: 1;
    font-size: clamp(2.5rem, 6vw, 4.5rem) !important;
    font-weight: 900 !important;
    color: var(--text-primary) !important;
    letter-spacing: -0.04em !important;
    line-height: 1.05 !important;
    margin: 0 0 1.5rem !important;
}

.text-gradient {
    background: linear-gradient(135deg, #10B981, #3B82F6);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.hero-subtitle {
    position: relative;
    z-index: 1;
    font-size: 1.2rem !important;
    font-weight: 400 !important;
    color: var(--text-secondary) !important;
    max-width: 700px !important;
    margin: 0 auto !important;
    line-height: 1.6 !important;
}

/* ── Metrics Grid ────────────────────────────────────── */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 1.5rem;
    margin-bottom: 3.5rem;
    position: relative;
    z-index: 1;
}

.stat-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 1.5rem;
    box-shadow: var(--shadow-card);
    display: flex;
    align-items: center;
    gap: 1.5rem;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
}

.stat-card:hover {
    box-shadow: var(--shadow-hover);
    transform: translateY(-5px);
    border-color: rgba(255, 255, 255, 0.2);
    background: rgba(30, 41, 59, 0.8);
}

.stat-icon {
    font-size: 2.2rem;
    background: rgba(255, 255, 255, 0.03);
    width: 68px;
    height: 68px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: var(--radius-md);
    border: 1px solid var(--border);
    box-shadow: inset 0 0 20px rgba(0,0,0,0.5);
}

.stat-content {
    display: flex;
    flex-direction: column;
}

.stat-label {
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-bottom: 0.3rem;
}

.stat-value {
    font-size: 2.2rem;
    font-weight: 800;
    color: var(--text-primary);
    line-height: 1;
    font-family: var(--font-head);
}

.stat-value--danger { color: var(--danger) !important; }
.stat-value--success { color: var(--accent) !important; }

/* ── Input Styling ────────────────────────────────────── */
.stTextInput>div>div>input {
    background: rgba(0, 0, 0, 0.4) !important;
    color: var(--text-primary) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-pill) !important;
    font-size: 1.1rem !important;
    padding: 16px 24px !important;
    transition: all 0.3s ease !important;
    box-shadow: inset 0 2px 4px rgba(0,0,0,0.5), 0 4px 20px rgba(0,0,0,0.3) !important;
    backdrop-filter: blur(10px) !important;
}
.stTextInput>div>div>input:focus {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 4px rgba(16, 185, 129, 0.15), inset 0 0 10px rgba(16, 185, 129, 0.1) !important;
    outline: none !important;
    background: rgba(15, 23, 42, 0.8) !important;
}
.stTextInput>div>div>input::placeholder {
    color: var(--text-muted) !important;
}

/* ── CTA Button ──────────────────────────────────────── */
button[data-testid="stBaseButton-primary"] {
    background: linear-gradient(135deg, var(--accent), #047857) !important;
    color: #FFFFFF !important;
    border: none !important;
    border-radius: var(--radius-pill) !important;
    font-weight: 700 !important;
    font-family: var(--font-head) !important;
    font-size: 1.1rem !important;
    padding: 14px 32px !important;
    box-shadow: 0 4px 15px rgba(16, 185, 129, 0.4) !important;
    transition: all 0.3s ease !important;
    text-transform: uppercase !important;
    letter-spacing: 1.5px !important;
}
button[data-testid="stBaseButton-primary"]:hover {
    box-shadow: 0 8px 25px rgba(16, 185, 129, 0.6) !important;
    transform: translateY(-2px) !important;
    background: linear-gradient(135deg, #34D399, var(--accent)) !important;
    color: #FFFFFF !important;
}

/* ── Secondary Buttons & Elements ────────────────────── */
.stButton>button {
    background: var(--bg-card) !important;
    color: var(--text-primary) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-pill) !important;
    font-weight: 600 !important;
    padding: 10px 24px !important;
    transition: all 0.2s ease !important;
}
.stButton>button:hover {
    background: rgba(255,255,255,0.05) !important;
    border-color: rgba(255,255,255,0.3) !important;
    transform: translateY(-1px) !important;
}

[data-testid="stExpander"] {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-lg) !important;
    box-shadow: var(--shadow-card) !important;
    overflow: hidden !important;
    backdrop-filter: blur(12px) !important;
}
[data-testid="stExpander"] summary {
    font-weight: 600 !important;
    color: var(--text-primary) !important;
}

/* ── Data Tables ─────────────────────────────────────── */
[data-testid="stDataFrame"] {
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-md) !important;
    box-shadow: var(--shadow-sm) !important;
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

/* ── Panels & Expanders ──────────────────────────────── */
.threat-banner-danger {
    background: linear-gradient(90deg, var(--danger-light), transparent) !important;
    border: 1px solid var(--danger) !important;
    border-left: 4px solid var(--danger) !important;
    border-radius: var(--radius-sm) !important;
    padding: 1.25rem 1.5rem !important;
    margin-bottom: 2rem !important;
}
.threat-banner-danger p {
    color: var(--danger) !important;
    font-weight: 700 !important;
    font-size: 1.1rem !important;
    margin: 0 !important;
    letter-spacing: 0.5px !important;
}
.threat-banner-warning {
    background: linear-gradient(90deg, var(--warning-bg), transparent) !important;
    border: 1px solid var(--warning-border) !important;
    border-left: 4px solid var(--warning-border) !important;
    border-radius: var(--radius-sm) !important;
    padding: 1.25rem 1.5rem !important;
    margin-bottom: 2rem !important;
}
.threat-banner-warning p {
    color: #FBBF24 !important;
    font-weight: 700 !important;
    font-size: 1.1rem !important;
    margin: 0 !important;
}

/* ── Landing Page Sections ───────────────────────────── */
html {
    scroll-behavior: smooth;
}
#home, #educate, #report, #donate {
    scroll-margin-top: 100px;
}
.section-container {
    max-width: 1000px;
    margin: 4rem auto;
    text-align: center;
}
.section-title {
    font-size: 2.5rem !important;
    font-weight: 800 !important;
    color: var(--text-primary) !important;
    margin-bottom: 0.5rem !important;
    font-family: var(--font-head);
}
.section-subtitle {
    font-size: 1.1rem !important;
    color: var(--text-secondary) !important;
    margin-bottom: 2.5rem !important;
    line-height: 1.6 !important;
}
.grid-3 {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 1.5rem;
}
.info-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 2rem 1.5rem;
    box-shadow: var(--shadow-card);
    transition: all 0.3s ease;
    text-align: left;
    backdrop-filter: blur(16px);
}
.info-card:hover {
    transform: translateY(-5px);
    border-color: rgba(16, 185, 129, 0.4);
    box-shadow: 0 10px 25px rgba(16, 185, 129, 0.15);
}
.info-card h3 {
    color: var(--text-primary) !important;
    font-size: 1.3rem !important;
    margin-bottom: 1rem !important;
    font-family: var(--font-head);
}
.info-card p {
    color: var(--text-secondary) !important;
    font-size: 0.95rem !important;
    line-height: 1.6 !important;
    margin: 0;
}

.donate-btn {
    display: flex;
    align-items: center;
    gap: 0.8rem;
    padding: 0.8rem 2rem;
    border-radius: var(--radius-pill);
    font-weight: 700;
    font-size: 1.1rem;
    text-decoration: none !important;
    transition: all 0.3s ease;
    border: 1px solid transparent;
}
.donate-crypto {
    background: rgba(245, 158, 11, 0.1);
    color: #FBBF24 !important;
    border-color: rgba(245, 158, 11, 0.3);
}
.donate-crypto:hover {
    background: rgba(245, 158, 11, 0.2);
    box-shadow: 0 0 20px rgba(245, 158, 11, 0.2);
    transform: translateY(-2px);
    color: #FCD34D !important;
}
.donate-coffee {
    background: rgba(16, 185, 129, 0.1);
    color: var(--accent) !important;
    border-color: rgba(16, 185, 129, 0.3);
}
.donate-coffee:hover {
    background: rgba(16, 185, 129, 0.2);
    box-shadow: 0 0 20px rgba(16, 185, 129, 0.2);
    transform: translateY(-2px);
    color: #34D399 !important;
}

/* ── Progress & Status ───────────────────────────────── */
.stStatusWidget {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-md) !important;
    backdrop-filter: blur(12px) !important;
}

/* ── Scrollbar ───────────────────────────────────────── */
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: var(--bg-page); }
::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: #475569; }

/* ── Glassmorphism ───────────────────────────────────── */
div[data-baseweb="input"] {
    background: transparent !important;
    border: none !important;
    box-shadow: none !important;
}
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

# --- Layout: Navbar & Footer ---
st.markdown(f"""
<div class="custom-navbar">
    <div class="nav-brand">
        <img src="{_logo_src}" alt="BudakNoob Logo" />
        <span>ZERO TRUST</span>
    </div>
    <div class="nav-links">
        <a href="/?p=home" target="_self">Home</a>
        <a href="/?p=educate" target="_self">Educate</a>
        <a href="/?p=report" target="_self">Report</a>
        <a href="/?p=donate" target="_self">Donate</a>
    </div>
</div>
<div class="custom-footer">
    <p>&copy; 2026 ZERO TRUST powered by BudakNoob OSINT Team. All rights reserved. | <a href="#">Terms of Service</a> | <a href="#">Privacy Policy</a></p>
</div>
    """, unsafe_allow_html=True)

# --- ROUTING LOGIC ---
query_params = st.query_params
active_page = query_params.get("p", "home")

# Header
if active_page == "home":
    st.markdown("""
    <div class="hero-container">
    <div class="hero-glow"></div>
    <div class="hero-badge">Advanced Threat Intelligence</div>
    <h1 class="hero-title">Expose <span class="text-gradient">Unknown Threats</span> in Seconds</h1>
    <p class="hero-subtitle">NEVER TRUST, ALWAYS VERIFY. ZERO TRUST intercepts malicious infrastructure before it impacts your organization. Deploy automated reconnaissance, gather forensic evidence, and initiate immediate takedowns.</p>
</div>
    """, unsafe_allow_html=True)

# --- Tab layout ---
if is_admin:
    tab_scan, tab_admin = st.tabs(["🔍 Threat Scanner", "🗄️ Command Center"])
    active_container = tab_scan
else:
    active_container = st.container()

with active_container:
    if active_page == "home":
        # --- DASHBOARD ---
        total_lapor, total_berjaya = get_stats()
        kill_rate = round((total_berjaya/total_lapor)*100, 1) if total_lapor > 0 else 0

        st.markdown(f"""
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon">🎯</div>
                <div class="stat-content">
                    <span class="stat-label">Threats Identified</span>
                    <span class="stat-value stat-value--danger">{total_lapor}</span>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">🛡️</div>
                <div class="stat-content">
                    <span class="stat-label">Domains Neutralized</span>
                    <span class="stat-value">{total_berjaya}</span>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">⚡</div>
                <div class="stat-content">
                    <span class="stat-label">Success Rate</span>
                    <span class="stat-value stat-value--success">{kill_rate}%</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    if active_page == "educate":
        # --- EDUCATE SECTION ---
        st.markdown("""
        <div class="section-container">
            <h2 class="section-title">Phishing <span class="text-gradient">Awareness</span></h2>
            <p class="section-subtitle">Understanding the anatomy of a phishing attack is your first line of defense against cyber threats.</p>
            <div class="grid-3">
                <div class="info-card">
                    <h3>🎣 The Bait</h3>
                    <p>Scammers use urgency, fear, or fake rewards to prompt immediate action. Always remain skeptical of unexpected emails.</p>
                </div>
                <div class="info-card">
                    <h3>🔗 The Hook</h3>
                    <p>Spoofed links are designed to look like legitimate websites. Carefully inspect domain names and look for subtle typos.</p>
                </div>
                <div class="info-card">
                    <h3>💸 The Catch</h3>
                    <p>If you enter your credentials, attackers harvest them instantly to compromise your accounts and steal your data.</p>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    if active_page == "report":
        # --- INPUT SECTION (REPORT) ---
        st.markdown("""
        <div class="section-container" style="margin-bottom: 1.5rem; margin-top: 2rem;">
            <h2 class="section-title">Scan & <span class="text-gradient">Report</span></h2>
            <p class="section-subtitle">Use our advanced threat intelligence to scan suspicious domains and initiate immediate takedowns.</p>
        </div>
        """, unsafe_allow_html=True)
        with st.container():
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
                body = urllib.parse.quote(f"Hello Abuse Desk,\n\nI am reporting a malicious phishing website hosted/registered on your network.\n\nMalicious URL: {res['url']}\nIP Address: {res['ip']}\nHosting: {res['hosting']}\nCreation Date: {res['whois']['creation_date']}\nThreat Status: {res['threat']}\nScreenshot Evidence: {res['image']}\n\nPlease investigate and suspend this domain immediately.\n\nRegards,\nReported via ZERO TRUST")
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

# --- DONATE SECTION ---
st.markdown("""
<div id="donate"></div>
<div class="section-container">
    <h2 class="section-title">Support <span class="text-gradient">The Mission</span></h2>
    <p class="section-subtitle">ZERO TRUST is maintained by the BudakNoob OSINT Team. Your donations cover our server costs and intelligence API expenses, allowing us to keep this service free for the community.</p>
    <div style="display: flex; justify-content: center; gap: 1rem; margin-top: 2rem; flex-wrap: wrap;">
        <a href="#" class="donate-btn donate-crypto"><span style="font-size: 1.5rem;">🪙</span> Crypto Donation</a>
        <a href="#" class="donate-btn donate-coffee"><span style="font-size: 1.5rem;">☕</span> Buy Us a Coffee</a>
    </div>
</div>
    """, unsafe_allow_html=True)

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