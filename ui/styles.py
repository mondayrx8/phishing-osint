"""CSS design-system engine.

Keeps the raw stylesheet readable in source code while serving a
minified version at runtime.  The background-image placeholder is
injected dynamically from ``AssetManager``.
"""

import re

import streamlit as st


class StyleEngine:
    """Generates, minifies, and injects the application stylesheet.

    Args:
        background_css: A CSS ``url(...)`` expression for the page background.
    """

    # ── Raw stylesheet (design-system source of truth) ─────────────
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

    def __init__(self, background_css: str = "none") -> None:
        self._background_css = background_css

    # ── CSS processing ─────────────────────────────────────────────

    @staticmethod
    def _minify(css: str) -> str:
        """Runtime CSS minifier — keeps source readable, serves compressed."""
        css = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
        css = re.sub(r"\s+", " ", css)
        css = re.sub(r"\s*([{}:;,>~+])\s*", r"\1", css)
        css = re.sub(r";}", "}", css)
        return css.strip()

    def build(self) -> str:
        """Return the final, minified CSS string with tokens injected."""
        raw = self._CSS_RAW.replace("__BG_IMG_PLACEHOLDER__", self._background_css)
        return self._minify(raw)

    def inject(self) -> None:
        """Inject the compiled stylesheet and font preconnect into the page."""
        st.markdown(
            '<link rel="preconnect" href="https://fonts.googleapis.com">'
            '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>',
            unsafe_allow_html=True,
        )
        st.markdown(f"<style>{self.build()}</style>", unsafe_allow_html=True)
