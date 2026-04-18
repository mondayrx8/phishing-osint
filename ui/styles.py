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
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;800;900&family=Share+Tech+Mono&family=JetBrains+Mono:wght@400;700&display=swap');

/* ── Design Tokens ───────────────────────────────────── */
:root {
    --bg-page: #0a0a0f;
    --bg-card: #12121a;
    --text-primary: #e0e0e0;
    --text-secondary: #6b7280;
    --accent: #00ff88;
    --accent-secondary: #ff00ff;
    --accent-tertiary: #00d4ff;
    --border: #2a2a3a;
    --input: #12121a;
    --danger: #ff3366;
    --warning-border: #F59E0B;
    
    --radius-none: 0px;
    --radius-sm: 2px;
    
    --font-head: 'Orbitron', 'Share Tech Mono', monospace;
    --font-body: 'JetBrains Mono', 'Fira Code', monospace;
    --font-mono: 'Share Tech Mono', monospace;
    
    --box-shadow-neon: 0 0 5px #00ff88, 0 0 10px #00ff8840;
    --box-shadow-neon-sm: 0 0 3px #00ff88, 0 0 6px #00ff8830;
    --box-shadow-neon-lg: 0 0 10px #00ff88, 0 0 20px #00ff8860, 0 0 40px #00ff8830;
    --box-shadow-neon-secondary: 0 0 5px #ff00ff, 0 0 20px #ff00ff60;
    --box-shadow-neon-tertiary: 0 0 5px #00d4ff, 0 0 20px #00d4ff60;
    --box-shadow-danger: 0 0 5px #ff3366, 0 0 15px #ff336640;
    --box-shadow-warning: 0 0 5px #F59E0B, 0 0 15px #F59E0B40;
}

/* ── Global Base ─────────────────────────────────────── */
html, body, .stApp, [data-testid="stAppViewContainer"] {
    background-color: var(--bg-page) !important;
    background-image: 
      linear-gradient(rgba(0, 255, 136, 0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0, 255, 136, 0.03) 1px, transparent 1px) !important;
    background-size: 50px 50px !important;
    color: var(--text-primary) !important;
    font-family: var(--font-body) !important;
}

/* Scanlines Overlay */
[data-testid="stAppViewContainer"]::after {
    content: '';
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0, 0, 0, 0.15) 2px,
      rgba(0, 0, 0, 0.15) 4px
    );
    pointer-events: none;
    z-index: 99999;
}

.stApp p, .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6, .stApp button, .stApp input, .stApp label, .stApp div[data-testid="stMarkdownContainer"] {
    font-family: var(--font-body) !important;
}
.stApp h1, .stApp h2, .stApp h3 {
    font-family: var(--font-head) !important;
    text-transform: uppercase;
}

/* ── Keyframes ───────────────────────────────────────── */
@keyframes blink {
  50% { opacity: 0; }
}

@keyframes glitch-anim {
  0%, 100% { transform: translate(0); }
  20% { transform: translate(-2px, 2px); }
  40% { transform: translate(2px, -2px); }
  60% { transform: translate(-1px, -1px); }
  80% { transform: translate(1px, 1px); }
}

@keyframes rgbShift {
  0%, 100% { text-shadow: -2px 0 #ff00ff, 2px 0 #00d4ff; }
  50% { text-shadow: 2px 0 #ff00ff, -2px 0 #00d4ff; }
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
    background: rgba(10, 10, 15, 0.9);
    border-bottom: 1px solid var(--accent);
    box-shadow: 0 0 10px rgba(0, 255, 136, 0.2);
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 5%;
    z-index: 999999;
    backdrop-filter: blur(5px);
}
.nav-brand {
    display: flex;
    align-items: center;
    gap: 1rem;
    font-family: var(--font-head);
    font-weight: 800;
    font-size: 1.3rem;
    color: var(--text-primary);
    text-transform: uppercase;
    letter-spacing: 2px;
}
.nav-brand img {
    height: 40px;
    width: auto;
    border-radius: var(--radius-none);
    filter: drop-shadow(0 0 5px var(--accent));
}
.nav-links {
    display: flex;
    gap: 2rem;
}
.nav-links a {
    color: var(--text-secondary);
    text-decoration: none;
    font-family: var(--font-mono);
    font-weight: 600;
    font-size: 0.95rem;
    transition: all 0.2s;
    text-transform: uppercase;
    letter-spacing: 0.1em;
}
.nav-links a:hover {
    color: var(--accent);
    text-shadow: var(--box-shadow-neon-sm);
}

.custom-footer {
    position: fixed;
    bottom: 0; left: 0; right: 0;
    height: 60px;
    background: rgba(10, 10, 15, 0.95);
    border-top: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 999999;
    color: var(--text-secondary);
    font-size: 0.85rem;
    font-family: var(--font-mono);
    text-transform: uppercase;
}
.custom-footer p { margin: 0; }
.custom-footer a { color: var(--accent); text-decoration: none; font-weight: 600; }
.custom-footer a:hover { text-decoration: underline; color: var(--accent); text-shadow: var(--box-shadow-neon-sm); }

/* Adjust main container */
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
    width: 200px;
    height: 100px;
    background: radial-gradient(circle, rgba(0, 255, 136, 0.15) 0%, transparent 70%);
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    z-index: 0;
    pointer-events: none;
    filter: blur(40px);
}

.hero-badge {
    position: relative;
    z-index: 1;
    background: transparent;
    border: 1px solid var(--accent);
    color: var(--accent);
    padding: 0.6rem 1.2rem;
    font-family: var(--font-mono);
    font-size: 0.85rem;
    font-weight: 600;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    margin-bottom: 2rem;
    box-shadow: var(--box-shadow-neon-sm);
    clip-path: polygon(
        0 10px, 10px 0,
        100% 0, 100% calc(100% - 10px),
        calc(100% - 10px) 100%, 0 100%
    );
}

.hero-title {
    position: relative;
    z-index: 1;
    font-size: clamp(2.5rem, 6vw, 5.5rem) !important;
    font-weight: 900 !important;
    color: var(--text-primary) !important;
    letter-spacing: 0.05em !important;
    line-height: 1.1 !important;
    margin: 0 0 1.5rem !important;
    text-transform: uppercase;
}

.cyber-glitch {
    animation: glitch-anim 3s infinite, rgbShift 2s infinite;
    display: inline-block;
}

.text-gradient {
    color: var(--accent);
    text-shadow: var(--box-shadow-neon-sm);
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
    font-family: var(--font-mono) !important;
}

.blink-cursor {
    animation: blink 1s step-end infinite;
    color: var(--accent);
    font-weight: bold;
}

/* ── Layout & Cards ──────────────────────────────────── */
.cyber-chamfer {
    clip-path: polygon(
      0 15px, 15px 0,
      100% 0, 100% calc(100% - 15px),
      calc(100% - 15px) 100%, 0 100%
    );
}
.cyber-chamfer-sm {
    clip-path: polygon(
      0 8px, 8px 0,
      100% 0, 100% calc(100% - 8px),
      calc(100% - 8px) 100%, 0 100%
    );
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
    text-transform: uppercase;
    letter-spacing: 2px;
}
.section-subtitle {
    font-size: 1.1rem !important;
    color: var(--text-secondary) !important;
    margin-bottom: 2.5rem !important;
    line-height: 1.6 !important;
    font-family: var(--font-mono) !important;
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
    padding: 1.5rem;
    display: flex;
    align-items: center;
    gap: 1.5rem;
    transition: all 150ms steps(4);
    clip-path: polygon(
      0 10px, 10px 0,
      100% 0, 100% calc(100% - 10px),
      calc(100% - 10px) 100%, 0 100%
    );
}

.stat-card:hover {
    transform: translateY(-2px);
    border-color: var(--accent);
    box-shadow: var(--box-shadow-neon);
}

.stat-icon {
    font-size: 2rem;
    color: var(--accent);
    width: 60px;
    height: 60px;
    display: flex;
    align-items: center;
    justify-content: center;
    border: 1px solid var(--border);
    clip-path: polygon(0 5px, 5px 0, 100% 0, 100% calc(100% - 5px), calc(100% - 5px) 100%, 0 100%);
    filter: drop-shadow(0 0 4px var(--accent));
}

.stat-content {
    display: flex;
    flex-direction: column;
    text-align: left;
}

.stat-label {
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.2em;
    margin-bottom: 0.3rem;
    font-family: var(--font-mono);
}

.stat-value {
    font-size: 2.2rem;
    font-weight: 800;
    color: var(--text-primary);
    line-height: 1;
    font-family: var(--font-head);
    text-shadow: var(--box-shadow-neon-sm);
}

.stat-value--danger { color: var(--danger) !important; text-shadow: var(--box-shadow-danger) !important; }
.stat-value--success { color: var(--accent) !important; text-shadow: var(--box-shadow-neon-sm) !important; }

/* ── Info Cards ──────────────────────────────────────── */
.grid-3 {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 1.5rem;
}
.info-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    padding: 2rem 1.5rem;
    transition: all 150ms steps(4);
    text-align: left;
    clip-path: polygon(
      0 15px, 15px 0,
      100% 0, 100% calc(100% - 15px),
      calc(100% - 15px) 100%, 0 100%
    );
}
.info-card:hover {
    transform: translateY(-2px);
    border-color: var(--accent);
    box-shadow: var(--box-shadow-neon);
}
.info-card h3 {
    color: var(--text-primary) !important;
    font-size: 1.3rem !important;
    margin-bottom: 1rem !important;
    font-family: var(--font-head);
    text-transform: uppercase;
    letter-spacing: 1px;
}
.info-card p {
    color: var(--text-secondary) !important;
    font-size: 0.95rem !important;
    line-height: 1.6 !important;
    margin: 0;
    font-family: var(--font-body);
}

/* ── Input Styling ────────────────────────────────────── */
.stTextInput>div>div>input {
    background: var(--input) !important;
    color: var(--accent) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-none) !important;
    font-family: var(--font-mono) !important;
    font-size: 1.1rem !important;
    padding: 16px 24px !important;
    transition: all 200ms ease !important;
    clip-path: polygon(
      0 8px, 8px 0,
      100% 0, 100% calc(100% - 8px),
      calc(100% - 8px) 100%, 0 100%
    );
}
.stTextInput>div>div>input:focus {
    border-color: var(--accent) !important;
    box-shadow: var(--box-shadow-neon) !important;
    outline: none !important;
}
.stTextInput>div>div>input::placeholder {
    color: var(--text-secondary) !important;
    font-family: var(--font-mono) !important;
}

/* ── CTA Button ──────────────────────────────────────── */
button[data-testid="stBaseButton-primary"] {
    background: var(--accent) !important;
    color: #000000 !important;
    border: none !important;
    border-radius: var(--radius-none) !important;
    font-weight: 800 !important;
    font-family: var(--font-mono) !important;
    font-size: 1.1rem !important;
    padding: 14px 32px !important;
    transition: all 150ms steps(4) !important;
    text-transform: uppercase !important;
    letter-spacing: 0.2em !important;
    clip-path: polygon(
      0 10px, 10px 0,
      100% 0, 100% calc(100% - 10px),
      calc(100% - 10px) 100%, 0 100%
    );
}
button[data-testid="stBaseButton-primary"]:hover {
    box-shadow: var(--box-shadow-neon-lg) !important;
    transform: translateY(-2px) !important;
    filter: brightness(1.2) !important;
}

/* ── Secondary Buttons & Elements ────────────────────── */
.stButton>button {
    background: transparent !important;
    color: var(--accent) !important;
    border: 2px solid var(--accent) !important;
    border-radius: var(--radius-none) !important;
    font-weight: 600 !important;
    font-family: var(--font-mono) !important;
    padding: 10px 24px !important;
    text-transform: uppercase !important;
    letter-spacing: 0.1em !important;
    transition: all 150ms steps(4) !important;
    clip-path: polygon(
      0 8px, 8px 0,
      100% 0, 100% calc(100% - 8px),
      calc(100% - 8px) 100%, 0 100%
    );
}
.stButton>button:hover {
    background: var(--accent) !important;
    color: #000 !important;
    box-shadow: var(--box-shadow-neon) !important;
}

[data-testid="stExpander"] {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-none) !important;
    clip-path: polygon(
      0 10px, 10px 0,
      100% 0, 100% calc(100% - 10px),
      calc(100% - 10px) 100%, 0 100%
    );
}
[data-testid="stExpander"] summary {
    font-family: var(--font-mono) !important;
    font-weight: 600 !important;
    color: var(--accent) !important;
    text-transform: uppercase;
}

/* ── Data Tables ─────────────────────────────────────── */
[data-testid="stDataFrame"] {
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-none) !important;
    font-family: var(--font-body) !important;
}
[data-testid="stDataFrame"] * {
    font-family: var(--font-body) !important;
}

/* ── Tabs ────────────────────────────────────────────── */
.stTabs [data-baseweb="tab-list"] {
    gap: 0 !important;
    background: transparent !important;
    padding: 0 !important;
    border-bottom: 2px solid var(--border) !important;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    color: var(--text-secondary) !important;
    border-radius: var(--radius-none) !important;
    font-weight: 600 !important;
    font-family: var(--font-mono) !important;
    font-size: 0.9rem !important;
    padding: 10px 20px !important;
    transition: all 0.2s ease !important;
    text-transform: uppercase;
    letter-spacing: 0.1em;
}
.stTabs [aria-selected="true"] {
    color: var(--accent) !important;
    text-shadow: var(--box-shadow-neon-sm) !important;
}
.stTabs [data-baseweb="tab-highlight"] {
    background-color: var(--accent) !important;
    box-shadow: var(--box-shadow-neon-sm) !important;
}
.stTabs [data-baseweb="tab-border"] { display: none !important; }

/* ── Panels & Threat Banners ─────────────────────────── */
.threat-banner-danger {
    background: transparent !important;
    border: 1px solid var(--danger) !important;
    border-left: 4px solid var(--danger) !important;
    padding: 1.25rem 1.5rem !important;
    margin-bottom: 2rem !important;
    box-shadow: inset 0 0 20px rgba(255, 51, 102, 0.1), var(--box-shadow-danger) !important;
    clip-path: polygon(0 8px, 8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%);
}
.threat-banner-danger p {
    color: var(--danger) !important;
    font-family: var(--font-mono) !important;
    font-weight: 700 !important;
    font-size: 1.1rem !important;
    margin: 0 !important;
    letter-spacing: 0.1em !important;
    text-transform: uppercase;
}
.threat-banner-warning {
    background: transparent !important;
    border: 1px solid var(--warning-border) !important;
    border-left: 4px solid var(--warning-border) !important;
    padding: 1.25rem 1.5rem !important;
    margin-bottom: 2rem !important;
    box-shadow: inset 0 0 20px rgba(245, 158, 11, 0.1), var(--box-shadow-warning) !important;
    clip-path: polygon(0 8px, 8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%);
}
.threat-banner-warning p {
    color: #FBBF24 !important;
    font-family: var(--font-mono) !important;
    font-weight: 700 !important;
    font-size: 1.1rem !important;
    margin: 0 !important;
    letter-spacing: 0.1em !important;
    text-transform: uppercase;
}

/* ── Donate Buttons ──────────────────────────────────── */
.donate-btn {
    display: flex;
    align-items: center;
    gap: 0.8rem;
    padding: 0.8rem 2rem;
    font-family: var(--font-mono);
    font-weight: 700;
    font-size: 1.1rem;
    text-decoration: none !important;
    transition: all 150ms steps(4);
    border: 1px solid transparent;
    text-transform: uppercase;
    clip-path: polygon(0 8px, 8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%);
}
.donate-crypto {
    background: transparent;
    color: #FBBF24 !important;
    border-color: #FBBF24;
}
.donate-crypto:hover {
    background: #FBBF24;
    color: #000 !important;
    box-shadow: var(--box-shadow-warning);
}
.donate-coffee {
    background: transparent;
    color: var(--accent) !important;
    border-color: var(--accent);
}
.donate-coffee:hover {
    background: var(--accent);
    color: #000 !important;
    box-shadow: var(--box-shadow-neon);
}

/* ── Progress & Status ───────────────────────────────── */
.stStatusWidget {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-none) !important;
    clip-path: polygon(0 8px, 8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%);
}

/* ── Scrollbar ───────────────────────────────────────── */
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: var(--bg-page); }
::-webkit-scrollbar-thumb { background: var(--border); }
::-webkit-scrollbar-thumb:hover { background: var(--accent); }

/* ── Glassmorphism Removal & Scroll ──────────────────── */
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
