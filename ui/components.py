"""Reusable HTML components for the ZERO TRUST UI.

Every method returns raw HTML strings — the caller is responsible for
rendering them via ``st.markdown(..., unsafe_allow_html=True)``.
"""

import urllib.parse


class UIComponents:
    """Factory for the application's reusable UI fragments.

    Args:
        logo_src: ``data:`` URI for the brand logo.
    """

    def __init__(self, logo_src: str = "") -> None:
        self._logo_src = logo_src

    # ── Navbar ─────────────────────────────────────────────────────

    def navbar(self) -> str:
        """Return the fixed-position top navigation bar HTML."""
        return f"""
        <div class="custom-navbar">
            <div class="nav-brand">
                <img src="{self._logo_src}" alt="BudakNoob Logo" />
                <span>ZERO TRUST</span>
            </div>
            <div class="nav-links">
                <a href="/?p=home" target="_self">Home</a>
                <a href="/?p=educate" target="_self">Educate</a>
                <a href="/?p=report" target="_self">Report</a>
                <a href="/?p=donate" target="_self">Donate</a>
            </div>
        </div>
        """

    # ── Footer ─────────────────────────────────────────────────────

    @staticmethod
    def footer() -> str:
        """Return the fixed-position bottom footer HTML."""
        return """
        <div class="custom-footer">
            <p>&copy; 2026 ZERO TRUST powered by BudakNoob OSINT Team.
            All rights reserved. |
            <a href="#">Terms of Service</a> |
            <a href="#">Privacy Policy</a></p>
        </div>
        """

    # ── Hero ───────────────────────────────────────────────────────

    @staticmethod
    def hero() -> str:
        """Return the landing-page hero section HTML."""
        return """
        <div class="hero-container">
            <div class="hero-glow"></div>
            <div class="hero-badge">Advanced Threat Intelligence</div>
            <h1 class="hero-title">Expose <span class="text-gradient">Unknown Threats</span> in Seconds</h1>
            <p class="hero-subtitle">NEVER TRUST, ALWAYS VERIFY. ZERO TRUST intercepts malicious
            infrastructure before it impacts your organization. Deploy automated
            reconnaissance, gather forensic evidence, and initiate immediate
            takedowns.</p>
        </div>
        """

    # ── Stats grid ─────────────────────────────────────────────────

    @staticmethod
    def stats_grid(total_reports: int, total_success: int, kill_rate: float) -> str:
        """Return the three-column dashboard metrics HTML."""
        return f"""
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon">🎯</div>
                <div class="stat-content">
                    <span class="stat-label">Threats Identified</span>
                    <span class="stat-value stat-value--danger">{total_reports}</span>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">🛡️</div>
                <div class="stat-content">
                    <span class="stat-label">Domains Neutralized</span>
                    <span class="stat-value">{total_success}</span>
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
        """

    # ── Educate cards ──────────────────────────────────────────────

    @staticmethod
    def educate_section() -> str:
        """Return the phishing-awareness education section HTML."""
        return """
        <div class="section-container">
            <h2 class="section-title">Phishing <span class="text-gradient">Awareness</span></h2>
            <p class="section-subtitle">Understanding the anatomy of a phishing attack is
            your first line of defense against cyber threats.</p>
            <div class="grid-3">
                <div class="info-card">
                    <h3>🎣 The Bait</h3>
                    <p>Scammers use urgency, fear, or fake rewards to prompt immediate
                    action. Always remain skeptical of unexpected emails.</p>
                </div>
                <div class="info-card">
                    <h3>🔗 The Hook</h3>
                    <p>Spoofed links are designed to look like legitimate websites.
                    Carefully inspect domain names and look for subtle typos.</p>
                </div>
                <div class="info-card">
                    <h3>💸 The Catch</h3>
                    <p>If you enter your credentials, attackers harvest them instantly
                    to compromise your accounts and steal your data.</p>
                </div>
            </div>
        </div>
        """

    # ── Donate section ─────────────────────────────────────────────

    @staticmethod
    def donate_section() -> str:
        """Return the donation call-to-action section HTML."""
        return """
        <div id="donate"></div>
        <div class="section-container">
            <h2 class="section-title">Support <span class="text-gradient">The Mission</span></h2>
            <p class="section-subtitle">ZERO TRUST is maintained by the BudakNoob OSINT Team.
            Your donations cover our server costs and intelligence API expenses,
            allowing us to keep this service free for the community.</p>
            <div style="display: flex; justify-content: center; gap: 1rem; margin-top: 2rem; flex-wrap: wrap;">
                <a href="#" class="donate-btn donate-crypto">
                    <span style="font-size: 1.5rem;">🪙</span> Crypto Donation</a>
                <a href="#" class="donate-btn donate-coffee">
                    <span style="font-size: 1.5rem;">☕</span> Buy Us a Coffee</a>
            </div>
        </div>
        """

    # ── Scan header ────────────────────────────────────────────────

    @staticmethod
    def report_header() -> str:
        """Return the scan-page header HTML."""
        return """
        <div class="section-container" style="margin-bottom: 1.5rem; margin-top: 2rem;">
            <h2 class="section-title">Scan & <span class="text-gradient">Report</span></h2>
            <p class="section-subtitle">Use our advanced threat intelligence to scan
            suspicious domains and initiate immediate takedowns.</p>
        </div>
        """

    # ── Threat banners ─────────────────────────────────────────────

    @staticmethod
    def threat_banner(threat: str) -> str:
        """Return a danger or warning banner depending on the threat string."""
        if "DANGEROUS" in threat:
            return (
                f"<div class='threat-banner-danger'>"
                f"<p>🚨 THREAT CONFIRMED — {threat}</p></div>"
            )
        return (
            f"<div class='threat-banner-warning'>"
            f"<p>⚠️ {threat} — Manual review recommended</p></div>"
        )

    # ── Takedown mailto ────────────────────────────────────────────

    @staticmethod
    def build_takedown_mailto(result: dict) -> str:
        """Build a ``mailto:`` URL for the abuse takedown request."""
        subj = urllib.parse.quote(
            f"URGENT: Phishing Abuse Report - {result['domain']}"
        )
        body = urllib.parse.quote(
            f"Hello Abuse Desk,\n\n"
            f"I am reporting a malicious phishing website hosted/registered on your network.\n\n"
            f"Malicious URL: {result['url']}\n"
            f"IP Address: {result['ip']}\n"
            f"Hosting: {result['hosting']}\n"
            f"Creation Date: {result['whois']['creation_date']}\n"
            f"Threat Status: {result['threat']}\n"
            f"Screenshot Evidence: {result['image']}\n\n"
            f"Please investigate and suspend this domain immediately.\n\n"
            f"Regards,\nReported via ZERO TRUST"
        )
        return f"mailto:{result['abuse_email']}?subject={subj}&body={body}"
