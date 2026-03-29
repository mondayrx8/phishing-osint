"""ZERO TRUST — Threat Intelligence Platform.

Main entry point.  Instantiates all service objects and delegates
rendering to the page-router.

Run with:  ``streamlit run app.py``
"""

import streamlit as st

from core.config import AppConfig
from core.database import DatabaseManager
from core.osint import OSINTEngine
from core.assets import AssetManager
from ui.styles import StyleEngine
from ui.components import UIComponents
from ui.pages import PageRenderer
from ui.admin import AdminPanel


class PhishingServer:
    """Top-level application orchestrator.

    Wires together configuration, database, OSINT engines, asset loading,
    styling, UI components, page rendering, and admin management.
    """

    def __init__(self) -> None:
        # ── Core services ──────────────────────────────────────────
        self._config = AppConfig()
        self._db = DatabaseManager(self._config)
        self._osint = OSINTEngine(self._config)

        # ── Asset pipeline ─────────────────────────────────────────
        self._assets = AssetManager(self._config)
        self._assets.load()

        # ── UI layer ───────────────────────────────────────────────
        self._style_engine = StyleEngine(self._assets.background_css)
        self._components = UIComponents(self._assets.logo_src)
        self._pages = PageRenderer(
            self._config, self._db, self._osint, self._components
        )
        self._admin = AdminPanel(self._config, self._db)

    # ── Streamlit page config (must be the first Streamlit call) ───

    @staticmethod
    def _configure_page(config: AppConfig) -> None:
        """Set Streamlit page metadata. Must run before any widget call."""
        st.set_page_config(
            page_title=config.app_title,
            page_icon=config.app_icon,
            layout="wide",
            initial_sidebar_state="expanded",
        )

    # ── Main application loop ──────────────────────────────────────

    def run(self) -> None:
        """Execute the full render pipeline for the current request."""
        # 1 — Bootstrap database
        self._db.init_db()

        # 2 — Inject stylesheet
        self._style_engine.inject()

        # 3 — Global chrome (navbar + footer)
        st.markdown(self._components.navbar(), unsafe_allow_html=True)
        st.markdown(self._components.footer(), unsafe_allow_html=True)

        # 4 — Determine active page from query params
        active_page = st.query_params.get("p", "home")

        # 5 — Tab layout (admin gets an extra tab)
        is_admin = self._admin.is_authenticated
        if is_admin:
            tab_scan, tab_admin = st.tabs(
                ["🔍 Threat Scanner", "🗄️ Command Center"]
            )
            active_container = tab_scan
        else:
            active_container = st.container()

        # 6 — Render the active page inside the scanner tab / container
        with active_container:
            _PAGE_MAP = {
                "home": self._pages.render_home,
                "educate": self._pages.render_educate,
                "report": self._pages.render_report,
                "donate": self._pages.render_donate,
            }
            renderer = _PAGE_MAP.get(active_page, self._pages.render_home)
            renderer()

        # 7 — Admin Command Center (second tab)
        if is_admin:
            self._admin.render_command_center(tab_admin)

        # 8 — Donate section (always visible at bottom)
        if active_page != "donate":
            st.markdown(
                self._components.donate_section(), unsafe_allow_html=True
            )

        # 9 — Operator authentication widget
        self._admin.render_auth_widget()


# ── Bootstrap ──────────────────────────────────────────────────────

# set_page_config MUST be the very first Streamlit command
_config_boot = AppConfig()
PhishingServer._configure_page(_config_boot)

# Instantiate and run
server = PhishingServer()
server.run()