"""Centralized application configuration.

All environment variables and constants are loaded once and exposed
through the AppConfig class.  No global variables leak into other modules.
"""

import os
from dotenv import load_dotenv


class AppConfig:
    """Immutable, single-source-of-truth configuration holder.

    Loads values from environment variables (with sensible defaults)
    and exposes them as instance attributes.  Every other class receives
    an ``AppConfig`` instance via its constructor — eliminating the need
    for scattered ``os.environ.get`` calls.
    """

    def __init__(self) -> None:
        load_dotenv()

        # --- API Keys ---
        self._vt_api_key: str = os.environ.get("VT_API_KEY", "")

        # --- Auth ---
        self._admin_password: str = os.environ.get("ADMIN_PASSWORD", "k")
        self._admin_secret: str = os.environ.get("ADMIN_SECRET", "k")

        # --- Database ---
        self._db_path: str = os.environ.get("DB_PATH", "phishing_hunter.db")

        # --- Assets ---
        self._background_image: str = "FalconO.png"
        self._logo_image: str = "BudakNoob2.png"

        # --- Trusted domains (frozen for safety) ---
        self._whitelist: frozenset = frozenset([
            "touchngo.com.my", "tngdigital.com.my", "maybank2u.com.my",
            "cimbclicks.com.my", "google.com", "facebook.com", "gov.my",
            "bankrakyat.com.my", "rhbgroup.com", "ambank.com.my",
            "pbebank.com", "hlb.com.my",
        ])

        # --- App metadata ---
        self._app_title: str = "ZERO TRUST — Threat Intelligence Platform"
        self._app_icon: str = "🛡️"
        self._team_name: str = "BudakNoob OSINT Team"

    # ── Public read-only properties ────────────────────────────────

    @property
    def vt_api_key(self) -> str:
        return self._vt_api_key

    @property
    def admin_password(self) -> str:
        return self._admin_password

    @property
    def admin_secret(self) -> str:
        return self._admin_secret

    @property
    def db_path(self) -> str:
        return self._db_path

    @property
    def background_image(self) -> str:
        return self._background_image

    @property
    def logo_image(self) -> str:
        return self._logo_image

    @property
    def whitelist(self) -> frozenset:
        return self._whitelist

    @property
    def app_title(self) -> str:
        return self._app_title

    @property
    def app_icon(self) -> str:
        return self._app_icon

    @property
    def team_name(self) -> str:
        return self._team_name

    # ── Convenience helpers ────────────────────────────────────────

    def is_whitelisted(self, root_domain: str) -> bool:
        """Check whether *root_domain* belongs to a known-safe organisation."""
        return any(root_domain.endswith(d) for d in self._whitelist)
