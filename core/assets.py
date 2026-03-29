"""Asset manager — loads and base64-encodes image files for CSS injection."""

import base64
import os
from typing import Optional

from core.config import AppConfig


class AssetManager:
    """Handles loading and encoding of static image assets.

    Args:
        config: An ``AppConfig`` instance providing asset file paths.
    """

    def __init__(self, config: AppConfig) -> None:
        self._bg_path: str = config.background_image
        self._logo_path: str = config.logo_image
        self._bg_b64: Optional[str] = None
        self._logo_b64: Optional[str] = None

    # ── Internal helpers ───────────────────────────────────────────

    @staticmethod
    def _encode_file(path: str) -> Optional[str]:
        """Return the base64-encoded content of *path*, or ``None``."""
        if os.path.exists(path):
            with open(path, "rb") as f:
                return base64.b64encode(f.read()).decode()
        return None

    # ── Public API ─────────────────────────────────────────────────

    def load(self) -> None:
        """Pre-load and cache both background and logo images."""
        self._bg_b64 = self._encode_file(self._bg_path)
        self._logo_b64 = self._encode_file(self._logo_path)

    @property
    def background_css(self) -> str:
        """CSS ``url(...)`` value for the background image."""
        if self._bg_b64:
            return f"url('data:image/png;base64,{self._bg_b64}')"
        return "none"

    @property
    def logo_src(self) -> str:
        """``data:`` URI suitable for an ``<img src>`` attribute."""
        if self._logo_b64:
            return f"data:image/png;base64,{self._logo_b64}"
        return ""
