"""Workspace management — file renaming and restructuring operations.

Replaces the standalone ``rename.py`` and ``restructure.py`` scripts with
a single, reusable class.
"""

import re
from typing import Dict, List, Optional


class WorkspaceManager:
    """Performs batch find-and-replace and structural edits on project files.

    Args:
        target_file: Path to the file that will be modified (default: ``app.py``).
    """

    def __init__(self, target_file: str = "app.py") -> None:
        self._target_file = target_file
        self._content: Optional[str] = None

    # ── File I/O ───────────────────────────────────────────────────

    def load(self) -> "WorkspaceManager":
        """Read the target file into memory. Returns ``self`` for chaining."""
        with open(self._target_file, "r") as f:
            self._content = f.read()
        return self

    def save(self) -> None:
        """Write the modified content back to disk."""
        if self._content is None:
            raise RuntimeError("Nothing loaded — call .load() first.")
        with open(self._target_file, "w") as f:
            f.write(self._content)

    # ── rename.py equivalent ───────────────────────────────────────

    def bulk_replace(self, replacements: Dict[str, str]) -> "WorkspaceManager":
        """Apply multiple literal string replacements.

        Args:
            replacements: Mapping from old string → new string.

        Returns:
            ``self`` for method chaining.

        Example::

            ws = WorkspaceManager("app.py").load()
            ws.bulk_replace({
                "Phishing Hunter": "Threat Sentinel",
                "BudakNoob.png": "BudakNoob2.png",
            }).save()
        """
        if self._content is None:
            raise RuntimeError("Nothing loaded — call .load() first.")
        for old, new in replacements.items():
            self._content = self._content.replace(old, new)
        return self

    # ── restructure.py equivalent ──────────────────────────────────

    def regex_replace(
        self,
        pattern: str,
        replacement: str,
        *,
        flags: int = 0,
    ) -> "WorkspaceManager":
        """Apply a single regex substitution.

        Args:
            pattern:     Regular expression pattern.
            replacement: Replacement string (may use back-references).
            flags:       ``re`` flags (e.g. ``re.DOTALL``).

        Returns:
            ``self`` for method chaining.
        """
        if self._content is None:
            raise RuntimeError("Nothing loaded — call .load() first.")
        self._content = re.sub(pattern, replacement, self._content, flags=flags)
        return self

    def update_navbar_links(self, links: List[Dict[str, str]]) -> "WorkspaceManager":
        """Rewrite the ``.nav-links`` block with the provided link definitions.

        Args:
            links: List of dicts, each with ``href`` and ``label`` keys.

        Returns:
            ``self`` for method chaining.

        Example::

            ws.update_navbar_links([
                {"href": "/?p=home",    "label": "Home"},
                {"href": "/?p=educate", "label": "Educate"},
                {"href": "/?p=report",  "label": "Report"},
                {"href": "/?p=donate",  "label": "Donate"},
            ])
        """
        link_html = "\n".join(
            f'        <a href="{l["href"]}" target="_self">{l["label"]}</a>'
            for l in links
        )
        new_nav = f'    <div class="nav-links">\n{link_html}\n    </div>'
        return self.regex_replace(
            r'    <div class="nav-links">\n.*?</div>',
            new_nav,
            flags=re.DOTALL,
        )

    def inject_page_router(self, marker: str = "# Header") -> "WorkspaceManager":
        """Insert the query-param page-router above a given marker comment.

        Args:
            marker: The comment line to replace with the router setup.

        Returns:
            ``self`` for method chaining.
        """
        router_code = (
            '# --- ROUTING LOGIC ---\n'
            'query_params = st.query_params\n'
            'active_page = query_params.get("p", "home")\n\n'
            '# Header'
        )
        if self._content is None:
            raise RuntimeError("Nothing loaded — call .load() first.")
        self._content = self._content.replace(marker, router_code)
        return self
