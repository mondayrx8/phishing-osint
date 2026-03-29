"""Page patcher — programmatic edits to the application source file.

Replaces the standalone ``patch_pages.py`` script with an encapsulated
class that can be imported and unit-tested.
"""

import re
from typing import Optional


class PagePatcher:
    """Applies structural patches to the Streamlit app source.

    All mutations happen in-memory; call :meth:`save` explicitly to
    persist the changes to disk.

    Args:
        target_file: Absolute or relative path to the file to patch.
    """

    def __init__(self, target_file: str = "app.py") -> None:
        self._target_file = target_file
        self._content: Optional[str] = None

    # ── File I/O ───────────────────────────────────────────────────

    def load(self) -> "PagePatcher":
        """Read the target file into memory. Returns ``self`` for chaining."""
        with open(self._target_file, "r") as f:
            self._content = f.read()
        return self

    def save(self) -> None:
        """Write the current in-memory content back to disk."""
        if self._content is None:
            raise RuntimeError("Nothing loaded — call .load() first.")
        with open(self._target_file, "w") as f:
            f.write(self._content)

    # ── Patch operations ───────────────────────────────────────────

    def patch_nav_links(self) -> "PagePatcher":
        """Rewrite navbar links to use query-param routing.

        Returns:
            ``self`` for method chaining.
        """
        new_nav = (
            '    <div class="nav-links">\n'
            '        <a href="/?p=home" target="_self">Home</a>\n'
            '        <a href="/?p=educate" target="_self">Educate</a>\n'
            '        <a href="/?p=report" target="_self">Report</a>\n'
            '        <a href="/?p=donate" target="_self">Donate</a>\n'
            '    </div>'
        )
        self._content = re.sub(
            r'    <div class="nav-links">\n.*?</div>',
            new_nav,
            self._content,
            flags=re.DOTALL,
        )
        return self

    def patch_page_router(self) -> "PagePatcher":
        """Insert the page-routing logic above the ``# Header`` marker.

        Returns:
            ``self`` for method chaining.
        """
        logic = (
            '# --- ROUTING LOGIC ---\n'
            'p = st.query_params.get("p", "home")\n\n'
            '# Header / Home\n'
        )
        if self._content is None:
            raise RuntimeError("Nothing loaded — call .load() first.")
        self._content = self._content.replace("# Header\n", logic)
        return self

    def patch_hero_conditional(self) -> "PagePatcher":
        """Wrap the hero section in an ``if p == "home":`` guard.

        Returns:
            ``self`` for method chaining.
        """
        if self._content is None:
            raise RuntimeError("Nothing loaded — call .load() first.")
        self._content = self._content.replace(
            'st.markdown("""\n<div id="home"></div>',
            'if p == "home":\n    st.markdown("""\n<div id="home"></div>',
        )
        return self

    def apply_all(self) -> "PagePatcher":
        """Run every patch in sequence. Returns ``self`` for chaining.

        Usage::

            PagePatcher("app.py").load().apply_all().save()
        """
        return self.patch_nav_links().patch_page_router().patch_hero_conditional()
