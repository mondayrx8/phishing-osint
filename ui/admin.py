"""Admin panel — operator authentication and threat-database management.

Access is controlled via a hashed-passphrase comparison stored in
``st.session_state`` — nothing leaks into the URL bar.
"""

import hmac

import streamlit as st

from core.config import AppConfig
from core.database import DatabaseManager


class AdminPanel:
    """Manages admin authentication and the Command Center UI.

    Args:
        config: Application configuration (admin credentials).
        db:     Database manager for report CRUD.
    """

    def __init__(self, config: AppConfig, db: DatabaseManager) -> None:
        self._config = config
        self._db = db

        # Ensure session state is initialised
        if "admin_authenticated" not in st.session_state:
            st.session_state.admin_authenticated = False

    # ── Properties ─────────────────────────────────────────────────

    @property
    def is_authenticated(self) -> bool:
        """Whether the current session has operator-level access."""
        return st.session_state.admin_authenticated

    # ── Authentication widget ──────────────────────────────────────

    def render_auth_widget(self) -> None:
        """Render the bottom-of-page passphrase authenticator."""
        st.markdown("<div style='height: 4rem;'></div>", unsafe_allow_html=True)
        with st.expander("⚙️ System Configuration"):
            passphrase = st.text_input(
                "Enter operator passphrase:",
                type="password",
                key="bottom_admin_passphrase",
            )
            if passphrase:
                if hmac.compare_digest(
                    passphrase.encode("utf-8"),
                    self._config.admin_secret.encode("utf-8"),
                ):
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

    # ── Command Center tab ─────────────────────────────────────────

    def render_command_center(self, container) -> None:
        """Render the admin Command Center inside *container*.

        Args:
            container: A Streamlit tab or container to draw into.
        """
        with container:
            st.markdown("### 🔐 Threat Database Management")
            pwd_input = st.text_input(
                "Authenticate to access classified records:", type="password"
            )

            if pwd_input == self._config.admin_password:
                df = self._db.get_all_reports()
                if not df.empty:
                    st.dataframe(df, use_container_width=True, hide_index=True)

                    st.markdown("#### ⚙️ Record Operations")
                    c_id, c_act = st.columns([1, 3])
                    with c_id:
                        target_id = st.number_input(
                            "Report ID:", min_value=1, step=1
                        )
                    with c_act:
                        st.write("Select action:")
                        b1, b2, b3 = st.columns(3)
                        if b1.button("✅ Mark Neutralized"):
                            self._db.update_status(target_id, "TAKEDOWN SUCCESSFUL")
                            st.rerun()
                        if b2.button("↩️ Reset to Pending"):
                            self._db.update_status(target_id, "Pending Action")
                            st.rerun()
                        if b3.button("🗑️ Delete Record"):
                            self._db.delete_report(target_id)
                            st.rerun()
                else:
                    st.info("No threat records found in the database.")
