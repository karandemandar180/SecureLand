
import os
import io
import json
import hmac
from datetime import datetime
from xml.sax.saxutils import escape

import pandas as pd
import streamlit as st

from database import *
from forensics import run_applicable_tools, tool_availability

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Image as RLImage
)

# ==========================================
# INITIALIZATION
# ==========================================

st.set_page_config(
    page_title="SecureLand",
    page_icon="🏛️",
    layout="wide"
)

init_db()
init_new_modules()

APP_DIR = os.path.dirname(os.path.abspath(__file__))

LOGO_CANDIDATES = [
    os.path.join(APP_DIR, "cyberbridge_logo.png"),
    os.path.join(APP_DIR, "assets", "cyberbridge_logo.png")
]

LOGO_PATH = next(
    (p for p in LOGO_CANDIDATES if os.path.isfile(p)),
    LOGO_CANDIDATES[0]
)

# ==========================================
# HELPER FUNCTIONS
# ==========================================

def safe_dataframe(data):
    df = data.copy() if isinstance(data, pd.DataFrame) else pd.DataFrame(data)

    if "Available" in df.columns:
        df["Available"] = df["Available"].astype(str)

    return df


def show_df(data):
    df = safe_dataframe(data)
    st.dataframe(
        df,
        width="stretch",
        hide_index=True
    )


def audit(actor, action, details):
    try:
        add_audit(actor, action, details)
    except Exception as exc:
        st.warning(f"Audit entry warning: {exc}")


# ==========================================
# BRANDING
# ==========================================

brand_col, title_col = st.columns([1, 4])

with brand_col:
    if os.path.isfile(LOGO_PATH):
        st.image(LOGO_PATH, width=150)

with title_col:
    st.title("🏛️ SecureLand")
    st.subheader("Land Records + Digital Forensics")
    st.caption("Educational prototype — not an official government system.")
    st.caption("Developed by CyberBridge Digital Solutions Pune")


# ==========================================
# PASSWORD CONFIGURATION
# ==========================================

def get_configured_password(secret_name):
    value = None

    try:
        value = st.secrets.get(secret_name)
    except Exception:
        pass

    if not value:
        value = os.getenv(secret_name)

    return str(value).strip() if value else ""


def is_strong_password(password):
    return (
        len(password) >= 12
        and any(c.isupper() for c in password)
        and any(c.islower() for c in password)
        and any(c.isdigit() for c in password)
        and any(not c.isalnum() for c in password)
    )


PASSWORDS = {
    "Admin": get_configured_password("SECURELAND_ADMIN_PASSWORD"),
    "Talathi": get_configured_password("SECURELAND_TALATHI_PASSWORD"),
    "Citizen": get_configured_password("SECURELAND_CITIZEN_PASSWORD")
}

missing_roles = [
    role for role, password in PASSWORDS.items()
    if not password
]

weak_roles = [
    role for role, password in PASSWORDS.items()
    if password and not is_strong_password(password)
]

if missing_roles or weak_roles:

    st.error("SecureLand login configuration is incomplete.")

    if missing_roles:
        st.warning("Password missing: " + ", ".join(missing_roles))

    if weak_roles:
        st.warning("Weak password: " + ", ".join(weak_roles))

    st.info(
        "Configure strong passwords in .streamlit/secrets.toml "
        "or environment variables."
    )

    st.stop()


# ==========================================
# LOGIN AND ROLE MANAGEMENT
# ==========================================

if "logged" not in st.session_state:
    st.session_state.logged = False

if "role" not in st.session_state:
    st.session_state.role = None

st.sidebar.title("SecureLand Login")

selected_role = st.sidebar.selectbox(
    "Select Role",
    ["Citizen", "Talathi", "Admin"]
)

password = st.sidebar.text_input(
    "Password",
    type="password",
    key="login_password"
)

if st.sidebar.button("Login"):

    if hmac.compare_digest(
        password,
        PASSWORDS[selected_role]
    ):

        st.session_state.logged = True
        st.session_state.role = selected_role

        audit(
            selected_role,
            "LOGIN",
            "Successful demo login"
        )

        st.rerun()

    else:
        st.sidebar.error("Incorrect password")


if st.sidebar.button("Logout"):

    old_role = st.session_state.get("role") or "Unknown"

    if st.session_state.logged:
        audit(old_role, "LOGOUT", "User logged out")

    st.session_state.logged = False
    st.session_state.role = None

    st.session_state.pop("login_password", None)

    st.rerun()


if not st.session_state.logged:

    st.info("Please log in using your configured role password.")

    st.sidebar.caption(
        "Demo prototype. Do not upload confidential citizen data."
    )

    st.stop()


role = st.session_state.role

st.success(f"Logged in as: {role}")
