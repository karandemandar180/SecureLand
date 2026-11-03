
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

# ============================================================
# PART 2: DASHBOARD + LAND RECORDS + EVIDENCE INTAKE
# ============================================================

# Create all application tabs
tabs = st.tabs([
    "Dashboard",
    "Land Records",
    "Evidence Intake",
    "Evidence Integrity",
    "Chain of Custody",
    "Forensic Tools",
    "Reports & Audit",
    "Land Integrity",
    "Fraud Risk",
    "Blockchain Ledger"
])

(
    t_dashboard,
    t_land,
    t_intake,
    t_integrity,
    t_custody,
    t_tools,
    t_reports,
    t_land_integrity,
    t_fraud,
    t_ledger
) = tabs


# ------------------------------------------------------------
# 1. DASHBOARD
# ------------------------------------------------------------

with t_dashboard:
    st.header("SecureLand Dashboard")
    st.caption("Land Records | Digital Forensics | Integrity | Fraud Risk")

    summary = get_dashboard_summary()

    c1, c2, c3 = st.columns(3)

    c1.metric("Land Records", summary.get("land_records", 0))
    c2.metric("Evidence Files", summary.get("evidence", 0))
    c3.metric("Custody Events", summary.get("custody_events", 0))

    c4, c5, c6 = st.columns(3)

    c4.metric("Forensic Tool Results", summary.get("tool_results", 0))
    c5.metric("Integrity Logs", summary.get("integrity_logs", 0))
    c6.metric("Fraud Risk Logs", summary.get("fraud_risk_logs", 0))

    st.subheader("Blockchain Ledger")

    st.metric(
        "Ledger Entries",
        summary.get("blockchain_ledger", 0)
    )

    st.info(
        "Note: This prototype uses a hash-linked SQLite ledger. "
        "It is not a distributed blockchain network."
    )

    if st.button("Refresh Dashboard", key="refresh_dashboard"):
        st.rerun()


# ------------------------------------------------------------
# 2. LAND RECORDS
# ------------------------------------------------------------

with t_land:
    st.header("Land Records Management")

    if role in ["Admin", "Talathi"]:
        st.subheader("Add New Land Record")

        with st.form("land_record_form"):
            village = st.text_input("Village Name")
            owner = st.text_input("Land Owner Name")
            survey_no = st.text_input("Survey / Gat Number")

            submit_record = st.form_submit_button(
                "Save Land Record"
            )

        if submit_record:
            if not village.strip() or not owner.strip() or not survey_no.strip():
                st.error("Please enter all required fields.")
            else:
                try:
                    result = add_land_record(
                        village.strip(),
                        owner.strip(),
                        survey_no.strip(),
                        role
                    )

                    st.success("Land record saved successfully.")
                    st.write(result)

                    audit(
                        "LAND_RECORD_ADDED",
                        f"Village={village}, Survey={survey_no}"
                    )

                    st.rerun()

                except Exception as e:
                    st.error(f"Unable to save record: {e}")

    else:
        st.info("Citizen role has read-only access.")

    st.subheader("Available Land Records")

    land_records = get_land_records()

    if land_records:
        land_df = pd.DataFrame(land_records)
        show_df(land_df)
    else:
        st.warning("No land records available.")


# ------------------------------------------------------------
# 3. EVIDENCE INTAKE
# ------------------------------------------------------------

with t_intake:
    st.header("Digital Evidence Intake")

    st.write(
        "Upload evidence files for forensic examination. "
        "The system calculates a SHA-256 hash for integrity tracking."
    )

    if role in ["Admin", "Talathi"]:
        uploaded_file = st.file_uploader(
            "Upload Evidence File",
            type=None,
            key="evidence_upload"
        )

        evidence_description = st.text_area(
            "Evidence Description",
            placeholder="Enter source, purpose and relevant details..."
        )

        if st.button("Submit Evidence", key="submit_evidence"):
            if uploaded_file is None:
                st.error("Please select an evidence file.")
            else:
                try:
                    file_bytes = uploaded_file.getvalue()

                    result = add_evidence(
                        uploaded_file.name,
                        file_bytes,
                        evidence_description,
                        role
                    )

                    st.success("Evidence submitted successfully.")
                    st.write(result)

                    audit(
                        "EVIDENCE_UPLOADED",
                        uploaded_file.name
                    )

                    st.rerun()

                except Exception as e:
                    st.error(f"Evidence upload failed: {e}")

    else:
        st.info("Citizen role has read-only access.")

    st.subheader("Evidence Register")

    evidence_records = list_evidence()

    if evidence_records:
        evidence_df = pd.DataFrame(evidence_records)
        show_df(evidence_df)

        if "id" in evidence_df.columns:
            evidence_ids = evidence_df["id"].tolist()

            selected_evidence = st.selectbox(
                "Select Evidence ID",
                evidence_ids,
                key="intake_evidence_id"
            )

            evidence_details = get_evidence(selected_evidence)

            if evidence_details:
                st.write("Selected Evidence Details")
                st.json(dict(evidence_details))

    else:
        st.warning("No evidence records available.")


# ------------------------------------------------------------
# 4. EVIDENCE INTEGRITY CHECK
# ------------------------------------------------------------

with t_integrity:
    st.header("Evidence Integrity Verification")

    evidence_records = list_evidence()

    if evidence_records:
        evidence_df = pd.DataFrame(evidence_records)

        if "id" in evidence_df.columns:
            evidence_ids = evidence_df["id"].tolist()

            selected_id = st.selectbox(
                "Select Evidence ID",
                evidence_ids,
                key="integrity_evidence_id"
            )

            selected_details = get_evidence(selected_id)

            if selected_details:
                st.subheader("Evidence Information")
                st.json(dict(selected_details))

            if st.button(
                "Verify Evidence SHA-256",
                key="verify_evidence_hash"
            ):
                try:
                    verification = verify_evidence(selected_id)

                    st.subheader("Verification Result")
                    st.write(verification)

                    audit(
                        "EVIDENCE_INTEGRITY_CHECK",
                        f"Evidence ID={selected_id}"
                    )

                except Exception as e:
                    st.error(f"Verification failed: {e}")

    else:
        st.warning("No evidence available for verification.")

    st.caption(
        "A matching SHA-256 hash indicates consistency with the "
        "stored reference hash. It does not independently prove "
        "the authenticity or legal admissibility of the evidence."
    )

# ============================================================
# PART 3: CHAIN OF CUSTODY + FORENSIC TOOLS + REPORTS
# ============================================================


# ------------------------------------------------------------
# PDF REPORT GENERATOR
# ------------------------------------------------------------

def create_secureland_pdf(title, content):
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer
    )
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    from reportlab.lib.units import inch

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph(
        "CyberBridge Digital Solutions Pune",
        styles["Title"]
    ))

    story.append(Paragraph(
        "Bridging Technology, Security & Digital Trust",
        styles["Normal"]
    ))

    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph(title, styles["Heading1"]))
    story.append(Spacer(1, 0.15 * inch))

    story.append(Paragraph(
        "Mobile: 9423174649 | Email: cyberbridgedigital@gmail.com",
        styles["Normal"]
    ))

    story.append(Spacer(1, 0.2 * inch))

    for line in str(content).splitlines():
        safe_line = escape(line)
        story.append(Paragraph(safe_line, styles["Normal"]))
        story.append(Spacer(1, 5))

    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph(
        "Generated by SecureLand Prototype. "
        "This report is a technical system output and is not "
        "a government-certified or independent forensic opinion.",
        styles["Italic"]
    ))

    doc.build(story)

    buffer.seek(0)
    return buffer.getvalue()


# ------------------------------------------------------------
# 5. CHAIN OF CUSTODY
# ------------------------------------------------------------

with t_custody:
    st.header("Digital Evidence - Chain of Custody")

    evidence_records = list_evidence()

    if evidence_records:
        evidence_df = pd.DataFrame(evidence_records)

        if "id" in evidence_df.columns:
            evidence_ids = evidence_df["id"].tolist()

            selected_id = st.selectbox(
                "Select Evidence",
                evidence_ids,
                key="custody_evidence_id"
            )

            st.subheader("Add Custody Event")

            if role in ["Admin", "Talathi"]:
                with st.form("custody_form"):
                    action = st.selectbox(
                        "Action",
                        [
                            "Evidence Received",
                            "Evidence Examined",
                            "Evidence Transferred",
                            "Evidence Stored",
                            "Evidence Returned"
                        ]
                    )

                    remarks = st.text_area("Remarks")

                    submit_custody = st.form_submit_button(
                        "Save Custody Event"
                    )

                if submit_custody:
                    try:
                        result = add_custody_event(
                            selected_id,
                            action,
                            remarks,
                            role
                        )

                        st.success("Custody event saved.")
                        st.write(result)

                        audit(
                            "CUSTODY_EVENT_ADDED",
                            f"Evidence ID={selected_id}, Action={action}"
                        )

                        st.rerun()

                    except Exception as e:
                        st.error(f"Unable to save custody event: {e}")

            st.subheader("Custody History")

            custody_history = get_custody(selected_id)

            if custody_history:
                show_df(pd.DataFrame(custody_history))
            else:
                st.info("No custody history found.")

    else:
        st.warning("Upload evidence before creating custody events.")

    st.caption(
        "Maintain original evidence, access controls, timestamps, "
        "hash values and documented transfers. System logs alone "
        "do not establish legal admissibility."
    )


# ------------------------------------------------------------
# 6. FORENSIC TOOLS
# ------------------------------------------------------------

with t_tools:
    st.header("Digital Forensics Tools")

    st.subheader("Tool Availability")

    try:
        availability_df = pd.DataFrame(tool_availability())

        # Fix for mixed boolean/string values causing PyArrow error
        if "Available" in availability_df.columns:
            availability_df["Available"] = (
                availability_df["Available"].astype(str)
            )

        show_df(availability_df)

    except Exception as e:
        st.error(f"Unable to load tool availability: {e}")

    st.divider()

    st.subheader("Run Forensic Examination")

    evidence_records = list_evidence()

    if evidence_records:
        evidence_df = pd.DataFrame(evidence_records)

        if "id" in evidence_df.columns:
            evidence_ids = evidence_df["id"].tolist()

            selected_id = st.selectbox(
                "Select Evidence for Examination",
                evidence_ids,
                key="forensic_evidence_id"
            )

            if st.button(
                "Run Applicable Forensic Tools",
                key="run_forensic_tools"
            ):
                try:
                    result = run_applicable_tools(selected_id)

                    st.subheader("Forensic Examination Output")
                    st.write(result)

                    audit(
                        "FORENSIC_TOOLS_EXECUTED",
                        f"Evidence ID={selected_id}"
                    )

                except Exception as e:
                    st.error(f"Forensic execution failed: {e}")

    else:
        st.warning("No evidence files available.")

    st.info(
        "Tool availability depends on file format and installed "
        "software. For example, TShark requires PCAP/PCAPNG network "
        "capture files. ExifTool must be installed and available on PATH."
    )


# ------------------------------------------------------------
# 7. REPORTS AND AUDIT
# ------------------------------------------------------------

with t_reports:
    st.header("Reports & Audit Management")

    st.subheader("Land Records Report")

    land_records = get_land_records()

    if land_records:
        land_df = pd.DataFrame(land_records)

        show_df(land_df)

        csv_data = land_df.to_csv(index=False).encode("utf-8")

        st.download_button(
            "Download Land Records CSV",
            data=csv_data,
            file_name="secureland_land_records.csv",
            mime="text/csv"
        )

    else:
        st.info("No land records available.")

    st.divider()

    st.subheader("Evidence Report")

    evidence_records = list_evidence()

    if evidence_records:
        evidence_df = pd.DataFrame(evidence_records)

        show_df(evidence_df)

        evidence_csv = evidence_df.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            "Download Evidence CSV",
            data=evidence_csv,
            file_name="secureland_evidence_report.csv",
            mime="text/csv"
        )

    else:
        st.info("No evidence records available.")

    st.divider()

    st.subheader("Audit Log")

    audit_records = get_audit_log()

    if audit_records:
        audit_df = pd.DataFrame(audit_records)

        show_df(audit_df)

        audit_csv = audit_df.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            "Download Audit CSV",
            data=audit_csv,
            file_name="secureland_audit_log.csv",
            mime="text/csv"
        )

    else:
        st.info("No audit entries available.")

    st.divider()

    st.subheader("Generate PDF Summary")

    if st.button(
        "Generate SecureLand PDF Report",
        key="generate_pdf_report"
    ):
        try:
            report_content = []

            report_content.append(
                f"Generated On: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )

            report_content.append(
                f"Generated By: {role}"
            )

            report_content.append(
                f"Total Land Records: {len(land_records) if land_records else 0}"
            )

            report_content.append(
                f"Total Evidence Files: {len(evidence_records) if evidence_records else 0}"
            )

            report_content.append("")

            report_content.append("LAND RECORDS")

            if land_records:
                for record in land_records:
                    report_content.append(str(dict(record)))

            report_content.append("")
            report_content.append("EVIDENCE REGISTER")

            if evidence_records:
                for record in evidence_records:
                    report_content.append(str(dict(record)))

            pdf_bytes = create_secureland_pdf(
                "SecureLand System Summary Report",
                "\n".join(report_content)
            )

            st.download_button(
                "Download PDF Report",
                data=pdf_bytes,
                file_name="SecureLand_Report.pdf",
                mime="application/pdf"
            )

            audit(
                "PDF_REPORT_GENERATED",
                "SecureLand System Summary Report"
            )

        except Exception as e:
            st.error(f"PDF generation failed: {e}")

# ============================================================
# PART 4: LAND INTEGRITY + FRAUD RISK + BLOCKCHAIN LEDGER
# ============================================================


# ------------------------------------------------------------
# 8. LAND RECORD INTEGRITY
# ------------------------------------------------------------

with t_land_integrity:
    st.header("Land Record Integrity Verification")

    land_records = get_land_records()

    if land_records:
        land_df = pd.DataFrame(land_records)

        if "id" in land_df.columns:
            record_ids = land_df["id"].tolist()

            selected_record_id = st.selectbox(
                "Select Land Record",
                record_ids,
                key="land_integrity_record_id"
            )

            selected_record = get_land_record(selected_record_id)

            if selected_record:
                st.subheader("Land Record Details")
                st.json(selected_record)

            if st.button(
                "Verify Land Record Integrity",
                key="verify_land_integrity"
            ):
                try:
                    result = verify_land_record_integrity(
                        selected_record_id
                    )

                    st.subheader("Integrity Verification Result")
                    st.json(result)

                    if result.get("status") == "INTEGRITY VERIFIED":
                        st.success("Stored record hash matches the recalculated hash.")
                    else:
                        st.warning("Integrity verification requires investigation.")

                except Exception as e:
                    st.error(f"Integrity verification failed: {e}")

    else:
        st.warning("No land records available.")

    st.caption(
        "This check compares the current land record fields with "
        "the stored SHA-256 hash. It does not independently prove "
        "ownership, authenticity or legal validity."
    )

    st.subheader("Integrity Verification History")

    integrity_history = get_integrity_history(
        selected_record_id
    ) if land_records else []

    if integrity_history:
        show_df(pd.DataFrame(integrity_history))
    else:
        st.info("No integrity history available.")


# ------------------------------------------------------------
# 9. FRAUD RISK ANALYSIS
# ------------------------------------------------------------

with t_fraud:
    st.header("Land Record Fraud Risk Analysis")

    st.info(
        "This prototype uses rule-based checks. "
        "It is not a trained AI fraud detection model."
    )

    land_records = get_land_records()

    if land_records:
        land_df = pd.DataFrame(land_records)

        if "id" in land_df.columns:
            record_ids = land_df["id"].tolist()

            selected_risk_id = st.selectbox(
                "Select Land Record for Risk Analysis",
                record_ids,
                key="fraud_risk_record_id"
            )

            if st.button(
                "Analyze Fraud Risk",
                key="analyze_fraud_risk"
            ):
                try:
                    risk_result = analyze_land_record(
                        selected_risk_id
                    )

                    st.subheader("Risk Analysis Result")
                    st.json(risk_result)

                    risk_level = risk_result.get("risk_level", "UNKNOWN")
                    risk_score = risk_result.get("risk_score", 0)

                    st.metric("Risk Score", risk_score)
                    st.metric("Risk Level", risk_level)

                    if risk_level == "HIGH":
                        st.error("High-risk indicators detected. Manual review required.")
                    elif risk_level == "MEDIUM":
                        st.warning("Potential risk indicators detected. Further review recommended.")
                    elif risk_level == "LOW":
                        st.success("No configured risk rules were triggered.")
                    else:
                        st.info("Review the analysis output.")

                except Exception as e:
                    st.error(f"Risk analysis failed: {e}")

            st.subheader("Risk Analysis History")

            risk_history = get_risk_history(selected_risk_id)

            if risk_history:
                show_df(pd.DataFrame(risk_history))
            else:
                st.info("No risk analysis history available.")

    else:
        st.warning("No land records available.")

    st.divider()

    st.subheader("Overall Risk Summary")

    try:
        risk_summary = get_risk_summary()

        if risk_summary is not None and len(risk_summary) > 0:
            show_df(pd.DataFrame(risk_summary))
        else:
            st.info("No risk analysis data available.")

    except Exception as e:
        st.error(f"Unable to load risk summary: {e}")


# ------------------------------------------------------------
# 10. HASH-LINKED BLOCKCHAIN LEDGER
# ------------------------------------------------------------

with t_ledger:
    st.header("Blockchain / Hash-Linked Ledger")

    st.info(
        "This prototype implements a hash-linked ledger in SQLite. "
        "It demonstrates record linking and tamper-evident verification; "
        "it is not a distributed blockchain network."
    )

    land_records = get_land_records()

    if land_records:
        land_df = pd.DataFrame(land_records)

        if "id" in land_df.columns:
            record_ids = land_df["id"].tolist()

            selected_ledger_id = st.selectbox(
                "Select Land Record",
                record_ids,
                key="ledger_record_id"
            )

            if role in ["Admin", "Talathi"]:
                if st.button(
                    "Create Ledger Snapshot",
                    key="create_ledger_snapshot"
                ):
                    try:
                        ledger_result = add_ledger_entry(
                            selected_ledger_id,
                            action="LAND_RECORD_SNAPSHOT",
                            created_by=role
                        )

                        st.subheader("Ledger Entry Result")
                        st.json(ledger_result)

                        if ledger_result.get("status") == "LEDGER ENTRY CREATED":
                            st.success("Ledger snapshot created.")
                        else:
                            st.warning("Check the ledger result.")

                    except Exception as e:
                        st.error(f"Ledger entry creation failed: {e}")

            else:
                st.info("Citizen role has read-only access.")

    else:
        st.warning("No land records available.")

    st.divider()

    st.subheader("Ledger Chain Verification")

    if st.button(
        "Verify Complete Ledger Chain",
        key="verify_ledger_chain"
    ):
        try:
            chain_result = verify_ledger_chain()

            st.json(chain_result)

            if chain_result.get("status") == "CHAIN VERIFIED":
                st.success("Ledger hash chain verification successful.")
            else:
                st.error("Ledger chain verification failed. Investigation required.")

        except Exception as e:
            st.error(f"Ledger verification error: {e}")

    st.divider()

    st.subheader("Ledger History")

    try:
        ledger_history = get_ledger_history()

        if ledger_history:
            show_df(pd.DataFrame(ledger_history))
        else:
            st.info("No ledger entries available.")

    except Exception as e:
        st.error(f"Unable to load ledger history: {e}")


# ------------------------------------------------------------
# APPLICATION FOOTER
# ------------------------------------------------------------

st.divider()

st.caption(
    "SecureLand Prototype | CyberBridge Digital Solutions Pune"
)

st.caption(
    "Bridging Technology, Security & Digital Trust"
)

st.caption(
    "For demonstration and research purposes. "
    "Not an official government land-record platform."
)

