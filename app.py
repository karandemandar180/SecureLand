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


# ==================================================
# PAGE CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="SecureLand",
    layout="wide"
)

init_db()

# Shared asset path for the application UI and PDF reports.
APP_DIR = os.path.dirname(os.path.abspath(__file__))
LOGO_PATH = os.path.join(APP_DIR, "assets", "cyberbridge_logo.png")

# Homepage branding
brand_col, title_col = st.columns([1, 4])
with brand_col:
    if os.path.isfile(LOGO_PATH):
        st.image(LOGO_PATH, use_container_width=True)
with title_col:
    st.title("🏛️ SecureLand — Land Records + Digital Forensics")
    st.caption("Educational prototype — not an official government system.")
    st.caption("Developed by CyberBridge Digital Solutions Pune")


# ==================================================
# STRONG PASSWORD CONFIGURATION
# ==================================================
# Do not put real passwords in this file.
# Configure these values in Streamlit Cloud > App > Settings > Secrets.
#
# Required secrets:
# SECURELAND_ADMIN_PASSWORD = "Your-Strong-Admin-Password"
# SECURELAND_TALATHI_PASSWORD = "Your-Strong-Talathi-Password"
# SECURELAND_CITIZEN_PASSWORD = "Your-Strong-Citizen-Password"
#
# Each password must be at least 12 characters and contain:
# uppercase + lowercase + number + special character.

def get_configured_password(secret_name):
    """Read a password from Streamlit Secrets or environment variables."""
    value = None

    try:
        value = st.secrets.get(secret_name)
    except Exception:
        value = None

    if not value:
        value = os.getenv(secret_name)

    return str(value).strip() if value else ""


def is_strong_password(password):
    if len(password) < 12:
        return False

    has_upper = any(ch.isupper() for ch in password)
    has_lower = any(ch.islower() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    has_special = any(not ch.isalnum() for ch in password)

    return has_upper and has_lower and has_digit and has_special


PASSWORDS = {
    "Admin": get_configured_password("SECURELAND_ADMIN_PASSWORD"),
    "Talathi": get_configured_password("SECURELAND_TALATHI_PASSWORD"),
    "Citizen": get_configured_password("SECURELAND_CITIZEN_PASSWORD")
}

missing_password_roles = [
    role_name for role_name, password in PASSWORDS.items()
    if not password
]

weak_password_roles = [
    role_name for role_name, password in PASSWORDS.items()
    if password and not is_strong_password(password)
]

if missing_password_roles or weak_password_roles:
    st.error("SecureLand login configuration is incomplete.")
    if missing_password_roles:
        st.warning(
            "Password not configured for: "
            + ", ".join(missing_password_roles)
        )
    if weak_password_roles:
        st.warning(
            "Password does not meet the strong-password policy for: "
            + ", ".join(weak_password_roles)
        )

    st.markdown(
        """
        **Required password policy**
        - Minimum 12 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one number
        - At least one special character

        Configure all three passwords in Streamlit Cloud Secrets.
        Do not use the old demo passwords and do not share passwords
        in source code, GitHub, screenshots, or chat messages.
        """
    )
    st.stop()


# ==================================================
# LOGIN AND ROLE MANAGEMENT
# ==================================================

if "logged" not in st.session_state:
    st.session_state.logged = False

if "role" not in st.session_state:
    st.session_state.role = None

role = st.sidebar.selectbox(
    "Role",
    ["Citizen", "Talathi", "Admin"]
)

pw = st.sidebar.text_input(
    "Password",
    type="password",
    key="login_password"
)

if st.sidebar.button("Login"):
    configured_password = PASSWORDS[role]

    if hmac.compare_digest(pw, configured_password):
        st.session_state.logged = True
        st.session_state.role = role

        add_audit(
            role,
            "LOGIN",
            "Successful demo login"
        )

        st.rerun()
    else:
        st.sidebar.error("Incorrect password")


if st.sidebar.button("Logout"):
    previous_role = st.session_state.get("role") or "Unknown"

    if st.session_state.get("logged", False):
        add_audit(
            previous_role,
            "LOGOUT",
            "User logged out"
        )

    st.session_state.logged = False
    st.session_state.role = None
    st.session_state.pop("login_password", None)
    st.rerun()


if not st.session_state.get("logged", False):
    st.info("Please log in using the password configured for your role.")
    st.sidebar.caption(
        "Demo prototype. Do not upload confidential citizen data."
    )
    st.stop()


role = st.session_state.role
st.success(f"Logged in as {role}")


# ==================================================
# PDF REPORT GENERATOR
# ==================================================

def create_secureland_pdf(
    evidence,
    custody_df,
    tools_df,
    audit_df,
    integrity_result
):
    """Create a branded PDF evidence report in memory."""

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=18 * mm,
        title="SecureLand Evidence Report",
        author="CyberBridge Digital Solutions Pune"
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "SecureLandTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=19,
        leading=23,
        textColor=colors.HexColor("#17365D"),
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        "SecureLandSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=10,
        leading=13,
        spaceAfter=8
    )

    heading_style = ParagraphStyle(
        "SecureLandHeading",
        parent=styles["Heading2"],
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#17365D"),
        spaceBefore=10,
        spaceAfter=5
    )

    cell_style = ParagraphStyle(
        "SecureLandCell",
        parent=styles["BodyText"],
        fontSize=7,
        leading=9,
        wordWrap="CJK"
    )

    body_style = ParagraphStyle(
        "SecureLandBody",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11
    )

    story = []

    # Optional CyberBridge logo: assets/cyberbridge_logo.png
    logo_path = LOGO_PATH

    if os.path.isfile(logo_path):
        try:
            logo = RLImage(
                logo_path,
                width=38 * mm,
                height=25 * mm,
                kind="proportional"
            )
            logo.hAlign = "CENTER"
            story.append(logo)
            story.append(Spacer(1, 4))
        except Exception:
            pass

    story.append(Paragraph("SECURELAND", title_style))
    story.append(Paragraph(
        "Land Records + Digital Forensics",
        subtitle_style
    ))

    story.append(Paragraph(
        "<b>Developed by:</b> CyberBridge Digital Solutions Pune",
        body_style
    ))
    story.append(Paragraph(
        "<b>Mobile:</b> 9423174649",
        body_style
    ))
    story.append(Paragraph(
        "<b>Email:</b> cyberbridgedigital@gmail.com",
        body_style
    ))
    story.append(Paragraph(
        "<b>Developed Year:</b> 2026",
        body_style
    ))
    story.append(Paragraph(
        "<b>Report Generated:</b> "
        + datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        body_style
    ))
    story.append(Spacer(1, 8))

    def safe_text(value):
        if value is None:
            return "N/A"
        try:
            if pd.isna(value):
                return "N/A"
        except Exception:
            pass
        return str(value)

    def make_table(rows, col_widths=None):
        if not rows:
            story.append(Paragraph("No records available.", body_style))
            return

        converted = []
        for row in rows:
            converted_row = []
            for value in row:
                converted_row.append(
                    Paragraph(escape(safe_text(value)), cell_style)
                )
            converted.append(converted_row)

        table = Table(
            converted,
            colWidths=col_widths,
            repeatRows=1,
            hAlign="LEFT"
        )

        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0),
             colors.HexColor("#17365D")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))

        story.append(table)
        story.append(Spacer(1, 5))

    def add_section(title):
        story.append(Paragraph(title, heading_style))

    # 1. Evidence details
    add_section("1. Evidence Information")

    evidence_rows = [
        ["Field", "Value"],
        ["Evidence ID", evidence.get("evidence_id", "N/A")],
        ["Case Number", evidence.get("case_ref") or "N/A"],
        ["Filename", evidence.get("filename", "N/A")],
        [
            "Registered File Size",
            str(evidence.get("size_bytes", "N/A")) + " bytes"
        ],
        ["Collected By", evidence.get("collected_by", "N/A")],
        ["Collected At", evidence.get("collected_at", "N/A")],
        ["File Path", evidence.get("filepath", "N/A")],
        ["Notes", evidence.get("notes") or "N/A"],
        ["Recorded SHA-256", evidence.get("sha256", "N/A")]
    ]

    make_table(
        evidence_rows,
        [45 * mm, 125 * mm]
    )

    # 2. File availability
    add_section("2. File Availability")

    filepath = evidence.get("filepath", "")
    file_available = bool(filepath and os.path.isfile(filepath))

    actual_size = (
        f"{os.path.getsize(filepath)} bytes"
        if file_available else "N/A"
    )

    make_table([
        ["Check", "Result"],
        [
            "File Availability",
            "FILE AVAILABLE" if file_available
            else "FILE NOT AVAILABLE"
        ],
        ["Actual File Size", actual_size]
    ], [50 * mm, 120 * mm])

    # 3. Integrity
    add_section("3. SHA-256 Integrity Verification")

    integrity_result = integrity_result or {}

    make_table([
        ["Field", "Value"],
        [
            "Verification Status",
            integrity_result.get("status", "NOT CHECKED")
        ],
        [
            "Recorded Hash",
            integrity_result.get("recorded_hash") or "N/A"
        ],
        [
            "Current Hash",
            integrity_result.get("current_hash") or "N/A"
        ]
    ], [50 * mm, 120 * mm])

    # 4. Chain of custody
    add_section("4. Chain of Custody History")

    if isinstance(custody_df, pd.DataFrame) and not custody_df.empty:
        make_table(
            [list(custody_df.columns)]
            + custody_df.fillna("").astype(str).values.tolist()
        )
    else:
        story.append(Paragraph(
            "No custody events recorded.",
            body_style
        ))

    # 5. Forensic tools
    add_section("5. Forensic Tools Results")

    if isinstance(tools_df, pd.DataFrame) and not tools_df.empty:
        make_table(
            [list(tools_df.columns)]
            + tools_df.fillna("").astype(str).values.tolist()
        )
    else:
        story.append(Paragraph(
            "No forensic tool results recorded.",
            body_style
        ))

    # 6. Audit log
    add_section("6. Audit History")

    if isinstance(audit_df, pd.DataFrame) and not audit_df.empty:
        make_table(
            [list(audit_df.columns)]
            + audit_df.fillna("").astype(str).values.tolist()
        )
    else:
        story.append(Paragraph(
            "No audit records available.",
            body_style
        ))

    # 7. Disclaimer
    add_section("7. Important Disclaimer")

    story.append(Paragraph(
        "This document is generated by an educational SecureLand "
        "prototype. It is not an official government record, forensic "
        "certification, or legal opinion. A matching SHA-256 hash "
        "indicates consistency with the recorded hash; it does not "
        "independently establish authenticity, ownership, or legal "
        "admissibility. Findings require appropriate independent "
        "verification by competent professionals.",
        body_style
    ))

    def add_page_number(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.drawString(
            15 * mm,
            9 * mm,
            "CyberBridge Digital Solutions Pune | SecureLand | 2026"
        )
        canvas.drawRightString(
            A4[0] - 15 * mm,
            9 * mm,
            f"Page {document.page}"
        )
        canvas.restoreState()

    doc.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number
    )

    buffer.seek(0)
    return buffer.getvalue()


# ==================================================
# MAIN TABS
# ==================================================

t1, t2, t3, t4, t5, t6 = st.tabs([
    "Land Records",
    "Evidence Intake",
    "Integrity Check",
    "Chain of Custody",
    "Forensic Tools",
    "Reports & Audit"
])


# ==================================================
# TAB 1: LAND RECORDS
# ==================================================

with t1:

    st.subheader("Land Records — Input → Output")

    if role in ("Admin", "Talathi"):

        with st.form("land"):

            v = st.text_input("Village")
            o = st.text_input("Owner")
            s = st.text_input("Survey/Gat number")

            go = st.form_submit_button("Save land record")

        if go:

            if v.strip() and o.strip() and s.strip():

                rid, digest = add_land_record(
                    v.strip(),
                    o.strip(),
                    s.strip(),
                    role
                )

                st.success(f"Record #{rid} saved")
                st.code(digest)

            else:
                st.error("Fill all fields.")

    df = get_land_records()

    q = st.text_input("Search village or owner")

    if q and not df.empty:

        df = df[
            df["village"].astype(str).str.contains(
                q,
                case=False,
                na=False,
                regex=False
            )
            |
            df["owner"].astype(str).str.contains(
                q,
                case=False,
                na=False,
                regex=False
            )
        ]

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True
    )


# ==================================================
# TAB 2: EVIDENCE INTAKE
# ==================================================

with t2:

    st.subheader("Evidence Intake — Input → Output")

    st.markdown("### 1. Upload New Evidence")

    if role in ("Admin", "Talathi"):

        case = st.text_input("Case/reference number")
        notes = st.text_area("Evidence notes")

        up = st.file_uploader(
            "Select evidence file",
            key="new_evidence_upload"
        )

        if st.button(
            "Acquire Evidence",
            type="primary"
        ):

            if up is None:

                st.error("First select a file.")

            else:

                eid, path, digest = add_evidence(
                    up.name,
                    up.getvalue(),
                    case,
                    role,
                    notes
                )

                add_audit(
                    role,
                    "EVIDENCE_ACQUIRED",
                    f"Evidence #{eid}: {up.name}"
                )

                st.success(f"Evidence ID: {eid}")
                st.write(f"Saved file: {path}")
                st.write("SHA-256 Hash:")
                st.code(digest)

    else:

        st.info("Citizen role: Evidence upload is not enabled.")

    st.divider()

    st.markdown("### 2. Search Existing Evidence")

    all_evidence = list_evidence()

    if not all_evidence:

        st.info("No existing evidence records found.")

    else:

        evidence_df = pd.DataFrame(all_evidence)

        search_query = st.text_input(
            "Search by Evidence ID, Filename or Case Number",
            key="evidence_search"
        )

        filtered_df = evidence_df.copy()

        if search_query.strip():

            q = search_query.strip()

            search_columns = [
                "evidence_id",
                "filename",
                "case_ref"
            ]

            mask = pd.Series(
                False,
                index=filtered_df.index
            )

            for col in search_columns:

                if col in filtered_df.columns:

                    mask = mask | filtered_df[col].astype(
                        str
                    ).str.contains(
                        q,
                        case=False,
                        na=False,
                        regex=False
                    )

            filtered_df = filtered_df[mask]

        st.markdown("### 3. Existing Evidence Records")

        st.caption(
            f"Total Evidence Records: {len(evidence_df)} | "
            f"Search Results: {len(filtered_df)}"
        )

        display_columns = [
            col for col in [
                "evidence_id",
                "case_ref",
                "filename",
                "size_bytes",
                "collected_by",
                "collected_at"
            ]
            if col in filtered_df.columns
        ]

        if filtered_df.empty:

            st.warning("No matching evidence records found.")

        else:

            st.dataframe(
                filtered_df[display_columns],
                use_container_width=True,
                hide_index=True
            )

            st.divider()

            st.markdown("### 4. View Evidence Details")

            evidence_options = {
                f"#{row['evidence_id']} — {row['filename']}": row
                for row in filtered_df.to_dict("records")
            }

            selected_label = st.selectbox(
                "Select Evidence to view details",
                list(evidence_options.keys()),
                key="evidence_details_select"
            )

            selected = evidence_options[selected_label]

            st.markdown("#### Evidence Information")

            st.write("Evidence ID:", selected.get("evidence_id"))
            st.write("Case Number:", selected.get("case_ref") or "N/A")
            st.write("Filename:", selected.get("filename"))
            st.write("Uploaded By:", selected.get("collected_by"))
            st.write("Collected At:", selected.get("collected_at"))
            st.write(
                "Registered File Size:",
                f"{selected.get('size_bytes', 0):,} bytes"
            )
            st.write("Notes:", selected.get("notes") or "N/A")

            st.markdown("#### SHA-256 Hash")
            st.code(selected.get("sha256", "N/A"))

            filepath = selected.get("filepath", "")

            st.markdown("#### File Availability Check")

            if st.button(
                "Check File Availability",
                key="check_file_availability"
            ):

                if filepath and os.path.isfile(filepath):

                    st.success("FILE AVAILABLE")
                    st.write("File Path:")
                    st.code(filepath)

                    actual_size = os.path.getsize(filepath)

                    st.write("Actual File Size:")
                    st.write(f"{actual_size:,} bytes")

                    st.write("Registered File Size:")
                    st.write(
                        f"{selected.get('size_bytes', 0):,} bytes"
                    )

                    add_audit(
                        role,
                        "FILE_AVAILABILITY_CHECK",
                        f"Evidence #{selected['evidence_id']}: "
                        "FILE AVAILABLE"
                    )

                else:

                    st.error("FILE NOT AVAILABLE")

                    st.warning(
                        "Database record exists, but the original "
                        "evidence file is missing from its recorded path."
                    )

                    add_audit(
                        role,
                        "FILE_AVAILABILITY_CHECK",
                        f"Evidence #{selected['evidence_id']}: "
                        "FILE NOT AVAILABLE"
                    )

            st.markdown("#### Integrity Verification")

            if st.button(
                "Verify Selected Evidence",
                key="verify_from_intake"
            ):

                result = verify_evidence(selected["evidence_id"])

                if result["status"] == "INTEGRITY VERIFIED":
                    st.success(result["status"])
                else:
                    st.error(result["status"])

                st.write("Recorded Hash")
                st.code(result.get("recorded_hash", "N/A"))

                st.write("Current Hash")
                st.code(result.get("current_hash") or "N/A")

                add_audit(
                    role,
                    "INTEGRITY_CHECK",
                    f"Evidence #{selected['evidence_id']}: "
                    f"{result['status']}"
                )


# ==================================================
# COMMON EVIDENCE LIST
# ==================================================

evidences = list_evidence()

choices = {
    f"#{x['evidence_id']} — {x['filename']}": x["evidence_id"]
    for x in evidences
}


# ==================================================
# TAB 3: INTEGRITY CHECK
# ==================================================

with t3:

    st.subheader("SHA-256 Integrity Check")

    if not choices:

        st.info("Acquire evidence first.")

    else:

        label = st.selectbox(
            "Select evidence",
            list(choices),
            key="verify"
        )

        if st.button("Verify integrity"):

            eid = choices[label]
            result = verify_evidence(eid)

            if result["status"] == "INTEGRITY VERIFIED":
                st.success(result["status"])
            else:
                st.error(result["status"])

            st.write("Recorded hash")
            st.code(result.get("recorded_hash", "N/A"))

            st.write("Current hash")
            st.code(result.get("current_hash") or "N/A")

            add_custody_event(
                eid,
                "INTEGRITY_CHECK",
                role,
                result["status"]
            )

            add_audit(
                role,
                "INTEGRITY_CHECK",
                f"Evidence #{eid}: {result['status']}"
            )


# ==================================================
# TAB 4: CHAIN OF CUSTODY
# ==================================================

with t4:

    st.subheader("Chain of Custody")

    if not choices:

        st.info("Acquire evidence first.")

    else:

        label = st.selectbox(
            "Evidence",
            list(choices),
            key="custody"
        )

        eid = choices[label]
        custody_df = get_custody(eid)

        with st.form("custody_form"):

            action = st.selectbox(
                "Action",
                [
                    "TRANSFERRED",
                    "EXAMINATION_STARTED",
                    "EXAMINATION_COMPLETED",
                    "SEALED",
                    "RELEASED",
                    "NOTE_ADDED"
                ]
            )

            note = st.text_area("Notes")

            submit = st.form_submit_button("Add custody event")

        if submit:

            if not note.strip():

                st.error(
                    "Notes are mandatory. Please enter event details."
                )

            elif (
                action == "RELEASED"
                and not custody_df.empty
                and custody_df["action"].astype(str).str.upper().eq(
                    "RELEASED"
                ).any()
            ):

                st.warning(
                    "Release event already exists for this Evidence ID. "
                    "Duplicate RELEASED event is not allowed."
                )

            else:

                add_custody_event(
                    eid,
                    action,
                    role,
                    note.strip()
                )

                add_audit(
                    role,
                    "CUSTODY_EVENT",
                    f"Evidence #{eid}: {action} - {note.strip()}"
                )

                st.success("Event recorded.")
                st.rerun()

        st.markdown("#### Custody History")

        st.dataframe(
            get_custody(eid),
            use_container_width=True,
            hide_index=True
        )


# ==================================================
# TAB 5: FORENSIC TOOLS
# ==================================================

with t5:

    st.subheader("Forensic Tools — Input → Process → Output")

    st.dataframe(
        pd.DataFrame(tool_availability()),
        use_container_width=True,
        hide_index=True
    )

    st.caption(
        "ExifTool works with supported metadata files; "
        "tshark requires .pcap/.pcapng. "
        "FTK Imager/Autopsy are external apps."
    )

    if not choices:

        st.info("Acquire evidence first.")

    else:

        label = st.selectbox(
            "Select evidence for analysis",
            list(choices),
            key="tools"
        )

        if st.button("Run Applicable Tools"):

            eid = choices[label]
            rec = get_evidence(eid)

            if (
                not rec
                or not rec["filepath"]
                or not os.path.isfile(rec["filepath"])
            ):

                st.error(
                    "Evidence path missing. "
                    "Re-acquire this file using Evidence Intake."
                )

            else:

                results = run_applicable_tools(
                    eid,
                    rec["filepath"],
                    role
                )

                for r in results:

                    st.markdown("### " + r["tool"])

                    if r["status"] == "SUCCESS":
                        st.success(r["status"])

                    elif r["status"] in (
                        "SKIPPED",
                        "NOT INSTALLED"
                    ):
                        st.warning(r["status"])

                    else:
                        st.error(r["status"])

                    st.code(
                        r["output"][:10000],
                        language="text"
                    )

                    save_tool_result(
                        eid,
                        r["tool"],
                        r["status"],
                        r["output"],
                        role
                    )

                    add_audit(
                        role,
                        "TOOL_RUN",
                        f"Evidence #{eid}: "
                        f"{r['tool']} {r['status']}"
                    )

        st.divider()

        st.markdown(
            "#### Register actual FTK Imager / Autopsy result"
        )

        st.caption(
            "Run the external tool separately, then paste "
            "a real summary here. This form does not run those tools."
        )

        extid = st.selectbox(
            "Evidence ID",
            [x["evidence_id"] for x in evidences],
            key="extid"
        )

        exttool = st.selectbox(
            "External tool",
            ["FTK Imager", "Autopsy", "Other"]
        )

        extout = st.text_area(
            "Actual result summary / report reference"
        )

        if st.button("Register external result"):

            if extout.strip():

                save_tool_result(
                    extid,
                    exttool,
                    "EXTERNAL RESULT",
                    extout.strip(),
                    role
                )

                add_custody_event(
                    extid,
                    "ANALYSIS_RESULT_REGISTERED",
                    role,
                    f"{exttool}: {extout[:300]}"
                )

                add_audit(
                    role,
                    "EXTERNAL_RESULT",
                    f"Evidence #{extid}: {exttool}"
                )

                st.success("Result recorded.")

            else:

                st.error("Paste the actual result first.")


# ==================================================
# TAB 6: REPORTS AND AUDIT
# ==================================================

with t6:

    st.subheader("Reports and Audit")

    if choices:

        label = st.selectbox(
            "Evidence for report",
            list(choices),
            key="report"
        )

        eid = choices[label]

        rec = get_evidence(eid)
        custody_df = get_custody(eid)
        tools_df = get_tool_results(eid)

        report = {
            "evidence": rec,
            "custody": custody_df.to_dict("records"),
            "tool_results": tools_df.to_dict("records"),
            "notice": (
                "Prototype report; not a legal conclusion."
            )
        }

        # Existing JSON report download
        st.download_button(
            "Download JSON report",
            json.dumps(
                report,
                indent=2,
                ensure_ascii=False,
                default=str
            ),
            file_name=f"secureland_evidence_{eid}.json",
            mime="application/json"
        )

        # Existing CSV report download
        st.download_button(
            "Download custody CSV",
            custody_df.to_csv(
                index=False
            ).encode("utf-8-sig"),
            file_name=f"secureland_custody_{eid}.csv",
            mime="text/csv"
        )

        st.divider()
        st.markdown("### CyberBridge Branded PDF Report")

        if st.button(
            "Generate PDF Evidence Report",
            type="primary",
            key="generate_pdf_report"
        ):

            try:

                integrity_result = verify_evidence(eid)
                audit_df = get_audit_log()

                pdf_bytes = create_secureland_pdf(
                    rec,
                    custody_df,
                    tools_df,
                    audit_df,
                    integrity_result
                )

                add_audit(
                    role,
                    "PDF_REPORT_GENERATED",
                    f"Evidence #{eid}: PDF report generated"
                )

                st.session_state["secureland_pdf"] = pdf_bytes
                st.session_state["secureland_pdf_name"] = (
                    f"SecureLand_Evidence_Report_{eid}.pdf"
                )
                st.session_state["secureland_pdf_eid"] = eid

                st.success("PDF report generated successfully.")

            except Exception as e:

                st.error(f"PDF generation failed: {e}")

        if (
            st.session_state.get("secureland_pdf")
            and st.session_state.get("secureland_pdf_eid") == eid
        ):

            st.download_button(
                "Download PDF Evidence Report",
                data=st.session_state["secureland_pdf"],
                file_name=st.session_state.get(
                    "secureland_pdf_name",
                    f"SecureLand_Report_{eid}.pdf"
                ),
                mime="application/pdf",
                key=f"download_secureland_pdf_{eid}"
            )

    else:

        st.info("Acquire evidence first.")

    st.divider()
    audit_logo_col, audit_title_col = st.columns([1, 5])
    with audit_logo_col:
        if os.path.isfile(LOGO_PATH):
            st.image(LOGO_PATH, use_container_width=True)
    with audit_title_col:
        st.markdown("### SecureLand — Audit Report")
        st.caption("Developed by CyberBridge Digital Solutions Pune")
        st.caption("Bridging Technology, Security & Digital Trust")

    st.markdown("#### Audit log")
    audit_report_df = get_audit_log()
    st.dataframe(
        audit_report_df,
        use_container_width=True,
        hide_index=True
    )

    if not audit_report_df.empty:
        st.download_button(
            "Download Audit Report (CSV)",
            audit_report_df.to_csv(index=False).encode("utf-8-sig"),
            file_name="SecureLand_Audit_Report.csv",
            mime="text/csv",
            key="download_audit_report_csv"
        )


# ==================================================
# SIDEBAR NOTICE
# ==================================================

st.sidebar.caption(
    "Demo only. Do not upload confidential citizen data."
)

st.divider()
st.markdown(
    "<div style='text-align:center; color: #777; font-size: 13px;'>"
    "Developed by <b>CyberBridge Digital Solutions Pune</b><br>"
    "Bridging Technology, Security &amp; Digital Trust"
    "</div>",
    unsafe_allow_html=True
)
