import os, json, pandas as pd, streamlit as st
from database import *
from forensics import run_applicable_tools, tool_availability

st.set_page_config(page_title="SecureLand", layout="wide")
init_db()
st.title("🏛️ SecureLand — Land Records + Digital Forensics")
st.caption("Educational prototype — not an official government system.")
PASSWORDS={"Admin":os.getenv("SECURELAND_ADMIN_PASSWORD","admin123"),
"Talathi":os.getenv("SECURELAND_TALATHI_PASSWORD","talathi123"),
"Citizen":os.getenv("SECURELAND_CITIZEN_PASSWORD","citizen123")}
role=st.sidebar.selectbox("Role",["Citizen","Talathi","Admin"])
pw=st.sidebar.text_input("Password",type="password")
if st.sidebar.button("Login"):
    if pw==PASSWORDS[role]:
        st.session_state.logged=True; st.session_state.role=role
        add_audit(role,"LOGIN","Successful demo login"); st.rerun()
    else: st.sidebar.error("Incorrect password")
if st.sidebar.button("Logout"):
    st.session_state.logged=False; st.session_state.pop("role",None); st.rerun()
if not st.session_state.get("logged",False):
    st.info("Login: Admin/admin123, Talathi/talathi123, Citizen/citizen123 (demo only).")
    st.stop()
role=st.session_state.role
st.success(f"Logged in as {role}")
t1,t2,t3,t4,t5,t6=st.tabs(["Land Records","Evidence Intake","Integrity Check","Chain of Custody","Forensic Tools","Reports & Audit"])

with t1:
    st.subheader("Land Records — Input → Output")
    if role in ("Admin","Talathi"):
        with st.form("land"):
            v=st.text_input("Village"); o=st.text_input("Owner"); s=st.text_input("Survey/Gat number")
            go=st.form_submit_button("Save land record")
        if go:
            if v.strip() and o.strip() and s.strip():
                rid,digest=add_land_record(v.strip(),o.strip(),s.strip(),role)
                st.success(f"Record #{rid} saved"); st.code(digest)
            else: st.error("Fill all fields.")
    df=get_land_records()
    q=st.text_input("Search village or owner")
    if q and not df.empty:
        df=df[df.village.str.contains(q,case=False,na=False)|df.owner.str.contains(q,case=False,na=False)]
    st.dataframe(df,use_container_width=True,hide_index=True)

with t2:
    st.subheader("Evidence Intake — Input → Output")
    case=st.text_input("Case/reference number")
    notes=st.text_area("Evidence notes")
    up=st.file_uploader("Select evidence file")
    if st.button("Acquire Evidence",type="primary"):
        if up is None: st.error("First select a file.")
        else:
            eid,path,digest=add_evidence(up.name,up.getvalue(),case,role,notes)
            add_audit(role,"EVIDENCE_ACQUIRED",f"Evidence #{eid}: {up.name}")
            st.success(f"Evidence ID: {eid}"); st.write(f"Saved file: {path}"); st.code(digest)

evidences=list_evidence()
choices={f"#{x['evidence_id']} — {x['filename']}":x['evidence_id'] for x in evidences}
with t3:
    st.subheader("SHA-256 Integrity Check")
    if not choices: st.info("Acquire evidence first.")
    else:
        label=st.selectbox("Select evidence",list(choices),key="verify")
        if st.button("Verify integrity"):
            eid=choices[label]; result=verify_evidence(eid)
            (st.success if result["status"]=="INTEGRITY VERIFIED" else st.error)(result["status"])
            st.write("Recorded hash"); st.code(result.get("recorded_hash","N/A"))
            st.write("Current hash"); st.code(result.get("current_hash") or "N/A")
            add_custody_event(eid,"INTEGRITY_CHECK",role,result["status"])
            add_audit(role,"INTEGRITY_CHECK",f"Evidence #{eid}: {result['status']}")

with t4:
    st.subheader("Chain of Custody")
    if not choices: st.info("Acquire evidence first.")
    else:
        label=st.selectbox("Evidence",list(choices),key="custody")
        with st.form("custody_form"):
            action=st.selectbox("Action",["TRANSFERRED","EXAMINATION_STARTED","EXAMINATION_COMPLETED","SEALED","RELEASED","NOTE_ADDED"])
            note=st.text_area("Notes")
            submit=st.form_submit_button("Add custody event")
        if submit:
            add_custody_event(choices[label],action,role,note)
            add_audit(role,"CUSTODY_EVENT",f"Evidence #{choices[label]}: {action}")
            st.success("Event recorded.")
        st.dataframe(get_custody(choices[label]),use_container_width=True,hide_index=True)

with t5:
    st.subheader("Forensic Tools — Input → Process → Output")
    st.dataframe(pd.DataFrame(tool_availability()),use_container_width=True,hide_index=True)
    st.caption("ExifTool works with supported metadata files; tshark requires .pcap/.pcapng. FTK Imager/Autopsy are external apps.")
    if not choices: st.info("Acquire evidence first.")
    else:
        label=st.selectbox("Select evidence for analysis",list(choices),key="tools")
        if st.button("Run Applicable Tools"):
            eid=choices[label]; rec=get_evidence(eid)
            if not rec or not rec["filepath"] or not os.path.isfile(rec["filepath"]):
                st.error("Evidence path missing. Re-acquire this file using Evidence Intake.")
            else:
                results=run_applicable_tools(eid,rec["filepath"],role)
                for r in results:
                    st.markdown("### "+r["tool"])
                    if r["status"]=="SUCCESS": st.success(r["status"])
                    elif r["status"] in ("SKIPPED","NOT INSTALLED"): st.warning(r["status"])
                    else: st.error(r["status"])
                    st.code(r["output"][:10000],language="text")
                    save_tool_result(eid,r["tool"],r["status"],r["output"],role)
                    add_audit(role,"TOOL_RUN",f"Evidence #{eid}: {r['tool']} {r['status']}")
        st.divider()
        st.markdown("#### Register actual FTK Imager / Autopsy result")
        st.caption("Run the external tool separately, then paste a real summary here. This form does not run those tools.")
        extid=st.selectbox("Evidence ID",[x["evidence_id"] for x in evidences],key="extid")
        exttool=st.selectbox("External tool",["FTK Imager","Autopsy","Other"])
        extout=st.text_area("Actual result summary / report reference")
        if st.button("Register external result"):
            if extout.strip():
                save_tool_result(extid,exttool,"EXTERNAL RESULT",extout.strip(),role)
                add_custody_event(extid,"ANALYSIS_RESULT_REGISTERED",role,f"{exttool}: {extout[:300]}")
                add_audit(role,"EXTERNAL_RESULT",f"Evidence #{extid}: {exttool}")
                st.success("Result recorded.")
            else: st.error("Paste the actual result first.")

with t6:
    st.subheader("Reports and Audit")
    if choices:
        label=st.selectbox("Evidence for report",list(choices),key="report")
        eid=choices[label]; rec=get_evidence(eid)
        report={"evidence":rec,"custody":get_custody(eid).to_dict("records"),
                "tool_results":get_tool_results(eid).to_dict("records"),
                "notice":"Prototype report; not a legal conclusion."}
        st.json(report)
        st.download_button("Download JSON report",json.dumps(report,indent=2,ensure_ascii=False,default=str),
                           file_name=f"secureland_evidence_{eid}.json",mime="application/json")
        st.download_button("Download custody CSV",get_custody(eid).to_csv(index=False).encode("utf-8-sig"),
                           file_name=f"secureland_custody_{eid}.csv",mime="text/csv")
    st.markdown("#### Audit log")
    st.dataframe(get_audit_log(),use_container_width=True,hide_index=True)
st.sidebar.caption("Demo only. Do not upload confidential citizen data.")
