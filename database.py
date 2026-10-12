import hashlib, os, sqlite3, uuid
from pathlib import Path
from datetime import datetime, timezone
import pandas as pd

BASE=Path(__file__).resolve().parent
DB=BASE/"secureland.db"
EVIDENCE_DIR=BASE/"evidence"
EVIDENCE_DIR.mkdir(exist_ok=True)

def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")
def get_db_path(): return str(DB)
def conn():
    c=sqlite3.connect(DB,timeout=30); c.row_factory=sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON"); return c

def init_db():
    with conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS land_records(id INTEGER PRIMARY KEY, village TEXT NOT NULL, owner TEXT NOT NULL, survey_no TEXT NOT NULL, record_hash TEXT NOT NULL, created_at TEXT NOT NULL, created_by TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS evidence(evidence_id INTEGER PRIMARY KEY, case_ref TEXT, filename TEXT NOT NULL, filepath TEXT NOT NULL, sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL, collected_by TEXT NOT NULL, collected_at TEXT NOT NULL, notes TEXT);
        CREATE TABLE IF NOT EXISTS custody_events(id INTEGER PRIMARY KEY, evidence_id INTEGER NOT NULL, action TEXT NOT NULL, actor TEXT NOT NULL, timestamp TEXT NOT NULL, notes TEXT, FOREIGN KEY(evidence_id) REFERENCES evidence(evidence_id));
        CREATE TABLE IF NOT EXISTS tool_results(id INTEGER PRIMARY KEY, evidence_id INTEGER NOT NULL, tool_name TEXT NOT NULL, status TEXT NOT NULL, output TEXT, actor TEXT NOT NULL, timestamp TEXT NOT NULL, FOREIGN KEY(evidence_id) REFERENCES evidence(evidence_id));
        CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, details TEXT, timestamp TEXT NOT NULL);
        """)

def add_audit(actor,action,details=""):
    with conn() as c: c.execute("INSERT INTO audit_log(actor,action,details,timestamp) VALUES(?,?,?,?)",(actor,action,details,now()))
def get_audit_log():
    with conn() as c: return pd.read_sql_query("SELECT * FROM audit_log ORDER BY id DESC LIMIT 1000",c)
def add_land_record(village,owner,survey_no,actor):
    digest=hashlib.sha256(f"{village}|{owner}|{survey_no}".encode()).hexdigest()
    with conn() as c:
        cur=c.execute("INSERT INTO land_records(village,owner,survey_no,record_hash,created_at,created_by) VALUES(?,?,?,?,?,?)",(village,owner,survey_no,digest,now(),actor))
        rid=cur.lastrowid
    add_audit(actor,"LAND_RECORD_CREATED",f"Record #{rid}"); return rid,digest
def get_land_records():
    with conn() as c: return pd.read_sql_query("SELECT * FROM land_records ORDER BY id DESC",c)
def add_evidence(filename,data,case_ref,actor,notes):
    suffix=Path(filename).suffix[:20]; safe=Path(filename).name
    path=EVIDENCE_DIR/(uuid.uuid4().hex+suffix); path.write_bytes(data)
    digest=hashlib.sha256(data).hexdigest(); stamp=now()
    with conn() as c:
        cur=c.execute("INSERT INTO evidence(case_ref,filename,filepath,sha256,size_bytes,collected_by,collected_at,notes) VALUES(?,?,?,?,?,?,?,?)",
                      (case_ref,safe,str(path),digest,len(data),actor,stamp,notes))
        eid=cur.lastrowid
        c.execute("INSERT INTO custody_events(evidence_id,action,actor,timestamp,notes) VALUES(?,?,?,?,?)",(eid,"ACQUIRED",actor,stamp,notes or "File acquired; SHA-256 recorded."))
    return eid,str(path),digest
def list_evidence():
    with conn() as c: return [dict(r) for r in c.execute("SELECT * FROM evidence ORDER BY evidence_id DESC").fetchall()]
def get_evidence(eid):
    with conn() as c:
        r=c.execute("SELECT * FROM evidence WHERE evidence_id=?",(int(eid),)).fetchone()
        return dict(r) if r else None
def verify_evidence(eid):
    r=get_evidence(eid)
    if not r: return {"status":"EVIDENCE NOT FOUND"}
    p=r["filepath"]
    if not p or not os.path.isfile(p): return {"status":"FILE NOT FOUND","recorded_hash":r["sha256"],"current_hash":None}
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
    current=h.hexdigest()
    return {"status":"INTEGRITY VERIFIED" if current==r["sha256"] else "INTEGRITY MISMATCH","recorded_hash":r["sha256"],"current_hash":current}
def add_custody_event(eid,action,actor,notes=""):
    with conn() as c: c.execute("INSERT INTO custody_events(evidence_id,action,actor,timestamp,notes) VALUES(?,?,?,?,?)",(int(eid),action,actor,now(),notes))
def get_custody(eid):
    with conn() as c: return pd.read_sql_query("SELECT * FROM custody_events WHERE evidence_id=? ORDER BY id",c,params=(int(eid),))
def save_tool_result(eid,tool,status,output,actor):
    with conn() as c: c.execute("INSERT INTO tool_results(evidence_id,tool_name,status,output,actor,timestamp) VALUES(?,?,?,?,?,?)",(int(eid),tool,status,output,actor,now()))
def get_tool_results(eid):
    with conn() as c: return pd.read_sql_query("SELECT * FROM tool_results WHERE evidence_id=? ORDER BY id",c,params=(int(eid),))
