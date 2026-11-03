
import hashlib
import os
import sqlite3
import uuid
import json

from pathlib import Path
from datetime import datetime, timezone

import pandas as pd


# =====================================================
# 1. PROJECT CONFIGURATION
# =====================================================

BASE = Path(__file__).resolve().parent

DB = BASE / "secureland.db"

EVIDENCE_DIR = BASE / "evidence"

EVIDENCE_DIR.mkdir(exist_ok=True)


# =====================================================
# 2. COMMON FUNCTIONS
# =====================================================

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db_path():
    return str(DB)


def conn():
    c = sqlite3.connect(DB, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c


def calculate_hash(data):
    if isinstance(data, str):
        data = data.encode("utf-8")

    return hashlib.sha256(data).hexdigest()


# =====================================================
# 3. DATABASE INITIALIZATION
# =====================================================

def init_db():

    with conn() as c:

        c.executescript("""

        CREATE TABLE IF NOT EXISTS land_records (
            id INTEGER PRIMARY KEY,
            village TEXT NOT NULL,
            owner TEXT NOT NULL,
            survey_no TEXT NOT NULL,
            record_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL
        );


        CREATE TABLE IF NOT EXISTS evidence (
            evidence_id INTEGER PRIMARY KEY,
            case_ref TEXT,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            collected_by TEXT NOT NULL,
            collected_at TEXT NOT NULL,
            notes TEXT
        );


        CREATE TABLE IF NOT EXISTS custody_events (
            id INTEGER PRIMARY KEY,
            evidence_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            notes TEXT,
            FOREIGN KEY(evidence_id)
                REFERENCES evidence(evidence_id)
        );


        CREATE TABLE IF NOT EXISTS tool_results (
            id INTEGER PRIMARY KEY,
            evidence_id INTEGER NOT NULL,
            tool_name TEXT NOT NULL,
            status TEXT NOT NULL,
            output TEXT,
            actor TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY(evidence_id)
                REFERENCES evidence(evidence_id)
        );


        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            timestamp TEXT NOT NULL
        );


        -- INTEGRITY VERIFICATION

        CREATE TABLE IF NOT EXISTS integrity_logs (
            id INTEGER PRIMARY KEY,
            record_id INTEGER NOT NULL,
            record_hash TEXT NOT NULL,
            verified_hash TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(record_id)
                REFERENCES land_records(id)
        );


        -- FRAUD RISK DETECTION

        CREATE TABLE IF NOT EXISTS fraud_risk_logs (
            id INTEGER PRIMARY KEY,
            record_id INTEGER NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            findings TEXT,
            analyzed_at TEXT NOT NULL,
            FOREIGN KEY(record_id)
                REFERENCES land_records(id)
        );


        -- HASH LINKED LEDGER

        CREATE TABLE IF NOT EXISTS blockchain_ledger (
            id INTEGER PRIMARY KEY,
            record_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            data_hash TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            FOREIGN KEY(record_id)
                REFERENCES land_records(id)
        );

        """)


# =====================================================
# 4. AUDIT LOG MODULE
# =====================================================

def add_audit(actor, action, details=""):

    with conn() as c:

        c.execute(
            """
            INSERT INTO audit_log
            (actor, action, details, timestamp)
            VALUES (?, ?, ?, ?)
            """,
            (actor, action, details, now())
        )


def get_audit_log():

    with conn() as c:

        return pd.read_sql_query(
            """
            SELECT * FROM audit_log
            ORDER BY id DESC
            LIMIT 1000
            """,
            c
        )


# =====================================================
# 5. LAND RECORD MODULE
# =====================================================

def add_land_record(village, owner, survey_no, actor):

    digest = calculate_hash(
        f"{village}|{owner}|{survey_no}"
    )

    with conn() as c:

        cur = c.execute(
            """
            INSERT INTO land_records
            (village, owner, survey_no, record_hash,
             created_at, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                village,
                owner,
                survey_no,
                digest,
                now(),
                actor
            )
        )

        rid = cur.lastrowid

    add_audit(
        actor,
        "LAND_RECORD_CREATED",
        f"Record #{rid}"
    )

    return rid, digest


def get_land_records():

    with conn() as c:

        return pd.read_sql_query(
            """
            SELECT * FROM land_records
            ORDER BY id DESC
            """,
            c
        )


def get_land_record(record_id):

    with conn() as c:

        r = c.execute(
            """
            SELECT * FROM land_records
            WHERE id = ?
            """,
            (int(record_id),)
        ).fetchone()

        return dict(r) if r else None


# =====================================================
# 6. DIGITAL EVIDENCE MODULE
# =====================================================

def add_evidence(filename, data, case_ref, actor, notes):

    suffix = Path(filename).suffix[:20]

    safe = Path(filename).name

    path = EVIDENCE_DIR / (
        uuid.uuid4().hex + suffix
    )

    path.write_bytes(data)

    digest = hashlib.sha256(data).hexdigest()

    stamp = now()

    with conn() as c:

        cur = c.execute(
            """
            INSERT INTO evidence
            (case_ref, filename, filepath, sha256,
             size_bytes, collected_by, collected_at, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_ref,
                safe,
                str(path),
                digest,
                len(data),
                actor,
                stamp,
                notes
            )
        )

        eid = cur.lastrowid

        c.execute(
            """
            INSERT INTO custody_events
            (evidence_id, action, actor, timestamp, notes)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                eid,
                "ACQUIRED",
                actor,
                stamp,
                notes or "File acquired; SHA-256 recorded."
            )
        )

    add_audit(
        actor,
        "EVIDENCE_REGISTERED",
        f"Evidence #{eid}"
    )

    return eid, str(path), digest


def list_evidence():

    with conn() as c:

        return [
            dict(r)
            for r in c.execute(
                """
                SELECT * FROM evidence
                ORDER BY evidence_id DESC
                """
            ).fetchall()
        ]


def get_evidence(eid):

    with conn() as c:

        r = c.execute(
            """
            SELECT * FROM evidence
            WHERE evidence_id = ?
            """,
            (int(eid),)
        ).fetchone()

        return dict(r) if r else None


def verify_evidence(eid):

    r = get_evidence(eid)

    if not r:

        return {
            "status": "EVIDENCE NOT FOUND"
        }

    p = r["filepath"]

    if not p or not os.path.isfile(p):

        return {
            "status": "FILE NOT FOUND",
            "recorded_hash": r["sha256"],
            "current_hash": None
        }

    h = hashlib.sha256()

    with open(p, "rb") as f:

        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b""
        ):
            h.update(chunk)

    current = h.hexdigest()

    status = (
        "INTEGRITY VERIFIED"
        if current == r["sha256"]
        else "INTEGRITY MISMATCH"
    )

    return {
        "status": status,
        "recorded_hash": r["sha256"],
        "current_hash": current
    }


# =====================================================
# 7. CHAIN OF CUSTODY MODULE
# =====================================================

def add_custody_event(eid, action, actor, notes=""):

    with conn() as c:

        c.execute(
            """
            INSERT INTO custody_events
            (evidence_id, action, actor, timestamp, notes)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                int(eid),
                action,
                actor,
                now(),
                notes
            )
        )

    add_audit(
        actor,
        "CUSTODY_EVENT_ADDED",
        f"Evidence #{eid}: {action}"
    )


def get_custody(eid):

    with conn() as c:

        return pd.read_sql_query(
            """
            SELECT * FROM custody_events
            WHERE evidence_id = ?
            ORDER BY id
            """,
            c,
            params=(int(eid),)
        )


# =====================================================
# 8. FORENSIC TOOL RESULTS
# =====================================================

def save_tool_result(
    eid,
    tool,
    status,
    output,
    actor
):

    with conn() as c:

        c.execute(
            """
            INSERT INTO tool_results
            (evidence_id, tool_name, status,
             output, actor, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                int(eid),
                tool,
                status,
                output,
                actor,
                now()
            )
        )

    add_audit(
        actor,
        "FORENSIC_TOOL_EXECUTED",
        f"Evidence #{eid}: {tool} - {status}"
    )


def get_tool_results(eid):

    with conn() as c:

        return pd.read_sql_query(
            """
            SELECT * FROM tool_results
            WHERE evidence_id = ?
            ORDER BY id
            """,
            c,
            params=(int(eid),)
        )


# =====================================================
# 9. INTEGRITY LOG MODULE
# =====================================================

def generate_record_hash(record_id):

    record = get_land_record(record_id)

    if not record:
        return None

    payload = (
        f"{record['village']}|"
        f"{record['owner']}|"
        f"{record['survey_no']}"
    )

    return calculate_hash(payload)


def verify_land_record_integrity(record_id):

    record = get_land_record(record_id)

    if not record:
        return {"status": "RECORD NOT FOUND"}

    original_hash = record["record_hash"]

    current_hash = generate_record_hash(record_id)

    status = (
        "INTEGRITY VERIFIED"
        if original_hash == current_hash
        else "INTEGRITY MISMATCH"
    )

    with conn() as c:

        c.execute(
            """
            INSERT INTO integrity_logs
            (record_id, record_hash, verified_hash,
             status, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                int(record_id),
                original_hash,
                current_hash,
                status,
                now()
            )
        )

    return {
        "record_id": record_id,
        "recorded_hash": original_hash,
        "verified_hash": current_hash,
        "status": status
    }


def get_integrity_history(record_id):

    with conn() as c:

        return pd.read_sql_query(
            """
            SELECT * FROM integrity_logs
            WHERE record_id = ?
            ORDER BY id DESC
            """,
            c,
            params=(int(record_id),)
        )


# =====================================================
# 10. FRAUD RISK DETECTION MODULE
# Rule-based prototype, not trained AI
# =====================================================

def analyze_land_record(record_id):

    record = get_land_record(record_id)

    if not record:
        return {"status": "RECORD NOT FOUND"}

    score = 0
    findings = []

    if not record["owner"].strip():

        score += 30
        findings.append("Owner name missing")

    if not record["village"].strip():

        score += 30
        findings.append("Village missing")

    if not record["survey_no"].strip():

        score += 30
        findings.append("Survey number missing")

    with conn() as c:

        duplicate = c.execute(
            """
            SELECT COUNT(*) FROM land_records
            WHERE village = ?
            AND survey_no = ?
            AND id != ?
            """,
            (
                record["village"],
                record["survey_no"],
                int(record_id)
            )
        ).fetchone()[0]

    if duplicate > 0:

        score += 40
        findings.append(
            "Duplicate survey number in same village"
        )

    score = min(score, 100)

    if score >= 60:
        level = "HIGH"

    elif score >= 30:
        level = "MEDIUM"

    else:
        level = "LOW"

    with conn() as c:

        c.execute(
            """
            INSERT INTO fraud_risk_logs
            (record_id, risk_score, risk_level,
             findings, analyzed_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                int(record_id),
                score,
                level,
                json.dumps(findings),
                now()
            )
        )

    add_audit(
        "SYSTEM",
        "FRAUD_RISK_ANALYSIS",
        f"Record #{record_id}: {level}"
    )

    return {
        "record_id": record_id,
        "risk_score": score,
        "risk_level": level,
        "findings": findings
    }


def get_risk_history(record_id):

    with conn() as c:

        return pd.read_sql_query(
            """
            SELECT * FROM fraud_risk_logs
            WHERE record_id = ?
            ORDER BY id DESC
            """,
            c,
            params=(int(record_id),)
        )


def get_risk_summary():

    with conn() as c:

        return pd.read_sql_query(
            """
            SELECT risk_level, COUNT(*) AS total
            FROM fraud_risk_logs
            GROUP BY risk_level
            """,
            c
        )


# =====================================================
# 11. HASH-LINKED LEDGER
# Local prototype, not distributed blockchain
# =====================================================

def add_ledger_entry(record_id, action, actor):

    record = get_land_record(record_id)

    if not record:
        return {"status": "RECORD NOT FOUND"}

    data_hash = generate_record_hash(record_id)

    with conn() as c:

        previous = c.execute(
            """
            SELECT entry_hash FROM blockchain_ledger
            ORDER BY id DESC LIMIT 1
            """
        ).fetchone()

        previous_hash = (
            previous["entry_hash"]
            if previous
            else "GENESIS"
        )

        timestamp = now()

        payload = (
            f"{record_id}|{action}|{data_hash}|"
            f"{previous_hash}|{timestamp}|{actor}"
        )

        entry_hash = calculate_hash(payload)

        c.execute(
            """
            INSERT INTO blockchain_ledger
            (record_id, action, data_hash,
             previous_hash, entry_hash,
             created_at, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(record_id),
                action,
                data_hash,
                previous_hash,
                entry_hash,
                timestamp,
                actor
            )
        )

    add_audit(
        actor,
        "LEDGER_ENTRY_CREATED",
        f"Record #{record_id}"
    )

    return {
        "status": "LEDGER ENTRY CREATED",
        "entry_hash": entry_hash
    }


def get_ledger_history():

    with conn() as c:

        return pd.read_sql_query(
            """
            SELECT * FROM blockchain_ledger
            ORDER BY id
            """,
            c
        )


def verify_ledger():

    entries = get_ledger_history()

    previous_hash = "GENESIS"

    for _, row in entries.iterrows():

        if row["previous_hash"] != previous_hash:

            return {
                "status": "LEDGER CHAIN MISMATCH",
                "entry_id": int(row["id"])
            }

        payload = (
            f"{row['record_id']}|"
            f"{row['action']}|"
            f"{row['data_hash']}|"
            f"{row['previous_hash']}|"
            f"{row['created_at']}|"
            f"{row['created_by']}"
        )

        expected_hash = calculate_hash(payload)

        if expected_hash != row["entry_hash"]:

            return {
                "status": "ENTRY HASH MISMATCH",
                "entry_id": int(row["id"])
            }

        previous_hash = row["entry_hash"]

    return {
        "status": "LEDGER VERIFIED",
        "total_entries": len(entries)
    }


# =====================================================
# 12. GOVERNMENT-STYLE DASHBOARD SUMMARY
# =====================================================

def get_dashboard_summary():

    with conn() as c:

        def count(table):

            return c.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]

        return {
            "total_land_records": count("land_records"),
            "total_evidence": count("evidence"),
            "total_custody_events": count("custody_events"),
            "total_tool_results": count("tool_results"),
            "total_audit_logs": count("audit_log"),
            "total_integrity_checks": count("integrity_logs"),
            "total_risk_analyses": count("fraud_risk_logs"),
            "total_ledger_entries": count("blockchain_ledger")
        }


# =====================================================
# 13. CSV EXPORT
# =====================================================

def export_land_records_csv():

    with conn() as c:

        return pd.read_sql_query(
            "SELECT * FROM land_records ORDER BY id DESC",
            c
        )


def export_evidence_csv():

    with conn() as c:

        return pd.read_sql_query(
            """
            SELECT evidence_id, case_ref, filename,
            sha256, size_bytes, collected_by,
            collected_at, notes
            FROM evidence
            ORDER BY evidence_id DESC
            """,
            c
        )
