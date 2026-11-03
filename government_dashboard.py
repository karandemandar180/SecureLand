
import sqlite3
import csv
import json
import os
from datetime import datetime


DB_NAME = "land_data.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def get_count(table_name):
    allowed_tables = {
        "land_records",
        "integrity_logs",
        "fraud_risk_logs",
        "blockchain_ledger",
        "digital_evidence",
        "chain_of_custody"
    }

    if table_name not in allowed_tables:
        raise ValueError("Invalid table name")

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(f"SELECT COUNT(*) FROM {table_name}")
        count = cur.fetchone()[0]
    except sqlite3.OperationalError:
        count = 0

    conn.close()
    return count


def get_dashboard_summary():
    return {
        "total_land_records": get_count("land_records"),
        "integrity_checks": get_count("integrity_logs"),
        "fraud_alerts": get_count("fraud_risk_logs"),
        "ledger_entries": get_count("blockchain_ledger"),
        "digital_evidence": get_count("digital_evidence"),
        "custody_events": get_count("chain_of_custody")
    }


def get_high_risk_records():
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT r.id, r.owner_name, r.village,
                   r.survey_number, f.risk_score,
                   f.risk_level, f.findings, f.checked_at
            FROM fraud_risk_logs f
            JOIN land_records r ON r.id = f.record_id
            WHERE f.risk_level IN ('HIGH', 'MEDIUM')
            AND f.id IN (
                SELECT MAX(id)
                FROM fraud_risk_logs
                GROUP BY record_id
            )
            ORDER BY f.risk_score DESC
        """)

        records = [dict(row) for row in cur.fetchall()]

    except sqlite3.OperationalError:
        records = []

    conn.close()
    return records


def get_latest_audit_logs(limit=50):
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT * FROM blockchain_ledger
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))

        logs = [dict(row) for row in cur.fetchall()]

    except sqlite3.OperationalError:
        logs = []

    conn.close()
    return logs


def get_evidence_summary():
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT evidence_id, original_filename,
                   sha256_hash, uploaded_by, created_at
            FROM digital_evidence
            ORDER BY id DESC
        """)

        records = [dict(row) for row in cur.fetchall()]

    except sqlite3.OperationalError:
        records = []

    conn.close()
    return records


def export_dashboard_json():
    report = {
        "project": "SecureLand",
        "generated_at": datetime.now().isoformat(
            timespec="seconds"
        ),
        "summary": get_dashboard_summary(),
        "risk_records": get_high_risk_records(),
        "audit_logs": get_latest_audit_logs(),
        "evidence": get_evidence_summary()
    }

    filename = "secureland_government_report.json"

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )

    return filename


def export_risk_csv():
    records = get_high_risk_records()

    filename = "secureland_risk_report.csv"

    fields = [
        "id",
        "owner_name",
        "village",
        "survey_number",
        "risk_score",
        "risk_level",
        "findings",
        "checked_at"
    ]

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fields,
            extrasaction="ignore"
        )

        writer.writeheader()
        writer.writerows(records)

    return filename


def get_database_status():
    return {
        "database_exists": os.path.isfile(DB_NAME),
        "database_name": DB_NAME,
        "database_size_bytes": (
            os.path.getsize(DB_NAME)
            if os.path.isfile(DB_NAME)
            else 0
        )
    }
