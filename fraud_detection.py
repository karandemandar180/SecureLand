
import sqlite3
from datetime import datetime
from collections import Counter

DB_NAME = "land_data.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def create_risk_table():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS fraud_risk_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id INTEGER NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            findings TEXT NOT NULL,
            checked_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def fetch_records():
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM land_records")
    records = [dict(row) for row in cur.fetchall()]

    conn.close()
    return records


def analyze_record(record, all_records):
    score = 0
    findings = []

    # Rule 1: Missing owner name
    if not str(record.get("owner_name") or "").strip():
        score += 25
        findings.append("Owner name missing")

    # Rule 2: Missing village
    if not str(record.get("village") or "").strip():
        score += 15
        findings.append("Village information missing")

    # Rule 3: Missing survey number
    if not str(record.get("survey_number") or "").strip():
        score += 20
        findings.append("Survey number missing")

    # Rule 4: Invalid area
    try:
        area = float(record.get("area"))
        if area <= 0:
            score += 30
            findings.append("Invalid land area")
    except (TypeError, ValueError):
        score += 30
        findings.append("Invalid land area")

    # Rule 5: Duplicate survey number in same village
    survey = str(record.get("survey_number") or "").strip().lower()
    village = str(record.get("village") or "").strip().lower()

    if survey and village:
        duplicate_count = sum(
            1 for other in all_records
            if other.get("id") != record.get("id")
            and str(other.get("survey_number") or "").strip().lower() == survey
            and str(other.get("village") or "").strip().lower() == village
        )

        if duplicate_count > 0:
            score += 30
            findings.append("Duplicate survey number in same village")

    # Rule 6: Unusual area compared with same village
    try:
        area = float(record.get("area"))

        village_areas = [
            float(other["area"])
            for other in all_records
            if str(other.get("village") or "").strip().lower() == village
            and other.get("area") is not None
            and other.get("id") != record.get("id")
        ]

        if len(village_areas) >= 3:
            average_area = sum(village_areas) / len(village_areas)

            if average_area > 0 and area > average_area * 5:
                score += 20
                findings.append("Unusually high area compared with village records")

    except (TypeError, ValueError):
        pass

    score = min(score, 100)

    if score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    if not findings:
        findings.append("No configured risk rules triggered")

    return {
        "risk_score": score,
        "risk_level": level,
        "findings": findings
    }


def analyze_all_records():
    create_risk_table()

    records = fetch_records()
    results = []

    conn = get_connection()
    cur = conn.cursor()

    for record in records:
        analysis = analyze_record(record, records)

        findings_text = "; ".join(analysis["findings"])

        cur.execute("""
            INSERT INTO fraud_risk_logs (
                record_id, risk_score, risk_level,
                findings, checked_at
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            record["id"],
            analysis["risk_score"],
            analysis["risk_level"],
            findings_text,
            datetime.now().isoformat(timespec="seconds")
        ))

        results.append({
            "record_id": record["id"],
            **analysis
        })

    conn.commit()
    conn.close()

    return results


def get_risk_history(record_id=None):
    create_risk_table()

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    if record_id is None:
        cur.execute("""
            SELECT * FROM fraud_risk_logs
            ORDER BY id DESC
        """)
    else:
        cur.execute("""
            SELECT * FROM fraud_risk_logs
            WHERE record_id = ?
            ORDER BY id DESC
        """, (record_id,))

    logs = [dict(row) for row in cur.fetchall()]
    conn.close()

    return logs


def get_risk_summary():
    results = analyze_all_records()

    return {
        "total_records": len(results),
        "high_risk": sum(
            1 for r in results if r["risk_level"] == "HIGH"
        ),
        "medium_risk": sum(
            1 for r in results if r["risk_level"] == "MEDIUM"
        ),
        "low_risk": sum(
            1 for r in results if r["risk_level"] == "LOW"
        )
    }
