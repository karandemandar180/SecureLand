
import sqlite3
import hashlib
import json
from datetime import datetime

DB_NAME = "land_data.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def create_integrity_table():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS integrity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id INTEGER NOT NULL,
            record_hash TEXT NOT NULL,
            verified_hash TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def calculate_sha256(record):
    """
    Record मधील माहितीचे स्थिर JSON स्वरूप तयार करून
    SHA-256 Hash निर्माण करतो.
    """

    record_data = {
        "id": record.get("id"),
        "owner_name": record.get("owner_name"),
        "village": record.get("village"),
        "taluka": record.get("taluka"),
        "district": record.get("district"),
        "survey_number": record.get("survey_number"),
        "record_type": record.get("record_type"),
        "area": record.get("area"),
        "status": record.get("status")
    }

    json_data = json.dumps(
        record_data,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":")
    )

    return hashlib.sha256(
        json_data.encode("utf-8")
    ).hexdigest()


def get_land_record(record_id):
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute(
        "SELECT * FROM land_records WHERE id = ?",
        (record_id,)
    )

    row = cur.fetchone()
    conn.close()

    return dict(row) if row else None


def generate_record_hash(record_id):
    create_integrity_table()

    record = get_land_record(record_id)

    if not record:
        return {
            "success": False,
            "message": "Land record not found"
        }

    record_hash = calculate_sha256(record)

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO integrity_logs (
            record_id, record_hash, status, created_at
        )
        VALUES (?, ?, ?, ?)
    """, (
        record_id,
        record_hash,
        "HASH_GENERATED",
        datetime.now().isoformat(timespec="seconds")
    ))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "record_id": record_id,
        "sha256": record_hash
    }


def verify_record_hash(record_id):
    create_integrity_table()

    record = get_land_record(record_id)

    if not record:
        return {
            "success": False,
            "message": "Land record not found"
        }

    current_hash = calculate_sha256(record)

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT record_hash
        FROM integrity_logs
        WHERE record_id = ?
        AND status = 'HASH_GENERATED'
        ORDER BY id DESC
        LIMIT 1
    """, (record_id,))

    row = cur.fetchone()

    if not row:
        conn.close()
        return {
            "success": False,
            "message": "Original hash not available"
        }

    original_hash = row[0]

    if original_hash == current_hash:
        status = "INTEGRITY VERIFIED"
    else:
        status = "HASH MISMATCH - REVIEW REQUIRED"

    cur.execute("""
        INSERT INTO integrity_logs (
            record_id, record_hash, verified_hash,
            status, created_at
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        record_id,
        original_hash,
        current_hash,
        status,
        datetime.now().isoformat(timespec="seconds")
    ))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "record_id": record_id,
        "original_hash": original_hash,
        "current_hash": current_hash,
        "status": status
    }


def get_integrity_history(record_id):
    create_integrity_table()

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM integrity_logs
        WHERE record_id = ?
        ORDER BY id DESC
    """, (record_id,))

    logs = [dict(row) for row in cur.fetchall()]
    conn.close()

    return logs
