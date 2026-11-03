
import sqlite3
import hashlib
import json
from datetime import datetime, timezone

DB_NAME = "land_data.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def create_ledger_table():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS blockchain_ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            current_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def calculate_hash(data):
    json_data = json.dumps(
        data,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":")
    )

    return hashlib.sha256(
        json_data.encode("utf-8")
    ).hexdigest()


def get_last_hash(cur):
    cur.execute("""
        SELECT current_hash
        FROM blockchain_ledger
        ORDER BY id DESC
        LIMIT 1
    """)

    row = cur.fetchone()

    if row:
        return row[0]

    return "GENESIS_BLOCK"


def add_ledger_entry(record_id, action, details):
    create_ledger_table()

    conn = get_connection()
    cur = conn.cursor()

    previous_hash = get_last_hash(cur)

    created_at = datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds")

    entry = {
        "record_id": record_id,
        "action": action,
        "details": details,
        "previous_hash": previous_hash,
        "created_at": created_at
    }

    current_hash = calculate_hash(entry)

    cur.execute("""
        INSERT INTO blockchain_ledger (
            record_id, action, details,
            previous_hash, current_hash, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        record_id,
        action,
        details,
        previous_hash,
        current_hash,
        created_at
    ))

    conn.commit()
    entry_id = cur.lastrowid
    conn.close()

    return {
        "success": True,
        "ledger_id": entry_id,
        "previous_hash": previous_hash,
        "current_hash": current_hash
    }


def get_ledger_records():
    create_ledger_table()

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM blockchain_ledger
        ORDER BY id ASC
    """)

    records = [dict(row) for row in cur.fetchall()]
    conn.close()

    return records


def verify_ledger():
    records = get_ledger_records()

    previous_hash = "GENESIS_BLOCK"

    for record in records:
        entry = {
            "record_id": record["record_id"],
            "action": record["action"],
            "details": record["details"],
            "previous_hash": record["previous_hash"],
            "created_at": record["created_at"]
        }

        expected_hash = calculate_hash(entry)

        if record["previous_hash"] != previous_hash:
            return {
                "valid": False,
                "failed_ledger_id": record["id"],
                "message": "Previous hash mismatch"
            }

        if record["current_hash"] != expected_hash:
            return {
                "valid": False,
                "failed_ledger_id": record["id"],
                "message": "Current hash mismatch"
            }

        previous_hash = record["current_hash"]

    return {
        "valid": True,
        "total_entries": len(records),
        "message": "Ledger integrity verified"
    }


def get_record_history(record_id):
    create_ledger_table()

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM blockchain_ledger
        WHERE record_id = ?
        ORDER BY id ASC
    """, (record_id,))

    records = [dict(row) for row in cur.fetchall()]
    conn.close()

    return records
