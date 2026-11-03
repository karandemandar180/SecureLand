
import sqlite3
import hashlib
import os
import shutil
import uuid
import json
from datetime import datetime, timezone

DB_NAME = "land_data.db"
EVIDENCE_DIR = "secureland_evidence"


def get_connection():
    return sqlite3.connect(DB_NAME)


def create_forensics_tables():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS digital_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id TEXT UNIQUE NOT NULL,
            record_id INTEGER,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            sha256_hash TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            uploaded_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS chain_of_custody (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id TEXT NOT NULL,
            action TEXT NOT NULL,
            handled_by TEXT NOT NULL,
            remarks TEXT,
            event_time TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def calculate_file_hash(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def register_evidence(
    source_path,
    record_id=None,
    uploaded_by="System",
    remarks="Evidence registered"
):
    create_forensics_tables()

    if not os.path.isfile(source_path):
        raise FileNotFoundError("Evidence file not found")

    original_filename = os.path.basename(source_path)

    evidence_id = str(uuid.uuid4())

    extension = os.path.splitext(original_filename)[1]
    stored_filename = evidence_id + extension

    destination = os.path.join(
        EVIDENCE_DIR,
        stored_filename
    )

    shutil.copy2(source_path, destination)

    file_hash = calculate_file_hash(destination)
    file_size = os.path.getsize(destination)

    conn = get_connection()
    cur = conn.cursor()

    created_at = datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds")

    cur.execute("""
        INSERT INTO digital_evidence (
            evidence_id, record_id, original_filename,
            stored_filename, file_path, sha256_hash,
            file_size, uploaded_by, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        evidence_id,
        record_id,
        original_filename,
        stored_filename,
        destination,
        file_hash,
        file_size,
        uploaded_by,
        created_at
    ))

    cur.execute("""
        INSERT INTO chain_of_custody (
            evidence_id, action, handled_by,
            remarks, event_time
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        evidence_id,
        "EVIDENCE_REGISTERED",
        uploaded_by,
        remarks,
        created_at
    ))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "evidence_id": evidence_id,
        "filename": original_filename,
        "sha256": file_hash,
        "file_size": file_size
    }


def verify_evidence(evidence_id):
    create_forensics_tables()

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM digital_evidence
        WHERE evidence_id = ?
    """, (evidence_id,))

    evidence = cur.fetchone()
    conn.close()

    if not evidence:
        return {
            "success": False,
            "message": "Evidence not found"
        }

    evidence = dict(evidence)

    if not os.path.isfile(evidence["file_path"]):
        return {
            "success": False,
            "message": "Evidence file missing"
        }

    current_hash = calculate_file_hash(
        evidence["file_path"]
    )

    original_hash = evidence["sha256_hash"]

    return {
        "success": True,
        "evidence_id": evidence_id,
        "original_hash": original_hash,
        "current_hash": current_hash,
        "integrity_verified": original_hash == current_hash,
        "status": (
            "INTEGRITY VERIFIED"
            if original_hash == current_hash
            else "HASH MISMATCH - REVIEW REQUIRED"
        )
    }


def add_custody_event(
    evidence_id,
    action,
    handled_by,
    remarks=""
):
    create_forensics_tables()

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id FROM digital_evidence
        WHERE evidence_id = ?
    """, (evidence_id,))

    if not cur.fetchone():
        conn.close()
        raise ValueError("Evidence ID not found")

    event_time = datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds")

    cur.execute("""
        INSERT INTO chain_of_custody (
            evidence_id, action, handled_by,
            remarks, event_time
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        evidence_id,
        action,
        handled_by,
        remarks,
        event_time
    ))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "evidence_id": evidence_id,
        "action": action,
        "event_time": event_time
    }


def get_evidence_register():
    create_forensics_tables()

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM digital_evidence
        ORDER BY id DESC
    """)

    records = [dict(row) for row in cur.fetchall()]
    conn.close()

    return records


def get_chain_of_custody(evidence_id):
    create_forensics_tables()

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM chain_of_custody
        WHERE evidence_id = ?
        ORDER BY id ASC
    """, (evidence_id,))

    records = [dict(row) for row in cur.fetchall()]
    conn.close()

    return records


def get_tool_status():
    return {
        "ExifTool": shutil.which("exiftool") or "NOT INSTALLED",
        "TShark": shutil.which("tshark") or "NOT INSTALLED"
    }


def export_evidence_report(evidence_id):
    evidence = next(
        (
            item for item in get_evidence_register()
            if item["evidence_id"] == evidence_id
        ),
        None
    )

    if not evidence:
        raise ValueError("Evidence not found")

    report = {
        "evidence": evidence,
        "integrity": verify_evidence(evidence_id),
        "chain_of_custody": get_chain_of_custody(evidence_id),
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(timespec="seconds")
    }

    filename = f"{evidence_id}_forensic_report.json"

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )

    return filename
