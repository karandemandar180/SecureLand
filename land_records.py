
import sqlite3
from datetime import datetime

DB_NAME = "land_data.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def create_land_table():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS land_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_name TEXT NOT NULL,
            village TEXT NOT NULL,
            taluka TEXT,
            district TEXT,
            survey_number TEXT NOT NULL,
            record_type TEXT,
            area REAL NOT NULL,
            status TEXT DEFAULT 'Active',
            created_at TEXT
        )
    """)

    conn.commit()
    conn.close()


def add_land_record(
    owner_name,
    village,
    taluka,
    district,
    survey_number,
    record_type,
    area
):
    create_land_table()

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO land_records (
            owner_name, village, taluka, district,
            survey_number, record_type, area,
            status, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        owner_name,
        village,
        taluka,
        district,
        survey_number,
        record_type,
        area,
        "Active",
        datetime.now().isoformat(timespec="seconds")
    ))

    conn.commit()
    conn.close()


def get_all_land_records():
    create_land_table()

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM land_records ORDER BY id DESC")
    records = [dict(row) for row in cur.fetchall()]

    conn.close()
    return records


def search_land_records(keyword):
    create_land_table()

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    search = f"%{keyword}%"

    cur.execute("""
        SELECT * FROM land_records
        WHERE owner_name LIKE ?
        OR village LIKE ?
        OR survey_number LIKE ?
        OR taluka LIKE ?
        OR district LIKE ?
        ORDER BY id DESC
    """, (search, search, search, search, search))

    records = [dict(row) for row in cur.fetchall()]
    conn.close()

    return records


def update_land_record(record_id, owner_name, area, status):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE land_records
        SET owner_name = ?, area = ?, status = ?
        WHERE id = ?
    """, (owner_name, area, status, record_id))

    conn.commit()
    conn.close()


def delete_land_record(record_id):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "DELETE FROM land_records WHERE id = ?",
        (record_id,)
    )

    conn.commit()
    conn.close()
