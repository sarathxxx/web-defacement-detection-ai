"""
URLGuard Database Module
SQLite-based storage for users, scan logs, and URL submissions.
"""

import sqlite3
import hashlib
import secrets
import os
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / 'urlguard.db'


def get_db():
    """Get a database connection."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create all tables and seed default admin."""
    conn = get_db()
    cur = conn.cursor()

    # ── Users table ──────────────────────────────────────────────────────────
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE NOT NULL,
            email       TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            role        TEXT NOT NULL DEFAULT 'user',
            is_active   INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT NOT NULL,
            last_login  TEXT
        )
    ''')

    # ── Scan logs table ───────────────────────────────────────────────────────
    cur.execute('''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id          INTEGER,
            url              TEXT NOT NULL,
            hostname         TEXT,
            predicted_class  TEXT NOT NULL,
            confidence       REAL NOT NULL,
            risk_score       INTEGER NOT NULL,
            rule_used        TEXT,
            scan_time_ms     REAL,
            features_json    TEXT,
            ip_address       TEXT,
            scanned_at       TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    # ── URL submissions table (for dataset) ───────────────────────────────────
    cur.execute('''
        CREATE TABLE IF NOT EXISTS url_submissions (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            url           TEXT NOT NULL,
            submitted_by  INTEGER,
            suggested_label TEXT,
            admin_label   TEXT,
            status        TEXT NOT NULL DEFAULT 'pending',
            notes         TEXT,
            submitted_at  TEXT NOT NULL,
            reviewed_at   TEXT,
            reviewed_by   INTEGER,
            FOREIGN KEY (submitted_by) REFERENCES users(id),
            FOREIGN KEY (reviewed_by)  REFERENCES users(id)
        )
    ''')

    # ── Session tokens table ──────────────────────────────────────────────────
    cur.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            token       TEXT PRIMARY KEY,
            user_id     INTEGER NOT NULL,
            created_at  TEXT NOT NULL,
            expires_at  TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    conn.commit()

    # Seed default admin if not exists
    existing = cur.execute("SELECT id FROM users WHERE role='admin'").fetchone()
    if not existing:
        admin_pw = hash_password('admin123')
        cur.execute('''
            INSERT INTO users (username, email, password, role, created_at)
            VALUES (?, ?, ?, ?, ?)
        ''', ('admin', 'admin@urlguard.local', admin_pw, 'admin',
              datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
        print("✓ Default admin created  →  admin / admin123")

    conn.close()


# ── Password hashing ──────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    """Hash password with SHA-256 + salt."""
    salt = 'urlguard_salt_2024'
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()


def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed


# ── User operations ───────────────────────────────────────────────────────────
def create_user(username: str, email: str, password: str, role: str = 'user') -> dict:
    conn = get_db()
    try:
        conn.execute('''
            INSERT INTO users (username, email, password, role, created_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (username.strip(), email.strip().lower(),
              hash_password(password), role,
              datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
        return {'success': True}
    except sqlite3.IntegrityError as e:
        if 'username' in str(e):
            return {'error': 'Username already taken'}
        if 'email' in str(e):
            return {'error': 'Email already registered'}
        return {'error': str(e)}
    finally:
        conn.close()


def get_user_by_username(username: str) -> dict | None:
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM users WHERE username=? AND is_active=1", (username,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> dict | None:
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_last_login(user_id: int):
    conn = get_db()
    conn.execute("UPDATE users SET last_login=? WHERE id=?",
                 (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_id))
    conn.commit()
    conn.close()


# ── Session operations ────────────────────────────────────────────────────────
def create_session(user_id: int) -> str:
    token = secrets.token_hex(32)
    from datetime import timedelta
    expires = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db()
    conn.execute('''
        INSERT INTO sessions (token, user_id, created_at, expires_at)
        VALUES (?, ?, ?, ?)
    ''', (token, user_id, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), expires))
    conn.commit()
    conn.close()
    return token


def get_session_user(token: str) -> dict | None:
    if not token:
        return None
    conn = get_db()
    row = conn.execute('''
        SELECT u.* FROM users u
        JOIN sessions s ON s.user_id = u.id
        WHERE s.token=? AND s.expires_at > ?
    ''', (token, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))).fetchone()
    conn.close()
    return dict(row) if row else None


def delete_session(token: str):
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE token=?", (token,))
    conn.commit()
    conn.close()


# ── Scan log operations ───────────────────────────────────────────────────────
def log_scan(user_id, result: dict, ip_address: str = None):
    import json
    conn = get_db()
    conn.execute('''
        INSERT INTO scan_logs
            (user_id, url, hostname, predicted_class, confidence,
             risk_score, rule_used, scan_time_ms, features_json, ip_address, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        user_id,
        result.get('url', ''),
        result.get('hostname', ''),
        result.get('predicted_class', ''),
        result.get('confidence', 0),
        result.get('risk_score', 0),
        result.get('rule_used', ''),
        result.get('scan_time_ms', 0),
        json.dumps(result.get('features', {})),
        ip_address,
        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    ))
    conn.commit()
    conn.close()


# ── URL submission operations ─────────────────────────────────────────────────
def submit_url(url: str, user_id: int, suggested_label: str = None, notes: str = None):
    conn = get_db()
    try:
        conn.execute('''
            INSERT INTO url_submissions
                (url, submitted_by, suggested_label, notes, submitted_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (url.strip(), user_id, suggested_label, notes,
              datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
        return {'success': True}
    except Exception as e:
        return {'error': str(e)}
    finally:
        conn.close()


def review_submission(submission_id: int, admin_label: str,
                      status: str, admin_id: int):
    conn = get_db()
    conn.execute('''
        UPDATE url_submissions
        SET admin_label=?, status=?, reviewed_at=?, reviewed_by=?
        WHERE id=?
    ''', (admin_label, status,
          datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
          admin_id, submission_id))
    conn.commit()
    conn.close()


# ── Admin dashboard data ───────────────────────────────────────────────────────
def get_admin_stats() -> dict:
    conn = get_db()
    stats = {}

    stats['total_users']   = conn.execute("SELECT COUNT(*) FROM users WHERE role='user'").fetchone()[0]
    stats['total_scans']   = conn.execute("SELECT COUNT(*) FROM scan_logs").fetchone()[0]
    stats['total_threats'] = conn.execute(
        "SELECT COUNT(*) FROM scan_logs WHERE predicted_class != 'benign'"
    ).fetchone()[0]
    stats['pending_submissions'] = conn.execute(
        "SELECT COUNT(*) FROM url_submissions WHERE status='pending'"
    ).fetchone()[0]
    stats['total_submissions'] = conn.execute(
        "SELECT COUNT(*) FROM url_submissions"
    ).fetchone()[0]

    # Threat breakdown
    for cls in ['phishing', 'defacement', 'malware']:
        count = conn.execute(
            "SELECT COUNT(*) FROM scan_logs WHERE predicted_class=?", (cls,)
        ).fetchone()[0]
        stats[f'{cls}_count'] = count

    # Scans per day (last 7 days)
    rows = conn.execute('''
        SELECT DATE(scanned_at) as day, COUNT(*) as cnt
        FROM scan_logs
        WHERE scanned_at >= DATE('now', '-7 days')
        GROUP BY day ORDER BY day
    ''').fetchall()
    stats['scans_per_day'] = [dict(r) for r in rows]

    # Top scanned hostnames
    rows = conn.execute('''
        SELECT hostname, COUNT(*) as cnt, predicted_class
        FROM scan_logs
        WHERE hostname != ''
        GROUP BY hostname
        ORDER BY cnt DESC LIMIT 10
    ''').fetchall()
    stats['top_hostnames'] = [dict(r) for r in rows]

    conn.close()
    return stats


def get_all_users() -> list:
    conn = get_db()
    rows = conn.execute('''
        SELECT u.*, COUNT(sl.id) as scan_count
        FROM users u
        LEFT JOIN scan_logs sl ON sl.user_id = u.id
        GROUP BY u.id
        ORDER BY u.created_at DESC
    ''').fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scan_logs(limit: int = 100, user_id: int = None) -> list:
    conn = get_db()
    if user_id:
        rows = conn.execute('''
            SELECT sl.*, u.username FROM scan_logs sl
            LEFT JOIN users u ON u.id = sl.user_id
            WHERE sl.user_id=?
            ORDER BY sl.scanned_at DESC LIMIT ?
        ''', (user_id, limit)).fetchall()
    else:
        rows = conn.execute('''
            SELECT sl.*, u.username FROM scan_logs sl
            LEFT JOIN users u ON u.id = sl.user_id
            ORDER BY sl.scanned_at DESC LIMIT ?
        ''', (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_url_submissions(status: str = None) -> list:
    conn = get_db()
    if status:
        rows = conn.execute('''
            SELECT us.*, u.username as submitter_name
            FROM url_submissions us
            LEFT JOIN users u ON u.id = us.submitted_by
            WHERE us.status=?
            ORDER BY us.submitted_at DESC
        ''', (status,)).fetchall()
    else:
        rows = conn.execute('''
            SELECT us.*, u.username as submitter_name
            FROM url_submissions us
            LEFT JOIN users u ON u.id = us.submitted_by
            ORDER BY us.submitted_at DESC
        ''').fetchall()
    conn.close()
    return [dict(r) for r in rows]


def export_approved_urls() -> list:
    """Export approved URLs for retraining dataset."""
    conn = get_db()
    rows = conn.execute('''
        SELECT url, admin_label, reviewed_at
        FROM url_submissions
        WHERE status='approved' AND admin_label IS NOT NULL
        ORDER BY reviewed_at DESC
    ''').fetchall()
    conn.close()
    return [dict(r) for r in rows]


if __name__ == '__main__':
    init_db()
    print(f"Database initialised at: {DB_PATH}")
