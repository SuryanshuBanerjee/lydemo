import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "leblanc.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist, and migrate existing schema."""
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prompt_id TEXT,
            prompt_text TEXT,
            enriched_prompt TEXT,
            matched_cwes TEXT,
            matched_keywords TEXT,
            keyword_cwe_pairs TEXT,
            model TEXT,
            mode TEXT,
            generated_code TEXT,
            clean_code TEXT,
            scan_results TEXT,
            vuln_count INTEGER,
            repair_result TEXT,
            final_status TEXT,
            total_iterations INTEGER,
            timestamp TEXT
        )
    """)
    # Migrate existing databases that predate these columns
    for col, col_type in [("matched_keywords", "TEXT"), ("keyword_cwe_pairs", "TEXT")]:
        try:
            conn.execute(f"ALTER TABLE runs ADD COLUMN {col} {col_type}")
        except sqlite3.OperationalError:
            pass  # Column already exists
    conn.commit()
    conn.close()


def save_run(data):
    """Save a pipeline run to the database."""
    conn = get_db()
    conn.execute(
        """
        INSERT INTO runs (
            prompt_id, prompt_text, enriched_prompt, matched_cwes,
            matched_keywords, keyword_cwe_pairs,
            model, mode, generated_code, clean_code,
            scan_results, vuln_count, repair_result,
            final_status, total_iterations, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data.get("prompt_id", ""),
            data.get("prompt_text", ""),
            data.get("enriched_prompt", ""),
            json.dumps(data.get("matched_cwes", [])),
            json.dumps(data.get("matched_keywords", [])),
            json.dumps(data.get("keyword_cwe_pairs", [])),
            data.get("model", ""),
            data.get("mode", ""),
            data.get("generated_code", ""),
            data.get("clean_code", ""),
            json.dumps(data.get("scan_results", [])),
            data.get("vuln_count", 0),
            json.dumps(data.get("repair_result", {})),
            data.get("final_status", ""),
            data.get("total_iterations", 0),
            datetime.now().isoformat(),
        ),
    )
    conn.commit()
    conn.close()


def get_all_runs():
    """Retrieve all runs from the database."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM runs ORDER BY id DESC").fetchall()
    conn.close()
    results = []
    for row in rows:
        r = dict(row)
        r["matched_cwes"] = json.loads(r["matched_cwes"] or "[]")
        r["matched_keywords"] = json.loads(r.get("matched_keywords") or "[]")
        r["keyword_cwe_pairs"] = json.loads(r.get("keyword_cwe_pairs") or "[]")
        r["scan_results"] = json.loads(r["scan_results"] or "[]")
        r["repair_result"] = json.loads(r["repair_result"] or "{}")
        results.append(r)
    return results
