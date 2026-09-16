import sqlite3
import datetime

class DatabaseManager:
    def __init__(self, db_name="analyzer_history.db"):
        self.db_name = db_name
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    timestamp TEXT
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ports (
                    scan_id INTEGER,
                    port INTEGER,
                    status TEXT,
                    banner TEXT,
                    audit_result TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS fuzz_hits (
                    scan_id INTEGER,
                    url TEXT,
                    status INTEGER,
                    size INTEGER,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
            ''')
            conn.commit()

    def save_scan(self, target: str, port_results: list[dict], fuzz_results: list[dict]):
        timestamp = datetime.datetime.now().isoformat()
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO scans (target, timestamp) VALUES (?, ?)', (target, timestamp))
            scan_id = cursor.lastrowid

            for p in port_results:
                cursor.execute('''
                    INSERT INTO ports (scan_id, port, status, banner, audit_result)
                    VALUES (?, ?, ?, ?, ?)
                ''', (scan_id, p['port'], p['status'], p.get('banner', ''), p.get('audit', '')))

            for f in fuzz_results:
                cursor.execute('''
                    INSERT INTO fuzz_hits (scan_id, url, status, size)
                    VALUES (?, ?, ?, ?)
                ''', (scan_id, f['url'], f['status'], f['size']))
            conn.commit()
        return scan_id

    def get_previous_scan(self, target: str):
        with sqlite3.connect(self.db_name) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, timestamp FROM scans WHERE target = ? ORDER BY id DESC LIMIT 1
            ''', (target,))
            row = cursor.fetchone()
            if not row:
                return None
            
            scan_id = row['id']
            timestamp = row['timestamp']

            cursor.execute('SELECT port, status, audit_result FROM ports WHERE scan_id = ?', (scan_id,))
            ports = [dict(r) for r in cursor.fetchall()]

            cursor.execute('SELECT url, status, size FROM fuzz_hits WHERE scan_id = ?', (scan_id,))
            fuzz_hits = [dict(r) for r in cursor.fetchall()]

            res = {
                "timestamp": timestamp,
                "ports": ports,
                "fuzz_hits": fuzz_hits
            }
        if isinstance(res, dict): res["target"] = target
        return res

    def get_all_scans(self, limit: int = 15):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, target, timestamp FROM scans ORDER BY id DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [{"id": r[0], "target": r[1], "timestamp": r[2]} for r in rows]
