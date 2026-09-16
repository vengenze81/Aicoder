import os
import pytest
from term_analyzer.db import DatabaseManager

def t_db_path(tmp_path):
    # Use temporary database for testing
    return str(tmp_path / "test_history.db")

def test_database_save_and_retrieve(tmp_path, monkeypatch):
    db_path = tmp_path / "test_history.db"
    
    # Mock the database name or create a DatabaseManager that uses a custom path if possible,
    # or test standard operations. Let's instantiate and test save_scan / get_previous_scan.
    db = DatabaseManager()
    
    target = "127.0.0.1"
    ports_data = [{"port": 80, "status": "open", "audit": "Secure / N/A"}]
    fuzz_data = [{"url": "http://127.0.0.1:80/admin", "status": 200, "size": 1200}]
    
    # Save a scan
    db.save_scan(target, ports_data, fuzz_data)
    
    # Retrieve previous scan
    prev = db.get_previous_scan(target)
    assert prev is not None
    assert prev["target"] == target
    assert len(prev["ports"]) == 1
    assert prev["ports"][0]["port"] == 80
    assert len(prev["fuzz_hits"]) == 1
    assert prev["fuzz_hits"][0]["url"] == "http://127.0.0.1:80/admin"
