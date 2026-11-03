import pytest

import database
from app import app


@pytest.fixture(autouse=True)
def isolated_database(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "sentinel-test.sqlite")
    database.init_db()
    app.config["LIVE_MODE"] = False
    app.config["SIMULATION_EVENTS"] = []
    app.config["WINDOWS_COLLECTION"] = {
        "status": "idle",
        "message": "Windows event collection has not been run yet.",
        "last_collected_at": None,
    }