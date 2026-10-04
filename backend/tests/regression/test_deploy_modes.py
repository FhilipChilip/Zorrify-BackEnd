"""
Modos de arranque del backend (cada caso en un proceso nuevo, porque la
configuración se lee al importar app.main).
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[2]

PROBE = """
import json
from fastapi.testclient import TestClient
from app.main import app
c = TestClient(app)
r = c.get("/")
pre = c.options("/api/queue", headers={"Origin": "https://front.example.com", "Access-Control-Request-Method": "GET"})
print(json.dumps({
    "root_type": r.headers.get("content-type", ""),
    "root_body": r.text[:200],
    "static": c.get("/static/app.js").status_code,
    "sw": c.get("/sw.js").status_code,
    "health": c.get("/health").status_code,
    "cors": pre.headers.get("access-control-allow-origin"),
}))
"""


def run_probe(**env) -> dict:
    out = subprocess.run(
        [sys.executable, "-c", PROBE], cwd=BACKEND, capture_output=True, text=True, timeout=60,
        env={**os.environ, "MONGO_URI": "", "SCAN_ON_STARTUP": "false", "PYTHONUTF8": "1", **env},
    )
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_api_only_mode_does_not_serve_frontend():
    r = run_probe(SERVE_FRONTEND="false")
    assert r["root_type"].startswith("application/json") and "zorryfy-api" in r["root_body"]
    assert r["static"] == 404 and r["sw"] == 404
    assert r["health"] == 200
    assert r["cors"] is None  # sin CORS_ORIGINS no se abre a otros dominios


def test_dev_mode_serves_frontend_from_sibling_folder():
    if not (BACKEND.parent / "frontend" / "index.html").is_file():
        pytest.skip("No hay carpeta frontend junto al backend")
    r = run_probe(SERVE_FRONTEND="auto")
    assert r["root_type"].startswith("text/html")
    assert r["static"] == 200 and r["sw"] == 200


def test_cors_only_for_configured_origin():
    r = run_probe(SERVE_FRONTEND="false", CORS_ORIGINS="https://front.example.com")
    assert r["cors"] == "https://front.example.com"
