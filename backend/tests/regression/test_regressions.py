"""
Pruebas de regresión: cada una fija un error real encontrado durante el
desarrollo o un cambio de requisito, para que no vuelva a aparecer.
"""

import datetime as dt
import re
from pathlib import Path

import pytest

from app import library as library_module
from app.auth import AuthError
from app.auth_store import InMemoryAuthStore
from tests.conftest import api_login_demo, full_login, make_mp3, make_png, register_and_enable

pytestmark = pytest.mark.regression
MONGO_INIT = Path(__file__).resolve().parents[2] / "db" / "mongo-init.js"


def test_token_is_read_from_authorization_header_not_query(client):
    """Bug: get_current_user leía `authorization` como parámetro de la URL."""
    headers = api_login_demo(client)
    token = headers["Authorization"]
    assert client.get("/auth/me", params={"authorization": token}).status_code == 401
    assert client.get("/auth/me", headers=headers).status_code == 200


def test_mongo_schema_patterns_survive_javascript_escaping():
    """Bug: el patrón "^\\d{4}-..." perdía las barras en mongo-init.js y rechazaba todas las sesiones."""
    source = MONGO_INIT.read_text(encoding="utf-8")
    patterns = re.findall(r'pattern:\s*"([^"]*)"', source)
    assert patterns, "no se encontraron patrones"
    for pattern in patterns:
        assert "\\" not in pattern, f"patrón con barra invertida: {pattern}"
    day = next(p for p in patterns if "[0-9]{4}" in p)
    assert re.fullmatch(day, "2026-10-03")


def test_wrong_password_for_qr_is_403_not_401(client):
    """Bug: un 401 aquí hacía que la interfaz cerrara la sesión."""
    headers = api_login_demo(client)
    r = client.post("/auth/2fa/qr", headers=headers, json={"password": "incorrecta1"})
    assert r.status_code == 403
    assert client.get("/auth/me", headers=headers).status_code == 200


def test_demo_code_only_in_demo_mode(auth, clock):
    register_and_enable(auth, clock)
    with pytest.raises(AuthError):
        auth.verify_login(auth.login("Alice", "password123")["mfa_token"], code="123456")


def test_advanced_search_was_removed(client):
    """Requisito: se eliminó la búsqueda avanzada; queda solo GET /api/library/search."""
    assert not hasattr(library_module, "SearchFilter")
    assert not hasattr(library_module, "advanced_search")
    headers = api_login_demo(client)
    assert client.post("/api/library/search", headers=headers, json={"query": "x"}).status_code == 405


def test_same_email_several_accounts(auth):
    """Requisito: el email no se verifica ni es único."""
    for name in ("Uno", "Dos", "Tres"):
        auth.register(name, "compartido@example.com", "password123", True, auth.terms_version)
    assert auth.store.count_users() == 3


def test_token_no_longer_expires_at_midnight(auth, clock):
    """Requisito: el token dura 24 h (antes vencía a la medianoche)."""
    secret, _ = register_and_enable(auth, clock)
    clock.now = dt.datetime(2026, 10, 3, 23, 50, tzinfo=dt.timezone(dt.timedelta(hours=-5)))
    token = full_login(auth, clock, secret)["access_token"]
    clock.advance(minutes=30)  # ya es el día siguiente
    assert auth.verify_token(token) is not None


def test_no_lockout_any_more(auth, clock):
    """Requisito: sin límites por intentos fallidos (antes: 5 fallos = 15 min bloqueado)."""
    secret, _ = register_and_enable(auth, clock)
    for _ in range(6):
        with pytest.raises(AuthError) as exc:
            auth.login("Alice", "wrongpass1")
        assert exc.value.status_code == 401  # nunca 423
    assert full_login(auth, clock, secret)["status"] == "ok"


def test_invalid_file_does_not_block_valid_ones(client):
    headers = api_login_demo(client)
    r = client.post("/api/library/upload", headers=headers, files=[
        ("files", ("buena.mp3", make_mp3(), "audio/mpeg")),
        ("files", ("mala.mp3", b"no es audio", "audio/mpeg")),
        ("files", ("notas.txt", b"hola", "text/plain")),
    ]).json()
    assert len(r["added"]) == 1 and len(r["errors"]) == 2


def test_removing_cover_keeps_playlist_detail(client):
    """Bug de la interfaz: quitar la portada devolvía un resumen sin pistas y rompía la vista."""
    headers = api_login_demo(client)
    pid = client.post("/api/playlists", headers=headers, json={"name": "P"}).json()["id"]
    client.put(f"/api/playlists/{pid}/cover", headers=headers, files={"file": ("p.png", make_png(), "image/png")})
    client.delete(f"/api/playlists/{pid}/cover", headers=headers)
    detail = client.get(f"/api/playlists/{pid}", headers=headers).json()
    assert detail["cover_url"] is None and detail["tracks"] == []


def test_memory_store_returns_copies():
    """Un documento leído no debe poder modificar el almacén por referencia."""
    store = InMemoryAuthStore()
    store.insert_session({"_id": "s1", "user_id": "u", "revoked_at": None,
                          "expires_at": dt.datetime.max.replace(tzinfo=dt.timezone.utc), "issued_at": 0})
    store.get_session("s1")["revoked_at"] = "hackeado"
    assert store.get_session("s1")["revoked_at"] is None


def test_token_valid_when_app_clock_differs_from_system_clock(auth, clock):
    """Bug: PyJWT validaba `iat` con el reloj del sistema y rechazaba tokens recién emitidos."""
    secret, _ = register_and_enable(auth, clock)
    clock.advance(days=2)  # el reloj de la app va por delante del reloj del sistema
    token = full_login(auth, clock, secret)["access_token"]
    assert auth.verify_token(token) is not None
