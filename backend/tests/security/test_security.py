"""Pruebas de seguridad: autenticación, tokens, cifrado, aislamiento, subidas y SSRF."""

import base64
import json
import time

import jwt
import pytest

from tests.conftest import (SECRET, api_login_demo, api_register_and_login, full_login, make_mp3, make_png,
                            push_subscription, register_and_enable)

pytestmark = pytest.mark.security

PROTECTED = [
    ("GET", "/auth/me"), ("POST", "/auth/2fa/qr"), ("GET", "/api/queue"), ("POST", "/api/queue/next"),
    ("DELETE", "/api/queue"), ("GET", "/api/library/search"), ("POST", "/api/library/upload"),
    ("GET", "/api/tracks/x/stream"), ("GET", "/api/playlists"), ("POST", "/api/playlists"),
    ("GET", "/api/playlists/x"), ("GET", "/api/playlists/x/cover"), ("PUT", "/api/playlists/x/cover"),
    ("POST", "/api/push/subscribe"), ("POST", "/api/email/confirmation"), ("PUT", "/api/account/email"),
]


@pytest.mark.parametrize("method,path", PROTECTED)
def test_protected_endpoints_require_token(client, method, path):
    assert client.request(method, path).status_code in (401, 422)
    assert client.request(method, path, headers={"Authorization": "Bearer basura"}).status_code in (401, 422)


# ------------------------------------------------------------ tokens
def _claims(client, headers):
    return jwt.decode(headers["Authorization"][7:], options={"verify_signature": False})


def test_unsigned_token_rejected(client):
    claims = _claims(client, api_login_demo(client))
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {header}.{body}."}).status_code == 401


def test_token_signed_with_other_key_rejected(client):
    claims = _claims(client, api_login_demo(client))
    forged = jwt.encode(claims, "otra-clave-0123456789abcdef0123456789abcdef", algorithm="HS256")
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_token_cannot_be_moved_to_other_user(client, services):
    victim = api_register_and_login(client, "Víctima")
    attacker = api_login_demo(client)
    claims = _claims(client, attacker)
    claims["sub"] = _claims(client, victim)["sub"]
    resigned = jwt.encode(claims, SECRET, algorithm="HS256")  # aun con la clave, la sesión no coincide
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {resigned}"}).status_code == 401


def test_expired_and_revoked_tokens_rejected(auth, clock):
    secret, _ = register_and_enable(auth, clock)
    token = full_login(auth, clock, secret)["access_token"]
    auth.logout(token)
    assert auth.verify_token(token) is None
    token2 = full_login(auth, clock, secret)["access_token"]
    clock.advance(hours=24, seconds=1)
    assert auth.verify_token(token2) is None


def test_challenge_tokens_are_not_interchangeable(client, services):
    mfa = client.post("/auth/login", json={"username": "demo", "password": "demo123"}).json()["mfa_token"]
    # Un mfa_token no sirve para confirmar el email ni para aceptar términos
    assert client.post("/auth/email/confirm", json={"token": mfa, "accept": True}).status_code == 401
    assert client.post("/auth/terms/accept", json={"terms_token": mfa, "accept_terms": True,
                                                   "terms_version": "1.0"}).status_code == 401


def test_same_error_for_unknown_user_and_wrong_password(client):
    a = client.post("/auth/login", json={"username": "no-existe", "password": "x1234567"})
    b = client.post("/auth/login", json={"username": "demo", "password": "x1234567"})
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


# ------------------------------------------------------------ datos cifrados
def test_no_personal_data_in_plaintext(client, services):
    headers = api_register_and_login(client, "Privada", email="privada@example.com")
    client.post("/api/push/subscribe", headers=headers, json=push_subscription("https://fcm.googleapis.com/fcm/send/secreto"))
    store = services.auth.store
    dump = json.dumps({
        "users": list(store._users.values()), "sessions": list(store._sessions.values()),
        "push": list(store._push.values()), "audit": store._audit,
    }, default=str)
    for secret_value in ("privada@example.com", "password123", "testclient", "fcm/send/secreto"):
        assert secret_value not in dump, secret_value
    codes = store.find_user("privada")["mfa"]["recovery_codes"]
    assert len(codes) == 10 and all(len(c["hash"]) == 64 and "-" not in c["hash"] for c in codes)


# ------------------------------------------------------------ aislamiento entre usuarios
def test_playlists_are_isolated_between_users(client):
    owner = api_login_demo(client)
    other = api_register_and_login(client, "Intruso")
    pid = client.post("/api/playlists", headers=owner, json={"name": "Privada"}).json()["id"]
    client.put(f"/api/playlists/{pid}/cover", headers=owner, files={"file": ("p.png", make_png(), "image/png")})
    for method, path, body in [
        ("GET", f"/api/playlists/{pid}", None), ("GET", f"/api/playlists/{pid}/cover", None),
        ("PATCH", f"/api/playlists/{pid}", {"name": "x"}), ("DELETE", f"/api/playlists/{pid}", None),
        ("POST", f"/api/playlists/{pid}/load", {"mode": "replace"}),
        ("POST", f"/api/playlists/{pid}/tracks", {"track_ids": []}),
    ]:
        assert client.request(method, path, headers=other, json=body).status_code == 404, (method, path)
    assert client.get("/api/playlists", headers=other).json() == []
    assert client.get(f"/api/playlists/{pid}", headers=owner).status_code == 200


# ------------------------------------------------------------ subidas
@pytest.mark.parametrize("filename,content", [
    ("portada.svg", b"<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>"),
    ("portada.png", b"<html><script>alert(1)</script></html>"),      # extensión falsa
    ("portada.png", b"GIF89a" + bytes(32)),
])
def test_dangerous_covers_rejected(client, filename, content):
    headers = api_login_demo(client)
    pid = client.post("/api/playlists", headers=headers, json={"name": "P"}).json()["id"]
    r = client.put(f"/api/playlists/{pid}/cover", headers=headers, files={"file": (filename, content, "image/png")})
    assert r.status_code == 400


def test_cover_served_with_safe_headers(client):
    headers = api_login_demo(client)
    pid = client.post("/api/playlists", headers=headers, json={"name": "P"}).json()["id"]
    client.put(f"/api/playlists/{pid}/cover", headers=headers, files={"file": ("p.png", make_png(), "image/png")})
    r = client.get(f"/api/playlists/{pid}/cover", headers=headers)
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["content-security-policy"] == "default-src 'none'"
    assert r.headers["content-type"] == "image/png"


def test_upload_filename_cannot_traverse_paths(client, services):
    headers = api_login_demo(client)
    r = client.post("/api/library/upload", headers=headers,
                    files=[("files", ("../../../etc/Artista - Tema.mp3", make_mp3(), "audio/mpeg"))]).json()
    assert r["added"][0]["filename"] == "Artista - Tema.mp3"
    assert "path" not in r["added"][0]


def test_oversized_cover_rejected(client):
    headers = api_login_demo(client)
    pid = client.post("/api/playlists", headers=headers, json={"name": "P"}).json()["id"]
    big = make_png() + bytes(2 * 1024 * 1024)
    r = client.put(f"/api/playlists/{pid}/cover", headers=headers, files={"file": ("big.png", big, "image/png")})
    assert r.status_code == 400


# ------------------------------------------------------------ SSRF en notificaciones
@pytest.mark.parametrize("endpoint", [
    "https://169.254.169.254/latest/meta-data/iam/",
    "https://127.0.0.1/admin",
    "http://fcm.googleapis.com/fcm/send/x",
    "https://fcm.googleapis.com.evil.com/x",
])
def test_push_subscribe_rejects_internal_or_unknown_targets(client, services, endpoint):
    headers = api_login_demo(client)
    r = client.post("/api/push/subscribe", headers=headers, json=push_subscription(endpoint))
    assert r.status_code == 400
    assert services.sender.sent == []


def test_email_confirmation_token_is_single_use(client, services):
    headers = api_register_and_login(client, "Única")
    client.post("/api/push/subscribe", headers=headers, json=push_subscription())
    token = services.sender.last_payload["token"]
    assert client.post("/auth/email/confirm", json={"token": token, "accept": True}).status_code == 200
    assert client.post("/auth/email/confirm", json={"token": token, "accept": False}).status_code == 401


def test_password_hash_is_slow_enough_in_production(monkeypatch):
    monkeypatch.delenv("PBKDF2_ITERATIONS", raising=False)
    from app.auth import AuthManager

    assert AuthManager().pbkdf2_iterations >= 600_000
