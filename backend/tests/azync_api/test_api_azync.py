"""
Pruebas asíncronas de la API (httpx.AsyncClient sobre ASGI, sin red).

Recorren los flujos completos y lanzan peticiones concurrentes con
asyncio.gather para comprobar que el sistema sigue fluido y consistente.
"""

import asyncio

import httpx
import pytest

from tests.conftest import make_mp3, make_png, push_subscription

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def aclient(services):
    from app import main

    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://zorryfy.test") as c:
        yield c


async def register(client, username, email="misma@example.com", password="password123"):
    version = (await client.get("/auth/terms")).json()["version"]
    return await client.post("/auth/register", json={
        "username": username, "email": email, "password": password, "accept_terms": True, "terms_version": version,
    })


async def login(client, username, password="password123") -> dict:
    mfa = (await client.post("/auth/login", json={"username": username, "password": password})).json()
    step = (await client.post("/auth/login/verify", json={"mfa_token": mfa["mfa_token"], "code": "123456"})).json()
    if step["status"] == "terms_required":
        step = (await client.post("/auth/terms/accept", json={
            "terms_token": step["terms_token"], "accept_terms": True, "terms_version": step["terms"]["version"],
        })).json()
    return {"Authorization": "Bearer " + step["access_token"]}


async def registered_user(client, username, email="misma@example.com") -> dict:
    setup = (await register(client, username, email)).json()
    await client.post("/auth/2fa/confirm", json={"setup_token": setup["setup_token"], "code": "123456"})
    return await login(client, username)


# ------------------------------------------------------------ flujos
async def test_register_with_any_name_and_login(aclient):
    r = await register(aclient, "María José Pérez")
    assert r.status_code == 201 and r.json()["qr_svg"].startswith("data:image/svg+xml")
    await aclient.post("/auth/2fa/confirm", json={"setup_token": r.json()["setup_token"], "code": "123456"})
    headers = await login(aclient, "maría josé pérez")
    me = (await aclient.get("/auth/me", headers=headers)).json()
    assert me["username"] == "María José Pérez" and me["email_status"] == "pending"


async def test_demo_flow_requires_terms(aclient):
    mfa = (await aclient.post("/auth/login", json={"username": "demo", "password": "demo123"})).json()
    bad = await aclient.post("/auth/login/verify", json={"mfa_token": mfa["mfa_token"], "code": "111111"})
    assert bad.status_code == 401
    step = (await aclient.post("/auth/login/verify", json={"mfa_token": mfa["mfa_token"], "code": "123456"})).json()
    assert step["status"] == "terms_required"
    refused = await aclient.post("/auth/terms/accept", json={
        "terms_token": step["terms_token"], "accept_terms": False, "terms_version": step["terms"]["version"]})
    assert refused.status_code == 400


async def test_token_is_valid_for_24_hours(aclient):
    headers = await login(aclient, "demo", "demo123")
    me = await aclient.get("/auth/me", headers=headers)
    assert me.status_code == 200
    assert (await aclient.get("/auth/config")).json()["token_hours"] == 24


async def test_email_confirmation_by_push(aclient, services):
    headers = await registered_user(aclient, "Laura")
    r = await aclient.post("/api/push/subscribe", headers=headers, json=push_subscription())
    assert r.json()["sent"] == 1
    payload = services.sender.last_payload
    assert payload["type"] == "email-confirm" and "misma@example.com" in payload["body"]
    # El service worker responde con el token que viajó en la notificación (sin cabecera de sesión)
    ok = await aclient.post("/auth/email/confirm", json={"token": payload["token"], "accept": True})
    assert ok.json() == {"email_status": "confirmed"}
    assert (await aclient.get("/auth/me", headers=headers)).json()["email_status"] == "confirmed"
    again = await aclient.post("/api/push/subscribe", headers=headers, json=push_subscription())
    assert again.json()["sent"] == 0  # ya confirmado: no se vuelve a preguntar


async def test_email_rejected_then_changed(aclient, services):
    headers = await registered_user(aclient, "Pedro")
    await aclient.post("/api/push/subscribe", headers=headers, json=push_subscription())
    await aclient.post("/auth/email/confirm", json={"token": services.sender.last_payload["token"], "accept": False})
    assert (await aclient.get("/auth/me", headers=headers)).json()["email_status"] == "rejected"
    changed = await aclient.put("/api/account/email", headers=headers, json={"email": "pedro@correcto.com"})
    assert changed.json()["email"] == "pedro@correcto.com" and changed.json()["email_status"] == "pending"
    resend = await aclient.post("/api/email/confirmation", headers=headers)
    assert resend.json()["sent"] == 1 and "pedro@correcto.com" in services.sender.last_payload["body"]


async def test_playlist_lifecycle_with_cover(aclient):
    headers = await login(aclient, "demo", "demo123")
    upload = await aclient.post("/api/library/upload", headers=headers, files=[
        ("files", ("Queen - Bohemian Rhapsody.mp3", make_mp3(), "audio/mpeg")),
        ("files", ("Shakira - Ojos Así.mp3", make_mp3(), "audio/mpeg")),
    ])
    ids = [t["id"] for t in upload.json()["added"]]

    created = await aclient.post("/api/playlists", headers=headers, json={"name": "Favoritas", "track_ids": ids})
    assert created.status_code == 201
    pid = created.json()["id"]
    cover = await aclient.put(f"/api/playlists/{pid}/cover", headers=headers,
                              files={"file": ("portada.png", make_png(), "image/png")})
    assert cover.json()["cover_url"].startswith(f"/api/playlists/{pid}/cover?v=1")

    listed = (await aclient.get("/api/playlists", headers=headers)).json()
    assert listed == [{**listed[0], "name": "Favoritas", "track_count": 2}]
    image = await aclient.get(listed[0]["cover_url"], headers=headers)
    assert image.headers["content-type"] == "image/png" and image.content == make_png()

    moved = await aclient.post(f"/api/playlists/{pid}/move", headers=headers, json={"from_position": 0, "to_position": 1})
    assert [t["artist"] for t in moved.json()["tracks"]] == ["Shakira", "Queen"]
    queue = await aclient.post(f"/api/playlists/{pid}/load", headers=headers, json={"mode": "replace"})
    assert [t["artist"] for t in queue.json()["items"]] == ["Shakira", "Queen"]

    assert (await aclient.delete(f"/api/playlists/{pid}", headers=headers)).status_code == 204
    assert (await aclient.get("/api/playlists", headers=headers)).json() == []


# ------------------------------------------------------------ concurrencia
async def test_concurrent_registrations_same_email(aclient):
    results = await asyncio.gather(*(register(aclient, f"Usuario {i}") for i in range(15)))
    assert all(r.status_code == 201 for r in results)


async def test_concurrent_registrations_same_name_only_one_wins(aclient):
    results = await asyncio.gather(*(register(aclient, "Nombre Repetido", f"r{i}@example.com") for i in range(8)))
    assert sorted(r.status_code for r in results) == [201] + [409] * 7


async def test_concurrent_uploads_all_reach_the_queue(aclient):
    headers = await login(aclient, "demo", "demo123")
    uploads = [
        aclient.post("/api/library/upload", headers=headers,
                     files=[("files", (f"Artista {i} - Pista {i}.mp3", make_mp3(5), "audio/mpeg"))])
        for i in range(12)
    ]
    assert all(r.status_code == 200 for r in await asyncio.gather(*uploads))
    queue = (await aclient.get("/api/queue", headers=headers)).json()
    assert len(queue["items"]) == 12 and queue["buffer"]["size"] == 12


async def test_concurrent_logins_get_distinct_tokens(aclient):
    tokens = await asyncio.gather(*(login(aclient, "demo", "demo123") for _ in range(6)))
    assert len({t["Authorization"] for t in tokens}) == 6
    statuses = await asyncio.gather(*(aclient.get("/auth/me", headers=t) for t in tokens))
    assert all(s.status_code == 200 for s in statuses)


async def test_concurrent_playlist_edits_keep_list_consistent(aclient, services):
    headers = await login(aclient, "demo", "demo123")
    up = await aclient.post("/api/library/upload", headers=headers,
                            files=[("files", ("A - B.mp3", make_mp3(5), "audio/mpeg"))])
    tid = up.json()["added"][0]["id"]
    pid = (await aclient.post("/api/playlists", headers=headers, json={"name": "Carrera"})).json()["id"]
    await asyncio.gather(*(aclient.post(f"/api/playlists/{pid}/tracks", headers=headers, json={"track_ids": [tid]})
                           for _ in range(20)))
    detail = (await aclient.get(f"/api/playlists/{pid}", headers=headers)).json()
    assert detail["track_count"] == 20
    services.playlists.get(pid).track_ids.check_integrity()
