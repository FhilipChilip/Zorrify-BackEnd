"""
Fixtures compartidas por todas las suites.

Las pruebas de API reemplazan los servicios globales de la app (auth, biblioteca,
cola, playlists, push) por instancias nuevas en memoria, con PBKDF2 rápido y un
enviador de notificaciones falso que guarda lo que se habría enviado.
"""

import base64
import datetime as dt
import os
import struct
import zlib

import pytest

from app import totp
from app.auth import AuthManager
from app.auth_store import InMemoryAuthStore
from app.crypto import FieldCipher
from app.library import TrackLibrary
from app.playback_queue import PlaybackQueue
from app.playlists import PlaylistManager
from app.push import PushGone, PushService

BOGOTA = dt.timezone(dt.timedelta(hours=-5))
FAST_PBKDF2 = 1000
SECRET = "test-secret-0123456789abcdef0123456789abcdef"


# ---------------------------------------------------------------- datos de prueba
def make_mp3(frames: int = 40) -> bytes:
    """MP3 válido de silencio (tramas MPEG-1 Layer III, 128 kbps, 44.1 kHz)."""
    frame = bytes([0xFF, 0xFB, 0x90, 0x64]) + bytes(413)
    return frame * frames


def make_png(width: int = 8, height: int = 8, rgb=(255, 140, 0)) -> bytes:
    """PNG real y decodificable, generado sin dependencias."""
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    raw = b"".join(b"\x00" + bytes(rgb) * width for _ in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def push_subscription(endpoint: str = "https://fcm.googleapis.com/fcm/send/abc123") -> dict:
    return {"endpoint": endpoint, "keys": {"p256dh": b64url(b"\x04" + bytes(64)), "auth": b64url(bytes(16))}}


# ---------------------------------------------------------------- reloj y servicios
class Clock:
    """Reloj controlable para probar expiraciones sin esperar."""

    def __init__(self, start: dt.datetime):
        self.now = start

    def __call__(self) -> dt.datetime:
        return self.now

    def advance(self, **kwargs) -> None:
        self.now += dt.timedelta(**kwargs)


class FakePushSender:
    """Sustituye a pywebpush: registra los envíos y puede simular suscripciones caducadas."""

    def __init__(self):
        self.sent: list[tuple[dict, dict]] = []
        self.gone_endpoints: set[str] = set()

    def __call__(self, subscription: dict, payload: dict) -> None:
        if subscription["endpoint"] in self.gone_endpoints:
            raise PushGone()
        self.sent.append((subscription, payload))

    @property
    def last_payload(self) -> dict:
        return self.sent[-1][1]


@pytest.fixture
def clock():
    # 3 oct 2026, 10:00 en Bogotá
    return Clock(dt.datetime(2026, 10, 3, 10, 0, tzinfo=BOGOTA).astimezone(dt.timezone.utc))


@pytest.fixture
def cipher():
    return FieldCipher.generate()


@pytest.fixture
def auth(clock, cipher):
    return AuthManager(InMemoryAuthStore(), secret_key=SECRET, now_fn=clock, pbkdf2_iterations=FAST_PBKDF2, cipher=cipher)


@pytest.fixture
def push_sender():
    return FakePushSender()


def register_and_enable(auth, clock, username="Alice", password="password123", email=None):
    setup = auth.register(username, email or "alice@example.com", password, True, auth.terms_version)
    code = totp.code_at(setup["totp_secret"], clock().timestamp())
    enabled = auth.confirm_mfa_setup(setup["setup_token"], code)
    return setup["totp_secret"], enabled["recovery_codes"]


def full_login(auth, clock, secret, username="Alice", password="password123"):
    step1 = auth.login(username, password)
    assert step1["status"] == "mfa_required"
    clock.advance(seconds=31)  # evita reutilizar el paso TOTP anterior
    return auth.verify_login(step1["mfa_token"], code=totp.code_at(secret, clock().timestamp()))


# ---------------------------------------------------------------- app con servicios aislados
class Services:
    def __init__(self, auth, library, queue, playlists, push, sender):
        self.auth = auth
        self.library = library
        self.queue = queue
        self.playlists = playlists
        self.push = push
        self.sender = sender


@pytest.fixture
def services(monkeypatch, tmp_path, push_sender):
    from app import main, routes  # main primero: routes importa los servicios de main

    cipher = FieldCipher.generate()
    store = InMemoryAuthStore()
    svc = Services(
        auth=AuthManager(store, secret_key=SECRET, pbkdf2_iterations=FAST_PBKDF2, cipher=cipher, demo_mode=True),
        library=TrackLibrary(tmp_path, 1024 * 1024, 4 * 1024 * 1024),
        queue=PlaybackQueue(),
        playlists=PlaylistManager(),
        push=PushService(store, cipher, sender=push_sender),
        sender=push_sender,
    )
    svc.auth.ensure_demo_user()
    for name, value in (("auth", svc.auth), ("library", svc.library), ("playback_queue", svc.queue),
                        ("playlists", svc.playlists), ("push", svc.push)):
        monkeypatch.setattr(routes, name, value)
    return svc


@pytest.fixture
def client(services):
    from fastapi.testclient import TestClient

    from app import main

    return TestClient(main.app)


def api_login_demo(client) -> dict:
    """Login demo completo por HTTP (contraseña -> 123456 -> términos). Devuelve headers."""
    mfa = client.post("/auth/login", json={"username": "demo", "password": "demo123"}).json()
    step = client.post("/auth/login/verify", json={"mfa_token": mfa["mfa_token"], "code": "123456"}).json()
    if step["status"] == "terms_required":
        step = client.post("/auth/terms/accept", json={
            "terms_token": step["terms_token"], "accept_terms": True, "terms_version": step["terms"]["version"],
        }).json()
    return {"Authorization": "Bearer " + step["access_token"]}


def api_register_and_login(client, username: str, email: str = "otra@example.com", password: str = "password123") -> dict:
    """Registro + 2FA (código demo) + login por HTTP. Devuelve headers."""
    version = client.get("/auth/terms").json()["version"]
    setup = client.post("/auth/register", json={
        "username": username, "email": email, "password": password, "accept_terms": True, "terms_version": version,
    })
    assert setup.status_code == 201, setup.text
    client.post("/auth/2fa/confirm", json={"setup_token": setup.json()["setup_token"], "code": "123456"})
    mfa = client.post("/auth/login", json={"username": username, "password": password}).json()
    ok = client.post("/auth/login/verify", json={"mfa_token": mfa["mfa_token"], "code": "123456"}).json()
    return {"Authorization": "Bearer " + ok["access_token"]}


def pytest_collection_modifyitems(config, items):
    # Las pruebas de MongoDB real solo corren si se indica dónde está la base
    if not os.getenv("MONGO_TEST_URI"):
        skip = pytest.mark.skip(reason="Define MONGO_TEST_URI para correr las pruebas contra MongoDB real")
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip)
