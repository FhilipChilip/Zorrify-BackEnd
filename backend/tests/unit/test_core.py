"""Pruebas unitarias de TOTP, cifrado, búsqueda, playlists y notificaciones push."""

import base64
import json
from pathlib import Path

import pytest

from app import totp
from app.crypto import CryptoError, FieldCipher
from app.library import TrackLibrary
from app.models import Track
from app.playlists import PlaylistError, PlaylistManager, detect_image_type
from app.push import PushError, PushService
from tests.conftest import make_png, push_subscription


# ------------------------------------------------------------ TOTP
def test_totp_rfc6238_vector():
    # RFC 6238, apéndice B: secreto ASCII "12345678901234567890", T=59 -> 94287082
    assert totp.hotp(b"12345678901234567890", 59 // 30, digits=8) == "94287082"


def test_totp_window_and_replay():
    secret = totp.generate_secret()
    code = totp.code_at(secret, 1_000_000)
    assert totp.verify(secret, code, 1_000_000 + 30) is not None       # 30 s de deriva: válido
    assert totp.verify(secret, code, 1_000_000 + 90) is None           # 90 s: fuera de la ventana
    step = totp.verify(secret, code, 1_000_000)
    assert totp.verify(secret, code, 1_000_000, last_used_step=step) is None


@pytest.mark.parametrize("bad", ["", "12345", "1234567", "abcdef", None])
def test_totp_rejects_malformed_codes(bad):
    assert totp.verify(totp.generate_secret(), bad) is None


def test_qr_is_svg_data_uri():
    uri = totp.provisioning_uri(totp.generate_secret(), "María José")
    assert uri.startswith("otpauth://totp/Zorryfy%3AMar%C3%ADa%20Jos%C3%A9?")
    assert totp.qr_svg_data_uri(uri).startswith("data:image/svg+xml")


# ------------------------------------------------------------ cifrado
def test_encrypt_roundtrip_and_random_nonce():
    c = FieldCipher.generate()
    a, b = c.encrypt("hola", "users.email:1"), c.encrypt("hola", "users.email:1")
    assert a != b and a.startswith("enc:v1:dev:")
    assert c.decrypt(a, "users.email:1") == "hola"


def test_ciphertext_bound_to_context():
    c = FieldCipher.generate()
    token = c.encrypt("secreto", "users.email:user-a")
    with pytest.raises(CryptoError):
        c.decrypt(token, "users.email:user-b")


def test_tampered_ciphertext_fails():
    c = FieldCipher.generate()
    token = c.encrypt("secreto", "ctx")
    prefix, payload = token.rsplit(":", 1)
    raw = bytearray(base64.b64decode(payload))
    raw[-1] ^= 1
    with pytest.raises(CryptoError):
        c.decrypt(prefix + ":" + base64.b64encode(bytes(raw)).decode(), "ctx")


def test_key_rotation_reads_old_data():
    old_key, new_key, index = b"o" * 32, b"n" * 32, b"i" * 32
    old = FieldCipher({"k1": old_key}, "k1", index)
    token = old.encrypt("dato", "ctx")
    rotated = FieldCipher({"k1": old_key, "k2": new_key}, "k2", index)
    assert rotated.decrypt(token, "ctx") == "dato"
    assert rotated.encrypt("dato", "ctx").startswith("enc:v1:k2:")
    with pytest.raises(CryptoError, match="desconocida"):
        FieldCipher({"k2": new_key}, "k2", index).decrypt(token, "ctx")


def test_from_env_requires_keys_with_database(monkeypatch):
    monkeypatch.delenv("DATA_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("BLIND_INDEX_KEY", raising=False)
    with pytest.raises(CryptoError):
        FieldCipher.from_env(required=True)


def test_from_env_rejects_short_key(monkeypatch):
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", base64.b64encode(b"corta").decode())
    monkeypatch.setenv("BLIND_INDEX_KEY", base64.b64encode(bytes(32)).decode())
    with pytest.raises(CryptoError, match="32 bytes"):
        FieldCipher.from_env(required=True)


# ------------------------------------------------------------ búsqueda
@pytest.fixture
def library(tmp_path: Path):
    lib = TrackLibrary(tmp_path, 1024, 1024)
    for i, (artist, title) in enumerate([
        ("Queen", "Bohemian Rhapsody"), ("Shakira", "Ojos Así"), ("Juanes", "La Camisa Negra"),
        ("Carlos Vives", "La Bicicleta"), ("Bomba Estéreo", "Soy Yo"),
    ]):
        lib._tracks[str(i)] = Track(str(i), title, artist, f"{i}.mp3", 100, "disk")
    return lib


@pytest.mark.parametrize("query,expected", [
    ("shak", ["Ojos Así"]),
    ("camisa", ["La Camisa Negra"]),
    ("OJOS ASI", ["Ojos Así"]),
    ("estereo", ["Soy Yo"]),
    ("queen bohemian", ["Bohemian Rhapsody"]),
    ("bo", ["Soy Yo", "Bohemian Rhapsody"]),
    ("zzz", []),
])
def test_search(library, query, expected):
    assert [t.title for t in library.search(query)] == expected


def test_search_empty_and_limit(library):
    assert len(library.search("")) == 5
    assert len(library.search("la", limit=1)) == 1


# ------------------------------------------------------------ playlists
def test_playlists_are_private_per_owner():
    pm = PlaylistManager()
    mine = pm.create("Mías", owner_id="a")
    pm.create("Ajenas", owner_id="b")
    assert [p.name for p in pm.all("a")] == ["Mías"]
    assert pm.get(mine.id, owner_id="b") is None
    with pytest.raises(KeyError):
        pm.rename(mine.id, "Robada", owner_id="b")


def test_playlist_name_rules():
    pm = PlaylistManager()
    assert pm.create("  Rock   del  80  ", owner_id="a").name == "Rock del 80"
    with pytest.raises(PlaylistError):
        pm.create("   ", owner_id="a")
    with pytest.raises(PlaylistError):
        pm.create("x" * 81, owner_id="a")


def test_playlist_track_editing():
    pm = PlaylistManager()
    p = pm.create("Lista", ["a", "b", "c"], owner_id="o")
    pm.move(p.id, 0, 2, owner_id="o")
    assert pm.track_ids(p.id) == ["b", "c", "a"]
    pm.remove_at(p.id, 1, owner_id="o")
    assert pm.track_ids(p.id) == ["b", "a"]
    pm.add_tracks(p.id, ["d"], owner_id="o")
    pm.remove_track_everywhere("a")
    assert pm.track_ids(p.id) == ["b", "d"]
    p.track_ids.check_integrity()


@pytest.mark.parametrize("data,mime", [
    (make_png(), "image/png"),
    (b"\xff\xd8\xff\xe0" + bytes(20), "image/jpeg"),
    (b"RIFF\x00\x00\x00\x00WEBPVP8 ", "image/webp"),
    (b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>", None),
    (b"GIF89a" + bytes(10), None),
    (b"<html>no soy imagen</html>", None),
])
def test_detect_image_type(data, mime):
    assert detect_image_type(data) == mime


def test_cover_set_replace_and_remove():
    pm = PlaylistManager()
    p = pm.create("Con portada", owner_id="o")
    pm.set_cover(p.id, make_png(), owner_id="o")
    assert p.cover_type == "image/png" and p.cover_version == 1
    pm.set_cover(p.id, b"\xff\xd8\xff" + bytes(10), owner_id="o")
    assert p.cover_type == "image/jpeg" and p.cover_version == 2
    pm.remove_cover(p.id, owner_id="o")
    assert p.cover is None and p.cover_version == 3


def test_cover_size_limit():
    pm = PlaylistManager()
    p = pm.create("Grande", owner_id="o")
    with pytest.raises(PlaylistError, match="2 MB"):
        pm.set_cover(p.id, make_png() + bytes(PlaylistManager.MAX_COVER_BYTES), owner_id="o")


# ------------------------------------------------------------ push
def test_vapid_public_key_is_uncompressed_p256_point(cipher):
    from app.auth_store import InMemoryAuthStore

    key = PushService(InMemoryAuthStore(), cipher).public_key
    raw = base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))
    assert len(raw) == 65 and raw[0] == 4


@pytest.mark.parametrize("endpoint", [
    "https://fcm.googleapis.com/fcm/send/x",
    "https://updates.push.services.mozilla.com/wpush/v2/x",
    "https://wns2-par02p.notify.windows.com/w/?token=x",
    "https://web.push.apple.com/x",
])
def test_push_accepts_browser_services(endpoint):
    assert PushService.validate_subscription(push_subscription(endpoint))["endpoint"] == endpoint


@pytest.mark.parametrize("endpoint", [
    "http://fcm.googleapis.com/fcm/send/x",            # sin TLS
    "https://169.254.169.254/latest/meta-data/",       # metadatos de la nube (SSRF)
    "https://localhost:8000/admin",
    "https://fcm.googleapis.com.evil.com/x",           # truco de sufijo
    "https://evilfcm.googleapis.com.attacker.io/x",
])
def test_push_rejects_unknown_hosts(endpoint):
    with pytest.raises(PushError):
        PushService.validate_subscription(push_subscription(endpoint))


def test_push_rejects_bad_keys():
    sub = push_subscription()
    sub["keys"]["p256dh"] = "corta"
    with pytest.raises(PushError):
        PushService.validate_subscription(sub)


def test_push_send_and_cleanup(cipher, push_sender):
    from app.auth_store import InMemoryAuthStore

    store = InMemoryAuthStore()
    service = PushService(store, cipher, sender=push_sender)
    service.subscribe("u1", push_subscription("https://fcm.googleapis.com/fcm/send/vivo"))
    service.subscribe("u1", push_subscription("https://fcm.googleapis.com/fcm/send/muerto"))
    push_sender.gone_endpoints.add("https://fcm.googleapis.com/fcm/send/muerto")
    result = service.send_to_user("u1", {"type": "email-confirm"})
    assert result == {"sent": 1, "removed": 1, "failed": 0}
    assert len(store.push_subscriptions("u1")) == 1
    stored = store.push_subscriptions("u1")[0]["subscription"]
    assert stored.startswith("enc:v1:") and "fcm.googleapis.com" not in stored
    assert json.loads(json.dumps(push_sender.last_payload)) == {"type": "email-confirm"}


def test_push_failure_does_not_break(cipher):
    from app.auth_store import InMemoryAuthStore

    def broken(_sub, _payload):
        raise RuntimeError("servicio push caído")

    store = InMemoryAuthStore()
    service = PushService(store, cipher, sender=broken)
    service.subscribe("u1", push_subscription())
    assert service.send_to_user("u1", {}) == {"sent": 0, "removed": 0, "failed": 1}
