"""
Integración con MongoDB real (el mismo esquema que se aplica en Atlas).

    MONGO_TEST_URI="mongodb://zorryfy_app:<pwd>@127.0.0.1:27018/zorryfy?authSource=zorryfy" pytest -m integration

La base debe estar inicializada con db/mongo-init.js. Cada prueba usa nombres
únicos, así que se puede correr varias veces sobre la misma base.
"""

import os
import uuid

import pytest

from app import totp
from app.auth import AuthError, AuthManager
from app.auth_store import MongoAuthStore
from app.crypto import FieldCipher
from app.push import PushService
from tests.conftest import FakePushSender, push_subscription

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def store():
    return MongoAuthStore(os.environ["MONGO_TEST_URI"], os.getenv("MONGO_TEST_DB", "zorryfy"))


@pytest.fixture
def mongo_auth(store):
    return AuthManager(store, secret_key="mongo-test-0123456789abcdef0123456789ab", cipher=FieldCipher.generate(),
                       pbkdf2_iterations=100_000, demo_mode=True)


def unique(prefix: str) -> str:
    return f"{prefix} {uuid.uuid4().hex[:8]}"


def test_full_flow_on_real_mongo(mongo_auth, store):
    name = unique("Mongo Ñandú")
    setup = mongo_auth.register(name, "compartido@example.com", "password123", True, mongo_auth.terms_version, ip="10.0.0.1")
    mongo_auth.confirm_mfa_setup(setup["setup_token"], totp.code_at(setup["totp_secret"]))
    step = mongo_auth.verify_login(mongo_auth.login(name.upper(), "password123")["mfa_token"], code="123456")
    user = mongo_auth.verify_token(step["access_token"])
    assert user.username == name and user.email == "compartido@example.com"
    doc = store.find_user(name.casefold())
    assert doc["email"].startswith("enc:v1:") and "compartido@example.com" not in str(doc)
    assert mongo_auth.logout(step["access_token"]) and mongo_auth.verify_token(step["access_token"]) is None


def test_same_email_twice_and_unique_name(mongo_auth):
    a, b = unique("Uno"), unique("Dos")
    mongo_auth.register(a, "igual@example.com", "password123", True, mongo_auth.terms_version)
    mongo_auth.register(b, "igual@example.com", "password123", True, mongo_auth.terms_version)
    with pytest.raises(AuthError) as exc:
        mongo_auth.register(a.upper(), "otro@example.com", "password123", True, mongo_auth.terms_version)
    assert exc.value.status_code == 409


def test_validator_rejects_plaintext_email(store):
    import datetime as dt

    from pymongo.errors import WriteError

    now = dt.datetime.now(dt.timezone.utc)
    doc = {
        "_id": uuid.uuid4().hex, "username": "Plano", "username_key": unique("plano"),
        "email": "enc:v1:k:x", "email_confirmation": {"status": "pending"},
        "password": {"algorithm": "pbkdf2_sha256", "iterations": 600000, "salt": "0" * 64, "hash": "enc:v1:k:x"},
        "status": "active", "mfa": {"enabled": False, "type": "totp", "totp_secret": "enc:v1:k:x", "recovery_codes": []},
        "terms": {"accepted": True, "version": "1.0", "accepted_at": now},
        "created_at": now, "updated_at": now,
    }
    store.users.insert_one(dict(doc))          # cifrado: se acepta
    store.users.delete_one({"_id": doc["_id"]})
    with pytest.raises(WriteError):            # el mismo documento con el email en claro: rechazado
        store.users.insert_one({**doc, "_id": uuid.uuid4().hex, "username_key": unique("plano"), "email": "plano@example.com"})


def test_email_confirmation_and_push_on_mongo(mongo_auth, store):
    name = unique("Push")
    setup = mongo_auth.register(name, "push@example.com", "password123", True, mongo_auth.terms_version)
    mongo_auth.confirm_mfa_setup(setup["setup_token"], "123456")
    user = mongo_auth.verify_token(mongo_auth.verify_login(mongo_auth.login(name, "password123")["mfa_token"], code="123456")["access_token"])
    sender = FakePushSender()
    push = PushService(store, mongo_auth.cipher, sender=sender)
    push.subscribe(user.id, push_subscription(f"https://fcm.googleapis.com/fcm/send/{uuid.uuid4().hex}"))
    assert push.send_to_user(user.id, mongo_auth.email_confirmation_payload(user))["sent"] == 1
    assert mongo_auth.answer_email_confirmation(sender.last_payload["token"], True) == {"email_status": "confirmed"}
    assert store.get_user(user.id)["email_confirmation"]["status"] == "confirmed"


def test_indexes_match_code(store):
    assert "uniq_username_key" in store.users.index_information()
    assert "uniq_email_index" not in store.users.index_information()
    assert "ttl_expires_at" in store.sessions.index_information()
    assert "user_push" in store.push.index_information()
