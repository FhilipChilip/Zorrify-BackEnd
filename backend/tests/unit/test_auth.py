"""Pruebas unitarias de AuthManager: registro, 2FA, tokens de 24 h, términos y email."""

import datetime as dt

import pytest

from app import totp
from app.auth import AuthError, AuthManager, username_key
from app.auth_store import InMemoryAuthStore
from tests.conftest import FAST_PBKDF2, SECRET, full_login, register_and_enable


# ------------------------------------------------------------ registro
@pytest.mark.parametrize("name", ["María José Pérez", "DJ   Zorro", "李小龙", "alice@home", "o'neil-2"])
def test_register_accepts_any_name(auth, name):
    setup = auth.register(name, "a@example.com", "password123", True, auth.terms_version)
    assert setup["username"] == " ".join(name.split())


def test_login_name_is_case_insensitive(auth, clock):
    secret, _ = register_and_enable(auth, clock, username="María José")
    step = auth.login("maría josé", "password123")
    assert step["status"] == "mfa_required"


def test_same_email_allows_several_accounts(auth):
    auth.register("Cuenta Uno", "misma@example.com", "password123", True, auth.terms_version)
    auth.register("Cuenta Dos", "misma@example.com", "password123", True, auth.terms_version)
    assert auth.store.count_users() == 2


def test_username_must_be_unique_ignoring_case(auth):
    auth.register("Alice", "a@example.com", "password123", True, auth.terms_version)
    with pytest.raises(AuthError) as exc:
        auth.register("ALICE", "b@example.com", "password123", True, auth.terms_version)
    assert exc.value.status_code == 409


@pytest.mark.parametrize("username,email,password,msg", [
    ("x", "x@example.com", "password123", "entre 2 y 50"),
    ("a" * 51, "x@example.com", "password123", "entre 2 y 50"),
    ("Bob\x07", "x@example.com", "password123", "no permitidos"),
    ("Bob", "no-es-email", "password123", "Email inválido"),
    ("Bob", "bob@example.com", "corta1", "entre 8 y 128"),
    ("Bob", "bob@example.com", "solamenteletras", "letra y un número"),
    ("Bobby", "bob@example.com", "bobby12345", "nombre de usuario"),
])
def test_register_validation(auth, username, email, password, msg):
    with pytest.raises(AuthError, match=msg):
        auth.register(username, email, password, True, auth.terms_version)


def test_register_requires_terms_and_current_version(auth):
    with pytest.raises(AuthError, match="Términos"):
        auth.register("Bob", "b@example.com", "password123", False, auth.terms_version)
    with pytest.raises(AuthError) as exc:
        auth.register("Bob", "b@example.com", "password123", True, "0.9")
    assert exc.value.status_code == 409


def test_email_is_not_verified_on_register(auth):
    auth.register("Alice", "alice@example.com", "password123", True, auth.terms_version)
    doc = auth.store.find_user(username_key("alice"))
    assert doc["email_confirmation"]["status"] == "pending"
    assert doc["status"] == "pending_2fa"  # solo falta el 2FA, no el email


# ------------------------------------------------------------ 2FA
def test_setup_returns_qr(auth):
    setup = auth.register("Alice", "a@example.com", "password123", True, auth.terms_version)
    assert setup["qr_svg"].startswith("data:image/svg+xml")
    assert setup["otpauth_uri"].startswith("otpauth://totp/Zorryfy%3AAlice?secret=" + setup["totp_secret"])


def test_mfa_setup_wrong_code_keeps_account_pending(auth):
    setup = auth.register("Alice", "a@example.com", "password123", True, auth.terms_version)
    with pytest.raises(AuthError, match="incorrecto"):
        auth.confirm_mfa_setup(setup["setup_token"], "000000")
    assert auth.store.find_user(username_key("alice"))["mfa"]["enabled"] is False


def test_login_before_mfa_setup_resumes_setup(auth):
    setup = auth.register("Alice", "a@example.com", "password123", True, auth.terms_version)
    result = auth.login("alice", "password123")
    assert result["status"] == "mfa_setup_required"
    assert result["totp_secret"] == setup["totp_secret"]


def test_totp_code_cannot_be_reused(auth, clock):
    secret, _ = register_and_enable(auth, clock)
    full_login(auth, clock, secret)
    code = totp.code_at(secret, clock().timestamp())
    step1 = auth.login("Alice", "password123")
    with pytest.raises(AuthError, match="incorrecto"):
        auth.verify_login(step1["mfa_token"], code=code)


def test_recovery_code_single_use(auth, clock):
    _, codes = register_and_enable(auth, clock)
    step1 = auth.login("Alice", "password123")
    assert auth.verify_login(step1["mfa_token"], recovery_code=codes[0].upper())["recovery_codes_remaining"] == 9
    step1 = auth.login("Alice", "password123")
    with pytest.raises(AuthError):
        auth.verify_login(step1["mfa_token"], recovery_code=codes[0])


def test_mfa_token_expires_after_5_minutes(auth, clock):
    secret, _ = register_and_enable(auth, clock)
    step1 = auth.login("Alice", "password123")
    clock.advance(minutes=6)
    with pytest.raises(AuthError, match="expiró"):
        auth.verify_login(step1["mfa_token"], code=totp.code_at(secret, clock().timestamp()))


def test_show_qr_requires_password(auth, clock):
    secret, _ = register_and_enable(auth, clock)
    user = auth.verify_token(full_login(auth, clock, secret)["access_token"])
    with pytest.raises(AuthError) as exc:
        auth.show_mfa_qr(user, "wrongpass1")
    assert exc.value.status_code == 403
    assert auth.show_mfa_qr(user, "password123")["totp_secret"] == secret


# ------------------------------------------------------------ sin límites de intentos
def test_no_lockout_after_many_wrong_passwords(auth, clock):
    secret, _ = register_and_enable(auth, clock)
    for _ in range(25):
        with pytest.raises(AuthError):
            auth.login("Alice", "wrongpass1")
    assert full_login(auth, clock, secret)["status"] == "ok"


def test_mfa_challenge_survives_many_wrong_codes(auth, clock):
    secret, _ = register_and_enable(auth, clock)
    step1 = auth.login("Alice", "password123")
    for _ in range(10):
        with pytest.raises(AuthError, match="incorrecto"):
            auth.verify_login(step1["mfa_token"], code="000000")
    clock.advance(seconds=31)
    assert auth.verify_login(step1["mfa_token"], code=totp.code_at(secret, clock().timestamp()))["status"] == "ok"


def test_failures_are_audited(auth, clock):
    register_and_enable(auth, clock)
    with pytest.raises(AuthError):
        auth.login("Alice", "wrongpass1")
    assert any(e["event"] == "login_failed" for e in auth.store.audit_events())


# ------------------------------------------------------------ tokens de 24 h
def test_token_lasts_exactly_24_hours(auth, clock):
    secret, _ = register_and_enable(auth, clock)
    result = full_login(auth, clock, secret)
    issued = clock()
    assert dt.datetime.fromisoformat(result["expires_at"]) == issued + dt.timedelta(hours=24)
    assert result["expires_in"] == 24 * 3600
    clock.now = issued + dt.timedelta(hours=23, minutes=59)
    assert auth.verify_token(result["access_token"]) is not None
    clock.now = issued + dt.timedelta(hours=24)
    assert auth.verify_token(result["access_token"]) is None


def test_login_late_at_night_still_gets_24_hours(auth, clock):
    secret, _ = register_and_enable(auth, clock)
    clock.now = dt.datetime(2026, 10, 3, 23, 50, tzinfo=dt.timezone(dt.timedelta(hours=-5)))
    token = full_login(auth, clock, secret)["access_token"]
    clock.advance(hours=12)
    assert auth.verify_token(token) is not None


def test_logout_revokes_token(auth, clock):
    secret, _ = register_and_enable(auth, clock)
    token = full_login(auth, clock, secret)["access_token"]
    assert auth.logout(token) is True
    assert auth.verify_token(token) is None


def test_session_limit_revokes_oldest(auth, clock):
    secret, _ = register_and_enable(auth, clock)
    tokens = [full_login(auth, clock, secret)["access_token"] for _ in range(AuthManager.MAX_SESSIONS_PER_USER + 1)]
    assert auth.verify_token(tokens[0]) is None
    assert all(auth.verify_token(t) for t in tokens[1:])


# ------------------------------------------------------------ términos
def test_changed_terms_require_acceptance_after_2fa(auth, clock):
    secret, _ = register_and_enable(auth, clock)
    newer = AuthManager(auth.store, secret_key=SECRET, now_fn=clock, pbkdf2_iterations=FAST_PBKDF2,
                        terms_version="2.0", cipher=auth.cipher)
    step1 = newer.login("Alice", "password123")
    clock.advance(seconds=31)
    step2 = newer.verify_login(step1["mfa_token"], code=totp.code_at(secret, clock().timestamp()))
    assert step2["status"] == "terms_required" and "access_token" not in step2
    with pytest.raises(AuthError, match="aceptar"):
        newer.accept_terms(step2["terms_token"], False, "2.0")
    result = newer.accept_terms(step2["terms_token"], True, "2.0")
    assert newer.verify_token(result["access_token"]).terms_version == "2.0"


# ------------------------------------------------------------ demo
def test_demo_mode_flow(clock, cipher):
    demo = AuthManager(InMemoryAuthStore(), secret_key=SECRET, now_fn=clock, pbkdf2_iterations=FAST_PBKDF2,
                       cipher=cipher, demo_mode=True)
    demo.ensure_demo_user()
    demo.ensure_demo_user()  # idempotente
    step = demo.verify_login(demo.login("demo", "demo123")["mfa_token"], code="123456")
    assert step["status"] == "terms_required"
    result = demo.accept_terms(step["terms_token"], True, demo.terms_version)
    assert demo.verify_token(result["access_token"]).username == "demo"


def test_demo_code_rejected_outside_demo_mode(auth, clock):
    register_and_enable(auth, clock)
    with pytest.raises(AuthError, match="incorrecto"):
        auth.verify_login(auth.login("Alice", "password123")["mfa_token"], code="123456")
    auth.ensure_demo_user()
    assert auth.store.find_user(username_key("demo")) is None


# ------------------------------------------------------------ confirmación del email
def _logged_user(auth, clock):
    secret, _ = register_and_enable(auth, clock)
    return auth.verify_token(full_login(auth, clock, secret)["access_token"])


def test_email_confirmation_accept(auth, clock):
    user = _logged_user(auth, clock)
    payload = auth.email_confirmation_payload(user)
    assert payload["type"] == "email-confirm" and "alice@example.com" in payload["body"]
    assert auth.answer_email_confirmation(payload["token"], True) == {"email_status": "confirmed"}
    assert auth._user(auth.store.get_user(user.id)).email_status == "confirmed"


def test_email_confirmation_token_is_single_use(auth, clock):
    payload = auth.email_confirmation_payload(_logged_user(auth, clock))
    auth.answer_email_confirmation(payload["token"], True)
    with pytest.raises(AuthError):
        auth.answer_email_confirmation(payload["token"], True)


def test_email_confirmation_reject_then_fix(auth, clock):
    user = _logged_user(auth, clock)
    auth.answer_email_confirmation(auth.email_confirmation_payload(user)["token"], False)
    assert auth.store.get_user(user.id)["email_confirmation"]["status"] == "rejected"
    updated = auth.update_email(user, "correcto@example.com")
    assert updated.email == "correcto@example.com" and updated.email_status == "pending"


def test_email_confirmation_expires_after_24_hours(auth, clock):
    payload = auth.email_confirmation_payload(_logged_user(auth, clock))
    clock.advance(hours=25)
    with pytest.raises(AuthError, match="expiró"):
        auth.answer_email_confirmation(payload["token"], True)


def test_confirmed_email_is_not_asked_again(auth, clock):
    user = _logged_user(auth, clock)
    auth.answer_email_confirmation(auth.email_confirmation_payload(user)["token"], True)
    with pytest.raises(AuthError) as exc:
        auth.email_confirmation_payload(user)
    assert exc.value.status_code == 409
