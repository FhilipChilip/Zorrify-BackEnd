"""
Autenticación de Zorryfy: registro, login con 2FA (TOTP) y tokens de 24 horas.

Flujo
    1. POST /auth/register        -> crea la cuenta (estado pending_2fa) y devuelve
                                     un setup_token + QR de Google Authenticator.
    2. POST /auth/2fa/confirm     -> el usuario escanea el QR y envía el primer código;
                                     se activa la cuenta y se entregan códigos de respaldo.
    3. POST /auth/login           -> valida usuario y contraseña; devuelve un mfa_token (5 min).
    4. POST /auth/login/verify    -> valida el código TOTP (o un código de respaldo).
                                     Si el usuario no ha aceptado la versión vigente de
                                     los Términos, devuelve un terms_token (paso 5);
                                     si ya la aceptó, emite el token de acceso.
    5. POST /auth/terms/accept    -> acepta los Términos (casilla obligatoria) y emite
                                     el token de acceso.

Reglas de producto
- El nombre de usuario es libre (espacios, tildes, mayúsculas); se compara sin
  distinguir mayúsculas y debe ser único porque es con lo que se inicia sesión.
- El email NO se verifica al registrarse y puede repetirse: una persona puede
  tener varias cuentas. Después, la app pide confirmar la dirección con una
  notificación push (ver app/push.py); confirmarla no bloquea nada.
- Sin límites por intentos fallidos: los fallos solo quedan en la auditoría.
- Token de acceso: JWT HS256 válido 24 horas desde el login. Cada token tiene un
  documento en `sessions` (por jti) para poder revocarlo en logout.

Modo demo (DEMO_MODE=true, solo para talleres): crea la cuenta demo/demo123 y
acepta el código 123456 como segundo factor. Nunca activarlo en producción.

Persistencia: app/auth_store.py (MongoDB Atlas o memoria).
Cifrado: app/crypto.py. Email, hash de contraseña, secreto 2FA, IP y navegador
se guardan cifrados con AES-256-GCM.
"""

import datetime as dt
import hashlib
import hmac
import os
import re
import secrets
import unicodedata
import uuid
from dataclasses import dataclass
from typing import Callable, Optional

import jwt

from . import totp
from .auth_store import DuplicateKeyError, InMemoryAuthStore
from .crypto import FieldCipher

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AuthError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _iso(value: Optional[dt.datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def clean_username(name: str) -> str:
    """Nombre tal como se muestra: espacios colapsados, sin caracteres de control."""
    return " ".join(unicodedata.normalize("NFKC", name or "").split())


def username_key(name: str) -> str:
    """Clave única de login: el mismo nombre sin distinguir mayúsculas."""
    return clean_username(name).casefold()


@dataclass
class User:
    id: str
    username: str
    email: str
    email_status: str
    status: str
    mfa_enabled: bool
    terms_version: Optional[str]
    terms_accepted_at: Optional[dt.datetime]
    created_at: dt.datetime
    last_login_at: Optional[dt.datetime]

    @classmethod
    def from_doc(cls, doc: dict, email: str) -> "User":
        """`email` llega ya descifrado (el documento solo guarda el cifrado)."""
        return cls(
            id=doc["_id"],
            username=doc["username"],
            email=email,
            email_status=doc["email_confirmation"]["status"],
            status=doc["status"],
            mfa_enabled=doc["mfa"]["enabled"],
            terms_version=doc["terms"]["version"],
            terms_accepted_at=doc["terms"]["accepted_at"],
            created_at=doc["created_at"],
            last_login_at=doc.get("last_login_at"),
        )

    def to_public_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "email_status": self.email_status,
            "mfa_enabled": self.mfa_enabled,
            "terms_version": self.terms_version,
            "terms_accepted_at": _iso(self.terms_accepted_at),
            "created_at": _iso(self.created_at),
            "last_login_at": _iso(self.last_login_at),
        }


class AuthManager:
    TOKEN_HOURS = 24
    CLOCK_SKEW_SECONDS = 60          # tolerancia para iat entre servidores
    MAX_SESSIONS_PER_USER = 10      # tokens vigentes simultáneos (una pestaña = una sesión)
    LOGIN_CHALLENGE_MINUTES = 5
    SETUP_CHALLENGE_MINUTES = 15
    TERMS_CHALLENGE_MINUTES = 10
    EMAIL_CONFIRM_HOURS = 24
    RECOVERY_CODES = 10
    ISSUER = "Zorryfy"
    DEMO_USERNAME = "demo"
    DEMO_PASSWORD = "demo123"
    DEMO_CODE = "123456"

    def __init__(
        self,
        store=None,
        secret_key: Optional[str] = None,
        now_fn: Callable[[], dt.datetime] = _utcnow,
        pbkdf2_iterations: Optional[int] = None,
        tz_offset_hours: Optional[int] = None,
        terms_version: Optional[str] = None,
        cipher: Optional[FieldCipher] = None,
        demo_mode: Optional[bool] = None,
    ):
        self.store = store if store is not None else InMemoryAuthStore()
        self.cipher = cipher or FieldCipher.generate()
        self.secret_key = secret_key or os.getenv("JWT_SECRET_KEY", "zorryfy-dev-secret-change-in-production")
        self._now = now_fn
        # OWASP (2023) recomienda 600.000 iteraciones para PBKDF2-HMAC-SHA256
        self.pbkdf2_iterations = pbkdf2_iterations or int(os.getenv("PBKDF2_ITERATIONS", "600000"))
        offset = tz_offset_hours if tz_offset_hours is not None else int(os.getenv("AUTH_TZ_OFFSET_HOURS", "-5"))
        self.tz = dt.timezone(dt.timedelta(hours=offset))
        self.terms_version = terms_version or os.getenv("TERMS_VERSION", "1.0")
        self.demo_mode = demo_mode if demo_mode is not None else os.getenv("DEMO_MODE", "false").lower() == "true"
        self._dummy_salt = secrets.token_hex(32)

    # ------------------------------------------------------------------
    # Cifrado de campos (contexto = colección.campo:_id)
    # ------------------------------------------------------------------
    def _enc(self, value: Optional[str], field: str, doc_id: str) -> Optional[str]:
        return self.cipher.encrypt(value, f"{field}:{doc_id}")

    def _dec(self, value: Optional[str], field: str, doc_id: str) -> Optional[str]:
        return self.cipher.decrypt(value, f"{field}:{doc_id}")

    def _recovery_hash(self, code: str) -> str:
        normalized = code.strip().lower().replace("-", "").replace(" ", "")
        return self.cipher.blind_index(normalized, "recovery_code")

    def _totp_secret(self, user_doc: dict) -> str:
        return self._dec(user_doc["mfa"]["totp_secret"], "users.mfa.totp_secret", user_doc["_id"])

    def _email(self, user_doc: dict) -> str:
        return self._dec(user_doc["email"], "users.email", user_doc["_id"])

    def _check_code(self, user_doc: dict, code: str, use_last_step: bool = True) -> tuple[bool, Optional[int]]:
        """Devuelve (válido, paso TOTP usado). En modo demo 123456 siempre es válido."""
        if self.demo_mode and (code or "").strip() == self.DEMO_CODE:
            return True, None
        last = user_doc["mfa"]["last_used_step"] if use_last_step else None
        step = totp.verify(self._totp_secret(user_doc), code, self._now().timestamp(), last_used_step=last)
        return step is not None, step

    def _user(self, user_doc: dict) -> User:
        return User.from_doc(user_doc, self._email(user_doc))

    # ------------------------------------------------------------------
    # Contraseñas
    # ------------------------------------------------------------------
    @staticmethod
    def _pbkdf2(password: str, salt_hex: str, iterations: int) -> str:
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), iterations).hex()

    def _verify_password(self, user_doc: dict, password: str) -> bool:
        pwd = user_doc["password"]
        stored = self._dec(pwd["hash"], "users.password.hash", user_doc["_id"])
        candidate = self._pbkdf2(password, pwd["salt"], pwd["iterations"])
        return hmac.compare_digest(candidate, stored)

    @staticmethod
    def _validate_password(password: str, key: str) -> None:
        if not 8 <= len(password) <= 128:
            raise AuthError("La contraseña debe tener entre 8 y 128 caracteres")
        if not re.search(r"[^\W\d_]", password) or not re.search(r"\d", password):
            raise AuthError("La contraseña debe incluir al menos una letra y un número")
        if len(key) >= 3 and key in password.casefold():
            raise AuthError("La contraseña no puede contener el nombre de usuario")

    def _password_doc(self, password: str, user_id: str) -> dict:
        salt = secrets.token_hex(32)
        return {
            "algorithm": "pbkdf2_sha256",
            "iterations": self.pbkdf2_iterations,
            "salt": salt,
            # Hash irreversible y además cifrado: sin la llave no se puede atacar offline
            "hash": self._enc(self._pbkdf2(password, salt, self.pbkdf2_iterations), "users.password.hash", user_id),
        }

    @staticmethod
    def _validate_email(email: str) -> str:
        email = (email or "").strip().lower()
        if not EMAIL_RE.match(email) or len(email) > 254:
            raise AuthError("Email inválido")
        return email

    # ------------------------------------------------------------------
    # Términos, configuración y cuenta demo
    # ------------------------------------------------------------------
    def get_terms(self) -> dict:
        """Contenido del modal de Términos y Condiciones."""
        return {
            "version": self.terms_version,
            "sections": [
                {
                    "title": "Condiciones de privacidad",
                    "body": "Tu email, tu contraseña, tu clave de doble factor, tu IP y tu navegador se "
                            "guardan cifrados (AES-256-GCM) en MongoDB Atlas. La contraseña además es un "
                            "hash irreversible. No compartimos tus datos con terceros.",
                },
                {
                    "title": "Límites de almacenamiento",
                    "body": "Solo archivos .mp3, máximo 25 MB por archivo y 200 MB de música en total. "
                            "Portadas de playlist: JPG, PNG o WebP de hasta 2 MB.",
                },
                {
                    "title": "Datos en memoria",
                    "body": "Las canciones que subes, tu cola y tus playlists viven en la memoria del "
                            "servidor: se borran al reiniciarlo. Tu cuenta sí se conserva.",
                },
            ],
        }

    def get_config(self) -> dict:
        return {"demo_mode": self.demo_mode, "terms_version": self.terms_version, "token_hours": self.TOKEN_HOURS}

    def _new_user_doc(self, username: str, email: str, password: str, now: dt.datetime) -> dict:
        user_id = uuid.uuid4().hex
        return {
            "_id": user_id,
            "username": username,
            "username_key": username_key(username),
            "email": self._enc(email, "users.email", user_id),
            "email_confirmation": {"status": "pending", "requested_at": None, "answered_at": None},
            "password": self._password_doc(password, user_id),
            "status": "pending_2fa",
            "mfa": {
                "enabled": False,
                "type": "totp",
                "totp_secret": self._enc(totp.generate_secret(), "users.mfa.totp_secret", user_id),
                "last_used_step": None,
                "confirmed_at": None,
                "recovery_codes": [],
            },
            "terms": {"accepted": False, "version": None, "accepted_at": None, "ip": None, "user_agent": None},
            "created_at": now,
            "updated_at": now,
            "last_login_at": None,
        }

    def ensure_demo_user(self) -> None:
        """Modo demo: crea demo/demo123 con 2FA activo y SIN términos aceptados."""
        if not self.demo_mode or self.store.find_user(username_key=username_key(self.DEMO_USERNAME)):
            return
        now = self._now()
        doc = self._new_user_doc(self.DEMO_USERNAME, "demo@zorryfy.test", self.DEMO_PASSWORD, now)
        doc["status"] = "active"
        doc["mfa"]["enabled"] = True
        doc["mfa"]["confirmed_at"] = now
        self.store.insert_user(doc)

    # ------------------------------------------------------------------
    # Registro + activación del 2FA
    # ------------------------------------------------------------------
    def register(
        self,
        username: str,
        email: str,
        password: str,
        accept_terms: bool,
        terms_version: str,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> dict:
        username = clean_username(username)
        if not 2 <= len(username) <= 50:
            raise AuthError("El nombre de usuario debe tener entre 2 y 50 caracteres")
        if any(unicodedata.category(c).startswith("C") for c in username):
            raise AuthError("El nombre de usuario tiene caracteres no permitidos")
        # Sin verificación y sin unicidad: el mismo email puede tener varias cuentas
        email = self._validate_email(email)
        self._validate_password(password, username_key(username))
        if accept_terms is not True:
            raise AuthError("Debes aceptar los Términos y Condiciones")
        if terms_version != self.terms_version:
            raise AuthError("Los Términos y Condiciones cambiaron; recarga la página y acéptalos de nuevo", 409)

        now = self._now()
        doc = self._new_user_doc(username, email, password, now)
        doc["terms"] = {
            "accepted": True,
            "version": terms_version,
            "accepted_at": now,
            "ip": self._enc(ip, "users.terms.ip", doc["_id"]),
            "user_agent": self._enc(user_agent, "users.terms.user_agent", doc["_id"]),
        }
        try:
            self.store.insert_user(doc)
        except DuplicateKeyError as exc:
            raise AuthError("Ese nombre de usuario ya existe; elige otro", 409) from exc
        self._audit(doc, "register", ip, user_agent, {"terms_version": terms_version})
        return self._mfa_setup_payload(doc)

    def _mfa_setup_payload(self, user_doc: dict) -> dict:
        setup_token = self._create_challenge(user_doc["_id"], "mfa_setup", self.SETUP_CHALLENGE_MINUTES)
        return {
            "status": "mfa_setup_required",
            "username": user_doc["username"],
            "setup_token": setup_token,
            **self._qr_payload(user_doc),
            "expires_in": self.SETUP_CHALLENGE_MINUTES * 60,
        }

    def _qr_payload(self, user_doc: dict) -> dict:
        secret = self._totp_secret(user_doc)
        uri = totp.provisioning_uri(secret, user_doc["username"], self.ISSUER)
        return {"totp_secret": secret, "otpauth_uri": uri, "qr_svg": totp.qr_svg_data_uri(uri)}

    def show_mfa_qr(self, user: User, password: str, ip: Optional[str] = None, user_agent: Optional[str] = None) -> dict:
        """
        Vuelve a mostrar el QR de Google Authenticator a un usuario con sesión
        (p. ej. teléfono nuevo). Exige la contraseña otra vez: el QR es la llave del 2FA.
        """
        user_doc = self.store.get_user(user.id)
        if user_doc is None:
            raise AuthError("Usuario no encontrado", 404)
        if not self._verify_password(user_doc, password):
            self._audit(user_doc, "login_failed", ip, user_agent, {"reason": "bad_password:mfa_qr"})
            raise AuthError("Contraseña incorrecta", 403)
        self._audit(user_doc, "mfa_qr_viewed", ip, user_agent)
        return {"username": user_doc["username"], **self._qr_payload(user_doc)}

    def confirm_mfa_setup(self, setup_token: str, code: str, ip: Optional[str] = None, user_agent: Optional[str] = None) -> dict:
        challenge, user_doc = self._open_challenge(setup_token, "mfa_setup")
        valid, step = self._check_code(user_doc, code, use_last_step=False)
        if not valid:
            self._audit(user_doc, "login_failed", ip, user_agent, {"reason": "bad_code:mfa_setup"})
            raise AuthError("Código de verificación incorrecto", 401)

        now = self._now()
        codes = [f"{secrets.token_hex(4)}-{secrets.token_hex(4)}" for _ in range(self.RECOVERY_CODES)]
        self.store.update_user(user_doc["_id"], set_fields={
            "status": "active",
            "mfa.enabled": True,
            "mfa.confirmed_at": now,
            "mfa.last_used_step": step,
            "mfa.recovery_codes": [{"hash": self._recovery_hash(c), "used_at": None} for c in codes],
            "updated_at": now,
        })
        self.store.delete_challenge(challenge["_id"])
        self._audit(user_doc, "mfa_enabled", ip, user_agent)
        return {"status": "mfa_enabled", "username": user_doc["username"], "recovery_codes": codes}

    # ------------------------------------------------------------------
    # Login en dos pasos
    # ------------------------------------------------------------------
    def login(self, username: str, password: str, ip: Optional[str] = None, user_agent: Optional[str] = None) -> dict:
        """Paso 1: nombre de usuario (sin distinguir mayúsculas) y contraseña."""
        user_doc = self.store.find_user(username_key=username_key(username))
        if user_doc is None:
            # Mismo coste que un usuario real para no revelar qué cuentas existen
            self._pbkdf2(password, self._dummy_salt, self.pbkdf2_iterations)
            self._audit(None, "login_failed", ip, user_agent, {"reason": "unknown_user"}, identifier=username)
            raise AuthError("Usuario o contraseña incorrectos", 401)
        if not self._verify_password(user_doc, password):
            self._audit(user_doc, "login_failed", ip, user_agent, {"reason": "bad_password"})
            raise AuthError("Usuario o contraseña incorrectos", 401)

        if not user_doc["mfa"]["enabled"]:
            # Registro sin terminar: se retoma la configuración del 2FA
            return self._mfa_setup_payload(user_doc)

        mfa_token = self._create_challenge(user_doc["_id"], "mfa_login", self.LOGIN_CHALLENGE_MINUTES)
        self._audit(user_doc, "login_password_ok", ip, user_agent)
        return {"status": "mfa_required", "mfa_token": mfa_token, "expires_in": self.LOGIN_CHALLENGE_MINUTES * 60}

    def verify_login(
        self,
        mfa_token: str,
        code: Optional[str] = None,
        recovery_code: Optional[str] = None,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> dict:
        """Paso 2: código TOTP o código de respaldo -> token de acceso (o paso de términos)."""
        if not code and not recovery_code:
            raise AuthError("Envía el código de tu app autenticadora o un código de respaldo")
        challenge, user_doc = self._open_challenge(mfa_token, "mfa_login")
        now = self._now()
        updates: dict = {}

        if code:
            method = "totp"
            valid, step = self._check_code(user_doc, code)
            if step is not None:
                updates["mfa.last_used_step"] = step
        else:
            method = "recovery_code"
            wanted = self._recovery_hash(recovery_code)
            valid = False
            codes = user_doc["mfa"]["recovery_codes"]
            for entry in codes:
                if entry["used_at"] is None and hmac.compare_digest(entry["hash"], wanted):
                    entry["used_at"] = now
                    updates["mfa.recovery_codes"] = codes
                    valid = True
                    break

        if not valid:
            # Sin límite de intentos: el reto sigue vigente hasta que vence (5 min)
            self._audit(user_doc, "login_failed", ip, user_agent, {"reason": "bad_code:mfa_login"})
            raise AuthError("Código de verificación incorrecto", 401)

        self.store.delete_challenge(challenge["_id"])
        updates.update({"last_login_at": now, "updated_at": now})
        user_doc = self.store.update_user(user_doc["_id"], set_fields=updates)

        terms = user_doc["terms"]
        if not terms["accepted"] or terms["version"] != self.terms_version:
            # Paso 5: debe aceptar los Términos vigentes antes de recibir el token
            terms_token = self._create_challenge(
                user_doc["_id"], "terms_accept", self.TERMS_CHALLENGE_MINUTES, meta={"method": method}
            )
            return {
                "status": "terms_required",
                "terms_token": terms_token,
                "terms": self.get_terms(),
                "expires_in": self.TERMS_CHALLENGE_MINUTES * 60,
            }
        return self._login_success(user_doc, method, ip, user_agent)

    def accept_terms(
        self,
        terms_token: str,
        accept_terms: bool,
        terms_version: str,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> dict:
        """Paso 5 del login: casilla de Términos marcada -> token de acceso."""
        challenge, user_doc = self._open_challenge(terms_token, "terms_accept")
        if accept_terms is not True:
            raise AuthError("Debes aceptar los Términos y Condiciones para continuar")
        if terms_version != self.terms_version:
            raise AuthError("Los Términos y Condiciones cambiaron; recarga la página y acéptalos de nuevo", 409)
        now = self._now()
        user_id = user_doc["_id"]
        user_doc = self.store.update_user(user_id, set_fields={
            "terms": {
                "accepted": True,
                "version": terms_version,
                "accepted_at": now,
                "ip": self._enc(ip, "users.terms.ip", user_id),
                "user_agent": self._enc(user_agent, "users.terms.user_agent", user_id),
            },
            "updated_at": now,
        })
        self.store.delete_challenge(challenge["_id"])
        self._audit(user_doc, "terms_accepted", ip, user_agent, {"terms_version": terms_version})
        return self._login_success(user_doc, challenge.get("meta", {}).get("method", "totp"), ip, user_agent)

    def _login_success(self, user_doc: dict, method: str, ip: Optional[str], user_agent: Optional[str]) -> dict:
        now = self._now()
        token, expires_at = self._issue_token(user_doc, method, ip, user_agent)
        self._audit(user_doc, "login_success", ip, user_agent, {"method": method})
        remaining = sum(1 for c in user_doc["mfa"]["recovery_codes"] if c["used_at"] is None)
        return {
            "status": "ok",
            "access_token": token,
            "token_type": "bearer",
            "expires_at": expires_at.isoformat(),
            "expires_in": int((expires_at - now).total_seconds()),
            "recovery_codes_remaining": remaining,
            "user": self._user(user_doc).to_public_dict(),
        }

    # ------------------------------------------------------------------
    # Tokens de acceso (24 h)
    # ------------------------------------------------------------------
    def _issue_token(self, user_doc: dict, method: str, ip: Optional[str], user_agent: Optional[str]) -> tuple[str, dt.datetime]:
        now = self._now()
        active = self.store.active_sessions(user_doc["_id"], now)
        for old in active[: max(0, len(active) - self.MAX_SESSIONS_PER_USER + 1)]:
            self.store.update_session(old["_id"], {"revoked_at": now, "revoked_reason": "session_limit"})

        expires_at = now + dt.timedelta(hours=self.TOKEN_HOURS)
        jti = secrets.token_hex(16)
        day = now.astimezone(self.tz).date().isoformat()
        payload = {
            "sub": user_doc["_id"],
            "jti": jti,
            "typ": "access",
            "amr": ["pwd", "otp"],
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
        }
        token = jwt.encode(payload, self.secret_key, algorithm="HS256")
        self.store.insert_session({
            "_id": jti,
            "user_id": user_doc["_id"],
            "day": day,
            "mfa_method": method,
            "issued_at": now,
            "expires_at": expires_at,
            "revoked_at": None,
            "revoked_reason": None,
            "ip": self._enc(ip, "sessions.ip", jti),
            "user_agent": self._enc(user_agent, "sessions.user_agent", jti),
        })
        return token, expires_at

    def _decode(self, token: str) -> Optional[dict]:
        try:
            # exp e iat se validan con self._now() (reloj de la app) en verify_token:
            # así un pequeño desfase de reloj entre servidores no invalida tokens recién emitidos
            claims = jwt.decode(
                token, self.secret_key, algorithms=["HS256"],
                options={"verify_exp": False, "verify_iat": False, "require": ["sub", "jti", "exp", "iat"]},
            )
        except jwt.InvalidTokenError:
            return None
        return claims if claims.get("typ") == "access" else None

    def verify_token(self, token: str) -> Optional[User]:
        claims = self._decode(token)
        if claims is None:
            return None
        now = self._now()
        if claims["exp"] <= now.timestamp() or claims["iat"] > now.timestamp() + self.CLOCK_SKEW_SECONDS:
            return None
        session = self.store.get_session(claims["jti"])
        if (
            session is None
            or session["revoked_at"] is not None
            or session["expires_at"] <= now
            or session["user_id"] != claims["sub"]
        ):
            return None
        user_doc = self.store.get_user(claims["sub"])
        if user_doc is None or user_doc["status"] != "active":
            return None
        return self._user(user_doc)

    def logout(self, token: str) -> bool:
        claims = self._decode(token)
        if claims is None or self.store.get_session(claims["jti"]) is None:
            return False
        self.store.update_session(claims["jti"], {"revoked_at": self._now(), "revoked_reason": "logout"})
        user_doc = self.store.get_user(claims["sub"])
        if user_doc:
            self._audit(user_doc, "logout", None, None)
        return True

    # ------------------------------------------------------------------
    # Confirmación del email por notificación push (no bloqueante)
    # ------------------------------------------------------------------
    def email_confirmation_payload(self, user: User) -> dict:
        """
        Crea un token de un solo uso (24 h) y el contenido de la notificación push
        que pregunta al usuario si el email registrado es suyo.
        """
        user_doc = self.store.get_user(user.id)
        if user_doc is None:
            raise AuthError("Usuario no encontrado", 404)
        if user_doc["email_confirmation"]["status"] == "confirmed":
            raise AuthError("Tu email ya está confirmado", 409)
        token = self._create_challenge(user.id, "email_confirm", self.EMAIL_CONFIRM_HOURS * 60)
        now = self._now()
        self.store.update_user(user.id, set_fields={"email_confirmation.requested_at": now, "updated_at": now})
        email = self._email(user_doc)
        return {
            "type": "email-confirm",
            "title": "Confirma tu email en Zorryfy",
            "body": f"¿{email} es tu dirección de correo?",
            "token": token,
            "email": email,
        }

    def answer_email_confirmation(self, token: str, accept: bool, ip: Optional[str] = None, user_agent: Optional[str] = None) -> dict:
        """Respuesta desde la notificación: «Sí, es mío» o «No es mi email»."""
        challenge, user_doc = self._open_challenge(token, "email_confirm")
        now = self._now()
        status = "confirmed" if accept else "rejected"
        self.store.update_user(user_doc["_id"], set_fields={
            "email_confirmation": {
                "status": status,
                "requested_at": user_doc["email_confirmation"]["requested_at"],
                "answered_at": now,
            },
            "updated_at": now,
        })
        self.store.delete_challenge(challenge["_id"])
        self._audit(user_doc, "email_confirmed" if accept else "email_rejected", ip, user_agent)
        return {"email_status": status}

    def update_email(self, user: User, email: str, ip: Optional[str] = None, user_agent: Optional[str] = None) -> User:
        """Corrige el email (p. ej. tras «No es mi email»); vuelve a quedar pendiente."""
        email = self._validate_email(email)
        now = self._now()
        updated = self.store.update_user(user.id, set_fields={
            "email": self._enc(email, "users.email", user.id),
            "email_confirmation": {"status": "pending", "requested_at": None, "answered_at": None},
            "updated_at": now,
        })
        if updated is None:
            raise AuthError("Usuario no encontrado", 404)
        self._audit(updated, "email_changed", ip, user_agent)
        return self._user(updated)

    # ------------------------------------------------------------------
    # Retos temporales y auditoría
    # ------------------------------------------------------------------
    def _create_challenge(self, user_id: str, purpose: str, minutes: int, meta: Optional[dict] = None) -> str:
        """Devuelve el token opaco; en la BD solo se guarda su SHA-256."""
        raw = secrets.token_urlsafe(32)
        now = self._now()
        self.store.insert_challenge({
            "_id": _sha256(raw),
            "user_id": user_id,
            "purpose": purpose,
            "meta": meta or {},
            "created_at": now,
            "expires_at": now + dt.timedelta(minutes=minutes),
        })
        return raw

    def _open_challenge(self, raw_token: str, purpose: str) -> tuple[dict, dict]:
        challenge = self.store.get_challenge(_sha256(raw_token or ""))
        if challenge is None or challenge["purpose"] != purpose or challenge["expires_at"] <= self._now():
            raise AuthError("La verificación expiró o no es válida; vuelve a intentarlo", 401)
        user_doc = self.store.get_user(challenge["user_id"])
        if user_doc is None:
            raise AuthError("La verificación expiró o no es válida; vuelve a intentarlo", 401)
        return challenge, user_doc

    def _audit(
        self,
        user_doc: Optional[dict],
        event: str,
        ip: Optional[str],
        user_agent: Optional[str],
        meta: Optional[dict] = None,
        identifier: Optional[str] = None,
    ) -> None:
        event_id = uuid.uuid4().hex
        meta = dict(meta or {})
        if identifier is not None:
            # Lo escrito en el login puede ser un dato personal: también va cifrado
            meta["identifier"] = self._enc(identifier, "audit_log.meta.identifier", event_id)
        self.store.add_audit({
            "_id": event_id,
            "user_id": user_doc["_id"] if user_doc else None,
            "username": user_doc["username"] if user_doc else None,
            "event": event,
            "at": self._now(),
            "ip": self._enc(ip, "audit_log.ip", event_id),
            "user_agent": self._enc(user_agent, "audit_log.user_agent", event_id),
            "meta": meta,
        })

    def get_stats(self) -> dict:
        now = self._now()
        self.store.purge_expired(now)
        return {
            "total_users": self.store.count_users(),
            "active_sessions": self.store.count_active_sessions(now),
        }
