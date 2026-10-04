"""
Notificaciones push del navegador (Web Push + VAPID) para confirmar el email.

Flujo
    1. El navegador pide permiso de notificaciones y se suscribe con la llave
       pública VAPID (GET /api/push/public-key).
    2. POST /api/push/subscribe guarda la suscripción (cifrada) y envía la
       notificación «¿<email> es tu dirección de correo?».
    3. El service worker (frontend/sw.js) muestra la notificación con los botones
       «Sí, es mío» / «No es mi email» y responde a POST /auth/email/confirm.

La suscripción es una URL del servicio push del navegador (Google, Mozilla,
Microsoft o Apple). Solo se aceptan esos dominios: así nadie puede usar el
servidor para enviar peticiones a direcciones arbitrarias (SSRF).
"""

import base64
import datetime as dt
import hashlib
import json
import logging
import os
from typing import Callable, Optional
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .crypto import FieldCipher

log = logging.getLogger("zorryfy.push")

# Servicios push de los navegadores (sufijos de dominio permitidos)
ALLOWED_PUSH_HOSTS = (
    "fcm.googleapis.com",            # Chrome, Edge (Android), Opera
    "push.services.mozilla.com",     # Firefox
    "notify.windows.com",            # Edge en Windows (WNS)
    "push.apple.com",                # Safari
)


class PushError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


class PushGone(Exception):
    """El servicio push indicó que la suscripción ya no existe (404/410)."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def generate_vapid_private_key() -> str:
    """Llave privada VAPID nueva (P-256, DER PKCS#8 en base64url) para .env."""
    key = ec.generate_private_key(ec.SECP256R1())
    der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return _b64url(der)


def _pywebpush_sender(private_key: ec.EllipticCurvePrivateKey, subject: str) -> Callable[[dict, dict], None]:
    """Envío real con pywebpush (import diferido: las pruebas usan un sender falso)."""
    from py_vapid import Vapid
    from pywebpush import WebPushException, webpush

    if os.getenv("PUSH_USE_SYSTEM_CERTS", "false").lower() == "true":
        # Redes con inspección TLS: usar el almacén de certificados del sistema
        import truststore

        truststore.inject_into_ssl()
    vapid = Vapid(private_key=private_key)

    def send(subscription: dict, payload: dict) -> None:
        try:
            webpush(
                subscription_info=subscription,
                data=json.dumps(payload),
                vapid_private_key=vapid,
                vapid_claims={"sub": subject},
                ttl=24 * 3600,
                timeout=10,
            )
        except WebPushException as exc:
            status = getattr(exc.response, "status_code", None)
            if status in (404, 410):
                raise PushGone() from exc
            raise

    return send


class PushService:
    def __init__(
        self,
        store,
        cipher: FieldCipher,
        private_key: Optional[str] = None,
        subject: str = "mailto:soporte@zorryfy.app",
        sender: Optional[Callable[[dict, dict], None]] = None,
        now_fn: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.timezone.utc),
    ):
        self.store = store
        self.cipher = cipher
        der = _b64url_decode(private_key) if private_key else _b64url_decode(generate_vapid_private_key())
        self._key = serialization.load_der_private_key(der, password=None)
        self.subject = subject
        self._sender = sender
        self._now = now_fn

    @classmethod
    def from_env(cls, store, cipher: FieldCipher) -> "PushService":
        private_key = os.getenv("VAPID_PRIVATE_KEY", "").strip() or None
        if private_key is None:
            log.warning("Sin VAPID_PRIVATE_KEY: se usa una llave temporal (las suscripciones no sobreviven un reinicio)")
        return cls(store, cipher, private_key, os.getenv("VAPID_SUBJECT", "mailto:soporte@zorryfy.app"))

    @property
    def public_key(self) -> str:
        """applicationServerKey para PushManager.subscribe() (punto P-256 sin comprimir)."""
        point = self._key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        return _b64url(point)

    def _send(self, subscription: dict, payload: dict) -> None:
        if self._sender is None:
            self._sender = _pywebpush_sender(self._key, self.subject)
        self._sender(subscription, payload)

    @staticmethod
    def validate_subscription(subscription: dict) -> dict:
        endpoint = str(subscription.get("endpoint") or "")
        keys = subscription.get("keys") or {}
        parsed = urlparse(endpoint)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or not any(host == h or host.endswith("." + h) for h in ALLOWED_PUSH_HOSTS):
            raise PushError("El navegador devolvió un servicio de notificaciones no reconocido")
        if len(endpoint) > 1024:
            raise PushError("Suscripción inválida")
        try:
            if len(_b64url_decode(str(keys["p256dh"]))) != 65 or len(_b64url_decode(str(keys["auth"]))) != 16:
                raise ValueError
        except (KeyError, ValueError, TypeError):
            raise PushError("Suscripción inválida: faltan las llaves del navegador")
        return {"endpoint": endpoint, "keys": {"p256dh": str(keys["p256dh"]), "auth": str(keys["auth"])}}

    def subscribe(self, user_id: str, subscription: dict, user_agent: Optional[str] = None) -> str:
        clean = self.validate_subscription(subscription)
        sub_id = hashlib.sha256(clean["endpoint"].encode("utf-8")).hexdigest()
        self.store.upsert_push_subscription({
            "_id": sub_id,
            "user_id": user_id,
            # La URL identifica al navegador: se guarda cifrada como el resto de datos personales
            "subscription": self.cipher.encrypt(json.dumps(clean), f"push_subscriptions.subscription:{sub_id}"),
            "user_agent": self.cipher.encrypt(user_agent, f"push_subscriptions.user_agent:{sub_id}"),
            "created_at": self._now(),
        })
        return sub_id

    def send_to_user(self, user_id: str, payload: dict) -> dict:
        """Envía a todos los navegadores del usuario; borra las suscripciones caducadas."""
        sent = removed = failed = 0
        for doc in self.store.push_subscriptions(user_id):
            subscription = json.loads(self.cipher.decrypt(doc["subscription"], f"push_subscriptions.subscription:{doc['_id']}"))
            try:
                self._send(subscription, payload)
                sent += 1
            except PushGone:
                self.store.delete_push_subscription(doc["_id"])
                removed += 1
            except Exception:  # noqa: BLE001 - un navegador caído no debe romper la petición
                log.exception("No se pudo enviar la notificación push")
                failed += 1
        return {"sent": sent, "removed": removed, "failed": failed}
