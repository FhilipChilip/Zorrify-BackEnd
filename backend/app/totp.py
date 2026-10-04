"""
TOTP (RFC 6238) para el segundo factor de autenticación.

Implementación propia sobre hmac/hashlib (sin dependencias binarias), compatible
con Google Authenticator, Microsoft Authenticator, Authy, 1Password, etc.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import Optional
from urllib.parse import quote, urlencode

PERIOD_SECONDS = 30
DIGITS = 6


def generate_secret() -> str:
    """Secreto aleatorio de 160 bits en Base32 (sin relleno '=')."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    secret = secret.strip().replace(" ", "").upper()
    return base64.b32decode(secret + "=" * (-len(secret) % 8))


def hotp(key: bytes, counter: int, digits: int = DIGITS) -> str:
    """HOTP (RFC 4226) con HMAC-SHA1 y truncado dinámico."""
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def time_step(timestamp: Optional[float] = None) -> int:
    return int((time.time() if timestamp is None else timestamp) // PERIOD_SECONDS)


def code_at(secret: str, timestamp: Optional[float] = None) -> str:
    return hotp(_decode_secret(secret), time_step(timestamp))


def verify(
    secret: str,
    code: str,
    timestamp: Optional[float] = None,
    last_used_step: Optional[int] = None,
    window: int = 1,
) -> Optional[int]:
    """
    Verifica el código aceptando ±`window` pasos (deriva de reloj).
    Devuelve el paso que coincidió, o None. Un paso <= last_used_step se
    rechaza para impedir la reutilización (replay) de un código ya usado.
    """
    code = (code or "").strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    key = _decode_secret(secret)
    current = time_step(timestamp)
    for step in range(current - window, current + window + 1):
        if last_used_step is not None and step <= last_used_step:
            continue
        if hmac.compare_digest(hotp(key, step), code):
            return step
    return None


def qr_svg_data_uri(uri: str) -> str:
    """
    Código QR (SVG en data URI) del otpauth:// para Google Authenticator.
    Se genera en el servidor: el secreto no pasa por ningún servicio externo.
    """
    import segno

    return segno.make(uri, error="m").svg_data_uri(scale=5, border=2, dark="#000000", light="#ffffff")


def provisioning_uri(secret: str, account: str, issuer: str = "Zorryfy") -> str:
    """URI otpauth:// que la app autenticadora lee desde el código QR."""
    label = quote(f"{issuer}:{account}")
    params = urlencode({
        "secret": secret,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": DIGITS,
        "period": PERIOD_SECONDS,
    })
    return f"otpauth://totp/{label}?{params}"
