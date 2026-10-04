"""
Cifrado de datos del usuario en reposo (AES-256-GCM, a nivel de aplicación).

MongoDB Atlas nunca ve estos campos en claro: se cifran antes de guardarse y
solo la API, que tiene las llaves, puede leerlos.

Formato guardado:   enc:v1:<kid>:<base64(nonce 12 B || ciphertext || tag 16 B)>
- kid: identificador de la llave, para rotarlas sin perder datos antiguos.
- AAD (datos asociados): "<colección>.<campo>:<_id>", así un valor cifrado no
  puede copiarse a otro campo u otro usuario sin que falle el descifrado.

Huellas con llave ("índice ciego"), para comparar sin guardar el valor:
  códigos de respaldo del 2FA = HMAC-SHA256(BLIND_INDEX_KEY, código).

Variables de entorno (llaves de 32 bytes en base64; generar con
`python -m app.crypto`):
    DATA_ENCRYPTION_KEY       llave activa
    DATA_ENCRYPTION_KEY_ID    id de la llave activa (por defecto "k1")
    DATA_ENCRYPTION_OLD_KEYS  llaves anteriores "k0:<base64>,..." (solo lectura)
    BLIND_INDEX_KEY           llave HMAC del índice ciego
"""

import base64
import hashlib
import hmac
import os
import secrets
import warnings
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "enc:v1:"


class CryptoError(Exception):
    pass


def _decode_key(value: str, name: str) -> bytes:
    try:
        key = base64.b64decode(value.strip(), validate=True)
    except (ValueError, TypeError) as exc:
        raise CryptoError(f"{name} no es base64 válido") from exc
    if len(key) != 32:
        raise CryptoError(f"{name} debe tener 32 bytes (AES-256)")
    return key


class FieldCipher:
    def __init__(self, keys: dict[str, bytes], active_kid: str, index_key: bytes):
        if active_kid not in keys:
            raise CryptoError(f"No existe la llave activa '{active_kid}'")
        if ":" in active_kid:
            raise CryptoError("El id de llave no puede contener ':'")
        self._aead = {kid: AESGCM(key) for kid, key in keys.items()}
        self.active_kid = active_kid
        self._index_key = index_key

    @staticmethod
    def _aad(context: str) -> bytes:
        return context.encode("utf-8")

    def encrypt(self, value: Optional[str], context: str) -> Optional[str]:
        if value is None:
            return None
        nonce = secrets.token_bytes(12)
        ciphertext = self._aead[self.active_kid].encrypt(nonce, value.encode("utf-8"), self._aad(context))
        return f"{PREFIX}{self.active_kid}:{base64.b64encode(nonce + ciphertext).decode('ascii')}"

    def decrypt(self, token: Optional[str], context: str) -> Optional[str]:
        if token is None:
            return None
        if not token.startswith(PREFIX):
            raise CryptoError("El valor no está cifrado")
        kid, _, payload = token[len(PREFIX):].partition(":")
        aead = self._aead.get(kid)
        if aead is None:
            raise CryptoError(f"Llave desconocida '{kid}'")
        raw = base64.b64decode(payload)
        try:
            return aead.decrypt(raw[:12], raw[12:], self._aad(context)).decode("utf-8")
        except InvalidTag as exc:
            raise CryptoError("No se pudo descifrar: dato alterado o contexto incorrecto") from exc

    def blind_index(self, value: str, field: str) -> str:
        return hmac.new(self._index_key, f"{field}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()

    @classmethod
    def generate(cls) -> "FieldCipher":
        """Llaves efímeras (se pierden al reiniciar): solo para pruebas y modo memoria."""
        return cls({"dev": AESGCM.generate_key(bit_length=256)}, "dev", secrets.token_bytes(32))

    @classmethod
    def from_env(cls, required: bool) -> "FieldCipher":
        active = os.getenv("DATA_ENCRYPTION_KEY", "").strip()
        index = os.getenv("BLIND_INDEX_KEY", "").strip()
        if not active or not index:
            if required:
                raise CryptoError("Faltan DATA_ENCRYPTION_KEY y/o BLIND_INDEX_KEY (genera con: python -m app.crypto)")
            warnings.warn("Sin llaves de cifrado: se usan llaves temporales (los datos no sobreviven un reinicio)")
            return cls.generate()
        kid = os.getenv("DATA_ENCRYPTION_KEY_ID", "k1").strip()
        keys = {kid: _decode_key(active, "DATA_ENCRYPTION_KEY")}
        for item in filter(None, os.getenv("DATA_ENCRYPTION_OLD_KEYS", "").split(",")):
            old_kid, _, old_key = item.strip().partition(":")
            keys[old_kid] = _decode_key(old_key, f"DATA_ENCRYPTION_OLD_KEYS[{old_kid}]")
        return cls(keys, kid, _decode_key(index, "BLIND_INDEX_KEY"))


if __name__ == "__main__":
    # Genera un juego de llaves nuevo para .env / AWS Secrets Manager
    print("DATA_ENCRYPTION_KEY=" + base64.b64encode(secrets.token_bytes(32)).decode())
    print("DATA_ENCRYPTION_KEY_ID=k1")
    print("BLIND_INDEX_KEY=" + base64.b64encode(secrets.token_bytes(32)).decode())
    print("JWT_SECRET_KEY=" + secrets.token_hex(32))
    from app.push import generate_vapid_private_key

    print("VAPID_PRIVATE_KEY=" + generate_vapid_private_key())
