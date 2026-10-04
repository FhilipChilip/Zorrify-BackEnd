"""
Persistencia NoSQL del módulo de autenticación.

- MongoAuthStore: MongoDB Atlas en producción (o el contenedor local), activado con MONGO_URI.
- InMemoryAuthStore: mismos documentos en dicts; para pruebas y desarrollo sin BD.

Colecciones (ver db/mongo-init.js para validadores e índices):
    users               cuentas, hash de contraseña, 2FA, términos, confirmación del email
                        (campos personales cifrados con app/crypto.py)
    sessions            tokens de acceso emitidos (por jti), TTL en expires_at
    auth_challenges     retos temporales (2FA, términos, confirmación del email), TTL
    push_subscriptions  navegadores suscritos a notificaciones push (cifradas)
    audit_log           eventos de seguridad, TTL de 90 días
"""

import copy
import datetime as dt
import os
import threading
from typing import Optional

AUDIT_RETENTION_DAYS = 90


class DuplicateKeyError(Exception):
    """El nombre de usuario ya existe (es el único campo único)."""

    def __init__(self, field: str):
        super().__init__(field)
        self.field = field


def _apply_update(doc: dict, set_fields: Optional[dict], inc_fields: Optional[dict]) -> None:
    """Aplica $set / $inc con rutas con punto ("mfa.enabled") sobre un dict."""
    for ops, is_inc in ((set_fields or {}, False), (inc_fields or {}, True)):
        for path, value in ops.items():
            target = doc
            *parents, leaf = path.split(".")
            for key in parents:
                target = target.setdefault(key, {})
            target[leaf] = target.get(leaf, 0) + value if is_inc else copy.deepcopy(value)


class InMemoryAuthStore:
    def __init__(self):
        self._users: dict[str, dict] = {}
        self._sessions: dict[str, dict] = {}
        self._challenges: dict[str, dict] = {}
        self._push: dict[str, dict] = {}
        self._audit: list[dict] = []
        self._lock = threading.RLock()

    # ---------------------------------------------------------------- users
    def insert_user(self, doc: dict) -> None:
        with self._lock:
            if self.find_user(username_key=doc["username_key"]):
                raise DuplicateKeyError("username")
            self._users[doc["_id"]] = copy.deepcopy(doc)

    def get_user(self, user_id: str) -> Optional[dict]:
        with self._lock:
            return copy.deepcopy(self._users.get(user_id))

    def find_user(self, username_key: str) -> Optional[dict]:
        with self._lock:
            for doc in self._users.values():
                if doc["username_key"] == username_key:
                    return copy.deepcopy(doc)
            return None

    def update_user(self, user_id: str, set_fields: Optional[dict] = None, inc_fields: Optional[dict] = None) -> Optional[dict]:
        with self._lock:
            doc = self._users.get(user_id)
            if doc is None:
                return None
            _apply_update(doc, set_fields, inc_fields)
            return copy.deepcopy(doc)

    def count_users(self) -> int:
        return len(self._users)

    # ------------------------------------------------------------- sessions
    def insert_session(self, doc: dict) -> None:
        with self._lock:
            self._sessions[doc["_id"]] = copy.deepcopy(doc)

    def get_session(self, jti: str) -> Optional[dict]:
        with self._lock:
            return copy.deepcopy(self._sessions.get(jti))

    def update_session(self, jti: str, set_fields: dict) -> None:
        with self._lock:
            if jti in self._sessions:
                _apply_update(self._sessions[jti], set_fields, None)

    def active_sessions(self, user_id: str, now: dt.datetime) -> list[dict]:
        """Sesiones vigentes del usuario, de la más antigua a la más reciente."""
        with self._lock:
            found = [
                copy.deepcopy(s) for s in self._sessions.values()
                if s["user_id"] == user_id and s["revoked_at"] is None and s["expires_at"] > now
            ]
        return sorted(found, key=lambda s: s["issued_at"])

    def count_active_sessions(self, now: dt.datetime) -> int:
        with self._lock:
            return sum(1 for s in self._sessions.values() if s["revoked_at"] is None and s["expires_at"] > now)

    # ----------------------------------------------------------- challenges
    def insert_challenge(self, doc: dict) -> None:
        with self._lock:
            self._challenges[doc["_id"]] = copy.deepcopy(doc)

    def get_challenge(self, challenge_id: str) -> Optional[dict]:
        with self._lock:
            return copy.deepcopy(self._challenges.get(challenge_id))

    def delete_challenge(self, challenge_id: str) -> None:
        with self._lock:
            self._challenges.pop(challenge_id, None)

    # --------------------------------------------------- push subscriptions
    def upsert_push_subscription(self, doc: dict) -> None:
        with self._lock:
            self._push[doc["_id"]] = copy.deepcopy(doc)

    def push_subscriptions(self, user_id: str) -> list[dict]:
        with self._lock:
            return [copy.deepcopy(d) for d in self._push.values() if d["user_id"] == user_id]

    def delete_push_subscription(self, sub_id: str) -> None:
        with self._lock:
            self._push.pop(sub_id, None)

    # ---------------------------------------------------------------- audit
    def add_audit(self, doc: dict) -> None:
        with self._lock:
            self._audit.append(copy.deepcopy(doc))

    def audit_events(self, user_id: Optional[str] = None) -> list[dict]:
        with self._lock:
            return [copy.deepcopy(e) for e in self._audit if user_id is None or e.get("user_id") == user_id]

    # ------------------------------------------------------------ limpieza
    def purge_expired(self, now: dt.datetime) -> None:
        """Equivalente manual a los índices TTL de MongoDB."""
        with self._lock:
            self._sessions = {k: v for k, v in self._sessions.items() if v["expires_at"] > now}
            self._challenges = {k: v for k, v in self._challenges.items() if v["expires_at"] > now}
            cutoff = now - dt.timedelta(days=AUDIT_RETENTION_DAYS)
            self._audit = [e for e in self._audit if e["at"] > cutoff]


class MongoAuthStore:
    def __init__(self, uri: str, db_name: str = "zorryfy"):
        # Import diferido: el modo en memoria no necesita pymongo instalado
        from pymongo import MongoClient
        from pymongo.errors import DuplicateKeyError as MongoDuplicateKeyError

        self._dup_error = MongoDuplicateKeyError
        # tz_aware: los datetime vuelven con tzinfo=UTC, igual que en memoria
        self._client = MongoClient(uri, tz_aware=True, serverSelectionTimeoutMS=5000)
        self._db = self._client[db_name]
        self.users = self._db["users"]
        self.sessions = self._db["sessions"]
        self.challenges = self._db["auth_challenges"]
        self.push = self._db["push_subscriptions"]
        self.audit = self._db["audit_log"]
        self.ensure_indexes()

    def ensure_indexes(self) -> None:
        """Idempotente; replica los índices que crea db/mongo-init.js."""
        from pymongo import ASCENDING

        self.users.create_index([("username_key", ASCENDING)], unique=True, name="uniq_username_key")
        self.sessions.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0, name="ttl_expires_at")
        self.sessions.create_index([("user_id", ASCENDING), ("issued_at", ASCENDING)], name="user_sessions")
        self.challenges.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0, name="ttl_expires_at")
        self.push.create_index([("user_id", ASCENDING)], name="user_push")
        self.audit.create_index(
            [("at", ASCENDING)], expireAfterSeconds=AUDIT_RETENTION_DAYS * 86400, name="ttl_90_days"
        )
        self.audit.create_index([("user_id", ASCENDING), ("at", ASCENDING)], name="user_events")

    # ---------------------------------------------------------------- users
    def insert_user(self, doc: dict) -> None:
        try:
            self.users.insert_one(copy.deepcopy(doc))
        except self._dup_error as exc:
            raise DuplicateKeyError("username") from exc

    def get_user(self, user_id: str) -> Optional[dict]:
        return self.users.find_one({"_id": user_id})

    def find_user(self, username_key: str) -> Optional[dict]:
        return self.users.find_one({"username_key": username_key})

    def update_user(self, user_id: str, set_fields: Optional[dict] = None, inc_fields: Optional[dict] = None) -> Optional[dict]:
        from pymongo import ReturnDocument

        update = {}
        if set_fields:
            update["$set"] = set_fields
        if inc_fields:
            update["$inc"] = inc_fields
        return self.users.find_one_and_update({"_id": user_id}, update, return_document=ReturnDocument.AFTER)

    def count_users(self) -> int:
        return self.users.estimated_document_count()

    # ------------------------------------------------------------- sessions
    def insert_session(self, doc: dict) -> None:
        self.sessions.insert_one(copy.deepcopy(doc))

    def get_session(self, jti: str) -> Optional[dict]:
        return self.sessions.find_one({"_id": jti})

    def update_session(self, jti: str, set_fields: dict) -> None:
        self.sessions.update_one({"_id": jti}, {"$set": set_fields})

    def active_sessions(self, user_id: str, now: dt.datetime) -> list[dict]:
        query = {"user_id": user_id, "revoked_at": None, "expires_at": {"$gt": now}}
        return list(self.sessions.find(query).sort("issued_at", 1))

    def count_active_sessions(self, now: dt.datetime) -> int:
        return self.sessions.count_documents({"revoked_at": None, "expires_at": {"$gt": now}})

    # ----------------------------------------------------------- challenges
    def insert_challenge(self, doc: dict) -> None:
        self.challenges.insert_one(copy.deepcopy(doc))

    def get_challenge(self, challenge_id: str) -> Optional[dict]:
        return self.challenges.find_one({"_id": challenge_id})

    def delete_challenge(self, challenge_id: str) -> None:
        self.challenges.delete_one({"_id": challenge_id})

    # --------------------------------------------------- push subscriptions
    def upsert_push_subscription(self, doc: dict) -> None:
        self.push.replace_one({"_id": doc["_id"]}, copy.deepcopy(doc), upsert=True)

    def push_subscriptions(self, user_id: str) -> list[dict]:
        return list(self.push.find({"user_id": user_id}))

    def delete_push_subscription(self, sub_id: str) -> None:
        self.push.delete_one({"_id": sub_id})

    # ---------------------------------------------------------------- audit
    def add_audit(self, doc: dict) -> None:
        self.audit.insert_one(copy.deepcopy(doc))

    def audit_events(self, user_id: Optional[str] = None) -> list[dict]:
        return list(self.audit.find({} if user_id is None else {"user_id": user_id}).sort("at", 1))

    def purge_expired(self, now: dt.datetime) -> None:
        # MongoDB lo hace solo con los índices TTL (barrido cada ~60 s)
        pass


def create_store_from_env():
    uri = os.getenv("MONGO_URI", "").strip()
    if uri:
        return MongoAuthStore(uri, os.getenv("MONGO_DB", "zorryfy"))
    return InMemoryAuthStore()
