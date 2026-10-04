// Zorryfy — base de datos NoSQL del módulo de autenticación (MongoDB Atlas / MongoDB 7).
//
// Producción (MongoDB Atlas):
//   mongosh "mongodb+srv://<admin>:<pwd>@<cluster>.mongodb.net/zorryfy" db/mongo-init.js
//   En Atlas el usuario de la app se crea desde la consola (Database Access),
//   por eso aquí solo se crea si CREATE_APP_USER=true (contenedor local).
// Desarrollo (docker-compose): se ejecuta solo al primer arranque del contenedor `mongo`.
//
// Es idempotente: crea lo que falte, actualiza validadores y borra índices obsoletos.
//
// Los campos marcados "cifrado" llegan ya cifrados por la API (AES-256-GCM,
// formato "enc:v1:<kid>:<base64>"); MongoDB nunca ve esos datos en claro.
// Nota: en este archivo se evitan barras invertidas en los patrones (en un string
// de JavaScript "\d" se convierte en "d"); se usan clases como [0-9].

const DB_NAME = process.env.MONGO_DB || "zorryfy";
const APP_USER = process.env.MONGO_APP_USER || "zorryfy_app";
const APP_PASSWORD = process.env.MONGO_APP_PASSWORD || "zorryfy_app_dev_password";

const zdb = db.getSiblingDB(DB_NAME);

const dateOrNull = { bsonType: ["date", "null"] };
const stringOrNull = { bsonType: ["string", "null"] };
const encrypted = { bsonType: "string", pattern: "^enc:v1:" };
const encryptedOrNull = { bsonType: ["string", "null"], pattern: "^enc:v1:" };

const schemas = {
  users: {
    bsonType: "object",
    required: ["_id", "username", "username_key", "email", "email_confirmation", "password", "status", "mfa", "terms", "created_at", "updated_at"],
    properties: {
      _id: { bsonType: "string", description: "uuid4 hex" },
      username: { bsonType: "string", minLength: 2, maxLength: 50, description: "nombre libre, tal como se muestra" },
      username_key: { bsonType: "string", minLength: 2, maxLength: 50, description: "nombre en minúsculas; único (login)" },
      email: { ...encrypted, description: "cifrado; no es único (varias cuentas por persona)" },
      email_confirmation: {
        bsonType: "object",
        required: ["status"],
        properties: {
          status: { enum: ["pending", "confirmed", "rejected"] },
          requested_at: dateOrNull,
          answered_at: dateOrNull,
        },
      },
      password: {
        bsonType: "object",
        required: ["algorithm", "iterations", "salt", "hash"],
        properties: {
          algorithm: { enum: ["pbkdf2_sha256"] },
          iterations: { bsonType: "int", minimum: 100000 },
          salt: { bsonType: "string", minLength: 64, maxLength: 64 },
          hash: { ...encrypted, description: "hash PBKDF2, además cifrado" },
        },
      },
      status: { enum: ["pending_2fa", "active", "disabled"] },
      mfa: {
        bsonType: "object",
        required: ["enabled", "type", "totp_secret", "recovery_codes"],
        properties: {
          enabled: { bsonType: "bool" },
          type: { enum: ["totp"] },
          totp_secret: { ...encrypted, description: "secreto TOTP cifrado" },
          last_used_step: { bsonType: ["long", "int", "null"], description: "anti-replay TOTP" },
          confirmed_at: dateOrNull,
          recovery_codes: {
            bsonType: "array",
            maxItems: 20,
            items: {
              bsonType: "object",
              required: ["hash", "used_at"],
              properties: { hash: { bsonType: "string", description: "HMAC-SHA256" }, used_at: dateOrNull },
            },
          },
        },
      },
      terms: {
        bsonType: "object",
        required: ["accepted", "version", "accepted_at"],
        properties: {
          accepted: { bsonType: "bool", description: "false solo en la cuenta demo hasta aceptar" },
          version: stringOrNull,
          accepted_at: dateOrNull,
          ip: encryptedOrNull,
          user_agent: encryptedOrNull,
        },
      },
      created_at: { bsonType: "date" },
      updated_at: { bsonType: "date" },
      last_login_at: dateOrNull,
    },
  },

  sessions: {
    bsonType: "object",
    required: ["_id", "user_id", "day", "issued_at", "expires_at", "revoked_at"],
    properties: {
      _id: { bsonType: "string", description: "jti del token" },
      user_id: { bsonType: "string" },
      day: { bsonType: "string", pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}$" },
      mfa_method: { enum: ["totp", "recovery_code"] },
      issued_at: { bsonType: "date" },
      expires_at: { bsonType: "date", description: "24 h después de emitido; índice TTL" },
      revoked_at: dateOrNull,
      revoked_reason: { enum: [null, "logout", "session_limit", "admin"] },
      ip: encryptedOrNull,
      user_agent: encryptedOrNull,
    },
  },

  auth_challenges: {
    bsonType: "object",
    required: ["_id", "user_id", "purpose", "created_at", "expires_at"],
    properties: {
      _id: { bsonType: "string", description: "SHA-256 del token opaco" },
      user_id: { bsonType: "string" },
      purpose: { enum: ["mfa_setup", "mfa_login", "terms_accept", "email_confirm"] },
      meta: { bsonType: "object" },
      created_at: { bsonType: "date" },
      expires_at: { bsonType: "date" },
    },
  },

  push_subscriptions: {
    bsonType: "object",
    required: ["_id", "user_id", "subscription", "created_at"],
    properties: {
      _id: { bsonType: "string", description: "SHA-256 de la URL del servicio push" },
      user_id: { bsonType: "string" },
      subscription: { ...encrypted, description: "endpoint + llaves del navegador, cifrado" },
      user_agent: encryptedOrNull,
      created_at: { bsonType: "date" },
    },
  },

  audit_log: {
    bsonType: "object",
    required: ["_id", "event", "at"],
    properties: {
      _id: { bsonType: "string" },
      user_id: stringOrNull,
      username: stringOrNull,
      event: {
        enum: ["register", "mfa_enabled", "login_password_ok", "login_failed", "terms_accepted",
               "login_success", "logout", "mfa_qr_viewed", "email_confirmed", "email_rejected",
               "email_changed"],
      },
      at: { bsonType: "date" },
      ip: encryptedOrNull,
      user_agent: encryptedOrNull,
      meta: { bsonType: "object" },
    },
  },
};

const existing = zdb.getCollectionNames();
for (const [name, schema] of Object.entries(schemas)) {
  const options = { validator: { $jsonSchema: schema }, validationLevel: "strict", validationAction: "error" };
  if (existing.includes(name)) {
    zdb.runCommand({ collMod: name, ...options });
  } else {
    zdb.createCollection(name, options);
  }
}

// Índices obsoletos de versiones anteriores (email único, usuario en minúsculas)
for (const old of ["uniq_email", "uniq_email_index", "uniq_username"]) {
  if (zdb.users.getIndexes().some((ix) => ix.name === old)) zdb.users.dropIndex(old);
}

// Índices (los mismos que MongoAuthStore.ensure_indexes)
zdb.users.createIndex({ username_key: 1 }, { unique: true, name: "uniq_username_key" });
zdb.sessions.createIndex({ expires_at: 1 }, { expireAfterSeconds: 0, name: "ttl_expires_at" });
zdb.sessions.createIndex({ user_id: 1, issued_at: 1 }, { name: "user_sessions" });
zdb.auth_challenges.createIndex({ expires_at: 1 }, { expireAfterSeconds: 0, name: "ttl_expires_at" });
zdb.push_subscriptions.createIndex({ user_id: 1 }, { name: "user_push" });
zdb.audit_log.createIndex({ at: 1 }, { expireAfterSeconds: 90 * 24 * 3600, name: "ttl_90_days" });
zdb.audit_log.createIndex({ user_id: 1, at: 1 }, { name: "user_events" });

// Usuario de la aplicación con permisos mínimos (solo esta base).
// En Atlas se crea desde la consola: Database Access -> rol readWrite@zorryfy.
if (process.env.CREATE_APP_USER === "true" && !zdb.getUser(APP_USER)) {
  zdb.createUser({ user: APP_USER, pwd: APP_PASSWORD, roles: [{ role: "readWrite", db: DB_NAME }] });
}

print(`Zorryfy: base '${DB_NAME}' lista (${Object.keys(schemas).join(", ")})`);
