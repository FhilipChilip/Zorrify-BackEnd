#!/bin/bash
# Zorryfy — arranque del BACKEND en una instancia EC2 (Amazon Linux 2023) con MongoDB Atlas.
#
# Pégalo en "User data" al lanzar la instancia (documentation.md §6). Antes de usarlo:
#   1. Cambia REPO_URL por la URL de tu repositorio (si es privado, usa un token de solo lectura).
#   2. Ajusta REGION y SECRET_ID si no usas us-east-1 y zorryfy/prod.
#
# Requisitos previos:
#   - Rol IAM de la instancia con secretsmanager:GetSecretValue sobre el secreto.
#   - Secreto JSON en AWS Secrets Manager con: DOMAIN, MONGO_URI, MONGO_ADMIN_URI,
#     JWT_SECRET_KEY, DATA_ENCRYPTION_KEY, BLIND_INDEX_KEY, VAPID_PRIVATE_KEY,
#     VAPID_SUBJECT, CERTBOT_EMAIL (opcionales: DEMO_MODE, CORS_ORIGINS).
#     MONGO_URI usa el usuario de la app (readWrite); MONGO_ADMIN_URI uno con dbAdmin
#     sobre la base zorryfy, solo para aplicar el esquema (validadores e índices).
#   - El DNS de DOMAIN apuntando a la IP elástica de la instancia.
#   - En Atlas (Network Access): solo la IP elástica de la instancia.
set -euo pipefail

REGION="us-east-1"
SECRET_ID="zorryfy/prod"
REPO_URL="https://github.com/FhilipChilip/Zorrify-BackEnd/tree/main"
APP_DIR=/opt/zorryfy
BACKEND_DIR="$APP_DIR/backend"

dnf install -y docker git jq
systemctl enable --now docker
mkdir -p /usr/local/lib/docker/cli-plugins
curl -fsSL "https://github.com/docker/compose/releases/download/v2.32.4/docker-compose-linux-$(uname -m)" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

if [ -d "$APP_DIR/.git" ]; then git -C "$APP_DIR" pull; else git clone --depth 1 "$REPO_URL" "$APP_DIR"; fi

# Secretos -> backend/.env (solo legible por root; nunca se guarda en el repositorio)
umask 077
aws secretsmanager get-secret-value --region "$REGION" --secret-id "$SECRET_ID" \
  --query SecretString --output text | jq -r 'to_entries[] | "\(.key)=\(.value)"' > "$BACKEND_DIR/.env"
set -a; . "$BACKEND_DIR/.env"; set +a

# Esquema de la base (idempotente): colecciones, validadores e índices en Atlas
docker run --rm -v "$BACKEND_DIR/db:/db:ro" mongo:7 mongosh "${MONGO_ADMIN_URI:-$MONGO_URI}" --quiet /db/mongo-init.js

# Primer certificado HTTPS (antes de levantar Nginx, que lo necesita para arrancar)
if [ ! -d /var/lib/docker/volumes/deploy_letsencrypt/_data/live/"$DOMAIN" ]; then
  docker run --rm -p 80:80 -v deploy_letsencrypt:/etc/letsencrypt \
    certbot/certbot:v3.0.1 certonly --standalone --non-interactive --agree-tos \
    -m "$CERTBOT_EMAIL" -d "$DOMAIN"
fi

cd "$BACKEND_DIR/deploy"
docker compose -f docker-compose.prod.yml --env-file ../.env up -d --build
