"""
API de Zorryfy (FastAPI).

El frontend vive en ../frontend y es independiente. En desarrollo, si esa
carpeta existe, esta misma app lo sirve (/, /sw.js, /static) para trabajar con
un solo proceso. En producción el backend se despliega solo (la imagen Docker no
incluye el frontend) y el frontend se publica aparte en el mismo dominio.

    SERVE_FRONTEND=auto|true|false   (auto: servirlo si la carpeta existe)
    FRONTEND_DIR=<ruta>              (por defecto ../frontend)
    CORS_ORIGINS=https://a.com,...   (solo si el frontend está en OTRO dominio)
"""

import os
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from .auth import AuthManager
from .auth_store import create_store_from_env
from .crypto import FieldCipher
from .library import TrackLibrary
from .playback_queue import PlaybackQueue
from .playlists import PlaylistManager
from .push import PushService

BASE_DIR = Path(__file__).resolve().parent.parent          # backend/
FRONTEND_DIR = Path(os.getenv("FRONTEND_DIR", str(BASE_DIR.parent / "frontend"))).resolve()
_serve = os.getenv("SERVE_FRONTEND", "auto").lower()
SERVE_FRONTEND = _serve == "true" or (_serve == "auto" and (FRONTEND_DIR / "index.html").is_file())
MUSIC_ROOT = Path(os.getenv("MUSIC_ROOT", str(BASE_DIR / "music")))
MUSIC_ROOT.mkdir(parents=True, exist_ok=True)

MB = 1024 * 1024
library = TrackLibrary(
    MUSIC_ROOT,
    int(os.getenv("MAX_UPLOAD_MB", "25")) * MB,
    int(os.getenv("MAX_TOTAL_UPLOAD_MB", "200")) * MB,
)
playback_queue = PlaybackQueue(history_limit=50)
playlists = PlaylistManager()
# MONGO_URI definido -> MongoDB Atlas; si no, almacén en memoria (desarrollo/pruebas).
# Con base de datos persistente las llaves de cifrado son obligatorias.
auth = AuthManager(
    create_store_from_env(),
    cipher=FieldCipher.from_env(required=bool(os.getenv("MONGO_URI", "").strip())),
)
auth.ensure_demo_user()
# Notificaciones push para confirmar el email (llaves VAPID en VAPID_PRIVATE_KEY)
push = PushService.from_env(auth.store, auth.cipher)

@asynccontextmanager
async def lifespan(_):
    if os.getenv("SCAN_ON_STARTUP", "true").lower() == "true":
        library.scan("")
    yield

app = FastAPI(title="Zorryfy API", version="1.2.0", lifespan=lifespan)

# CORS solo hace falta si el frontend se publica en otro dominio (por defecto, mismo dominio)
_cors = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
if _cors:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "Range"],
        expose_headers=["Content-Range", "Accept-Ranges"],
    )

from .routes import router
app.include_router(router)

if SERVE_FRONTEND:
    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(FRONTEND_DIR / "index.html")

    @app.get("/sw.js", include_in_schema=False)
    def service_worker():
        # Servido desde la raíz para que controle todo el sitio (alcance "/")
        return FileResponse(FRONTEND_DIR / "sw.js", media_type="application/javascript", headers={"Cache-Control": "no-cache"})

    @app.get("/login", include_in_schema=False)
    def login_page():
        # El login es un modal dentro de la interfaz principal
        return RedirectResponse("/")

    app.mount("/static", StaticFiles(directory=FRONTEND_DIR / "static"), name="static")
else:
    @app.get("/", include_in_schema=False)
    def api_root():
        return {"service": "zorryfy-api", "status": "ok", "health": "/health"}
