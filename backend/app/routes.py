import re
from typing import Literal, Optional
from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from .auth import AuthError, User
from .library import LibraryError
from .main import auth, library, playback_queue, playlists, push
from .models import Playlist
from .playlists import PlaylistError
from .push import PushError

router = APIRouter()

def get_current_user(authorization: Optional[str] = Header(default=None)) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing auth")
    user = auth.verify_token(authorization[7:])
    if not user:
        raise HTTPException(401, "Invalid or expired token")
    return user

def _client(request: Request) -> tuple[Optional[str], Optional[str]]:
    return (request.client.host if request.client else None), request.headers.get("user-agent")

class RegisterRequest(BaseModel):
    username: str = Field(max_length=30)
    email: str = Field(max_length=254)
    password: str = Field(max_length=128)
    accept_terms: bool
    terms_version: str = Field(max_length=20)

class MfaConfirmRequest(BaseModel):
    setup_token: str = Field(max_length=100)
    code: str = Field(max_length=10)

class LoginRequest(BaseModel):
    username: str = Field(max_length=100, description="Nombre de usuario")
    password: str = Field(max_length=128)

class LoginVerifyRequest(BaseModel):
    mfa_token: str = Field(max_length=100)
    code: Optional[str] = Field(default=None, max_length=10)
    recovery_code: Optional[str] = Field(default=None, max_length=20)

class TermsAcceptRequest(BaseModel):
    terms_token: str = Field(max_length=100)
    accept_terms: bool
    terms_version: str = Field(max_length=20)

class PasswordRequest(BaseModel):
    password: str = Field(max_length=128)

class EmailConfirmRequest(BaseModel):
    token: str = Field(max_length=100)
    accept: bool

class EmailUpdateRequest(BaseModel):
    email: str = Field(max_length=254)

class PushKeys(BaseModel):
    p256dh: str = Field(max_length=200)
    auth: str = Field(max_length=100)

class PushSubscription(BaseModel):
    endpoint: str = Field(max_length=1024)
    keys: PushKeys

class PlaylistCreateRequest(BaseModel):
    name: str = Field(max_length=200)
    track_ids: list[str] = Field(default_factory=list, max_length=2000)

class PlaylistRenameRequest(BaseModel):
    name: str = Field(max_length=200)

class TrackIdsRequest(BaseModel):
    track_ids: list[str] = Field(max_length=2000)

class PlaylistLoadRequest(BaseModel):
    mode: Literal["replace", "append"] = "replace"

class MoveRequest(BaseModel):
    from_position: int
    to_position: int

class JumpRequest(BaseModel):
    position: int

# ----------------------------------------------------------------------
# Autenticación
# ----------------------------------------------------------------------
@router.get("/auth/config")
def auth_config():
    return auth.get_config()

@router.get("/auth/terms")
def terms():
    return auth.get_terms()

@router.post("/auth/register", status_code=201)
def register(body: RegisterRequest, request: Request):
    ip, ua = _client(request)
    try:
        return auth.register(body.username, body.email, body.password, body.accept_terms, body.terms_version, ip, ua)
    except AuthError as e:
        raise HTTPException(e.status_code, str(e))

@router.post("/auth/2fa/confirm")
def confirm_2fa(body: MfaConfirmRequest, request: Request):
    ip, ua = _client(request)
    try:
        return auth.confirm_mfa_setup(body.setup_token, body.code, ip, ua)
    except AuthError as e:
        raise HTTPException(e.status_code, str(e))

@router.post("/auth/login")
def login(body: LoginRequest, request: Request):
    ip, ua = _client(request)
    try:
        return auth.login(body.username, body.password, ip, ua)
    except AuthError as e:
        raise HTTPException(e.status_code, str(e))

@router.post("/auth/login/verify")
def login_verify(body: LoginVerifyRequest, request: Request):
    ip, ua = _client(request)
    try:
        return auth.verify_login(body.mfa_token, body.code, body.recovery_code, ip, ua)
    except AuthError as e:
        raise HTTPException(e.status_code, str(e))

@router.post("/auth/terms/accept")
def terms_accept(body: TermsAcceptRequest, request: Request):
    ip, ua = _client(request)
    try:
        return auth.accept_terms(body.terms_token, body.accept_terms, body.terms_version, ip, ua)
    except AuthError as e:
        raise HTTPException(e.status_code, str(e))

@router.post("/auth/2fa/qr")
def mfa_qr(body: PasswordRequest, request: Request, user: User = Depends(get_current_user)):
    """QR de Google Authenticator para vincular otro teléfono (pide la contraseña)."""
    ip, ua = _client(request)
    try:
        return auth.show_mfa_qr(user, body.password, ip, ua)
    except AuthError as e:
        raise HTTPException(e.status_code, str(e))

@router.post("/auth/logout")
def logout(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing auth")
    return {"revoked": auth.logout(authorization[7:])}

@router.get("/auth/me")
def me(user: User = Depends(get_current_user)):
    return user.to_public_dict()

# ----------------------------------------------------------------------
# Confirmación del email por notificación push
# ----------------------------------------------------------------------
@router.get("/api/push/public-key")
def push_public_key():
    return {"public_key": push.public_key}

@router.post("/api/push/subscribe")
def push_subscribe(body: PushSubscription, request: Request, user: User = Depends(get_current_user)):
    """Guarda el navegador y, si el email está pendiente, le envía la pregunta de confirmación."""
    _, ua = _client(request)
    try:
        push.subscribe(user.id, body.model_dump(), ua)
    except PushError as e:
        raise HTTPException(e.status_code, str(e))
    if user.email_status == "confirmed":
        return {"sent": 0, "email_status": user.email_status}
    return _send_email_confirmation(user)

@router.post("/api/email/confirmation")
def request_email_confirmation(user: User = Depends(get_current_user)):
    """Reenvía la notificación «¿Este email es tuyo?» a los navegadores suscritos."""
    return _send_email_confirmation(user)

def _send_email_confirmation(user: User) -> dict:
    try:
        payload = auth.email_confirmation_payload(user)
    except AuthError as e:
        raise HTTPException(e.status_code, str(e))
    result = push.send_to_user(user.id, payload)
    return {**result, "email_status": "pending"}

@router.post("/auth/email/confirm")
def confirm_email(body: EmailConfirmRequest, request: Request):
    """Respuesta del service worker; el token de un solo uso viaja dentro de la notificación."""
    ip, ua = _client(request)
    try:
        return auth.answer_email_confirmation(body.token, body.accept, ip, ua)
    except AuthError as e:
        raise HTTPException(e.status_code, str(e))

@router.put("/api/account/email")
def update_email(body: EmailUpdateRequest, request: Request, user: User = Depends(get_current_user)):
    ip, ua = _client(request)
    try:
        return auth.update_email(user, body.email, ip, ua).to_public_dict()
    except AuthError as e:
        raise HTTPException(e.status_code, str(e))

# ----------------------------------------------------------------------
# Biblioteca: búsqueda interactiva y subida por drag & drop
# ----------------------------------------------------------------------
@router.get("/api/library/search")
def search_library(
    q: str = Query(default="", max_length=100, description="Artista o nombre de la canción"),
    limit: int = Query(default=20, ge=1, le=100),
    user: User = Depends(get_current_user),
):
    return [t.to_public_dict() for t in library.search(q, limit)]

@router.post("/api/library/upload")
async def upload_tracks(files: list[UploadFile] = File(...), user: User = Depends(get_current_user)):
    """
    Recibe uno o varios .mp3 (arrastrados desde el explorador de archivos) y los
    añade al final de la cola. Un archivo inválido no impide subir los demás.
    """
    added, errors = [], []
    for upload in files:
        # Se lee como máximo límite+1 bytes: suficiente para detectar archivos demasiado grandes
        data = await upload.read(library.max_upload_bytes + 1)
        try:
            track = library.add_upload(upload.filename or "track.mp3", data)
        except LibraryError as e:
            errors.append({"filename": upload.filename, "error": str(e)})
            continue
        playback_queue.enqueue(track.id)
        added.append(track.to_public_dict())
    return {"added": added, "errors": errors, "queue": _queue_payload()}

# ----------------------------------------------------------------------
# Cola de reproducción (array circular)
# ----------------------------------------------------------------------
def _queue_payload() -> dict:
    snap = playback_queue.snapshot()
    tracks = [library.get(track_id) for track_id in snap["items"]]
    snap["items"] = [t.to_public_dict() for t in tracks if t is not None]
    return snap

@router.get("/api/queue")
def get_queue(user: User = Depends(get_current_user)):
    return _queue_payload()

@router.post("/api/queue/next")
def queue_next(user: User = Depends(get_current_user)):
    playback_queue.advance()
    return _queue_payload()

@router.post("/api/queue/previous")
def queue_previous(user: User = Depends(get_current_user)):
    playback_queue.rewind()
    return _queue_payload()

@router.post("/api/queue/jump")
def queue_jump(body: JumpRequest, user: User = Depends(get_current_user)):
    try:
        playback_queue.jump_to(body.position)
    except IndexError:
        raise HTTPException(400, "Invalid position")
    return _queue_payload()

@router.post("/api/queue/move")
def queue_move(body: MoveRequest, user: User = Depends(get_current_user)):
    try:
        playback_queue.move(body.from_position, body.to_position)
    except IndexError:
        raise HTTPException(400, "Invalid position")
    return _queue_payload()

@router.delete("/api/queue")
def queue_clear(user: User = Depends(get_current_user)):
    playback_queue.clear()
    return _queue_payload()

# ----------------------------------------------------------------------
# Streaming con soporte de HTTP Range (seek)
# ----------------------------------------------------------------------
_RANGE_RE = re.compile(r"bytes=(\d*)-(\d*)$")

@router.get("/api/tracks/{track_id}/stream")
def stream_track(track_id: str, range: Optional[str] = Header(default=None), user: User = Depends(get_current_user)):
    track = library.get(track_id)
    if track is None:
        raise HTTPException(404, "Track not found")
    size = track.size_bytes
    start, end, status = 0, size - 1, 200
    match = _RANGE_RE.match(range or "")
    if match and (match.group(1) or match.group(2)):
        if match.group(1):
            start = int(match.group(1))
            end = min(int(match.group(2)), size - 1) if match.group(2) else size - 1
        else:  # bytes=-N -> últimos N bytes
            start = max(0, size - int(match.group(2)))
        if start > end or start >= size:
            raise HTTPException(416, "Range not satisfiable", headers={"Content-Range": f"bytes */{size}"})
        status = 206
    headers = {"Accept-Ranges": "bytes", "Content-Length": str(end - start + 1)}
    if status == 206:
        headers["Content-Range"] = f"bytes {start}-{end}/{size}"
    return StreamingResponse(library.iter_file(track, start, end), status_code=status, media_type="audio/mpeg", headers=headers)

# ----------------------------------------------------------------------
# Playlists (cada usuario ve solo las suyas)
# ----------------------------------------------------------------------
def _playlist_summary(p: Playlist) -> dict:
    return {
        "id": p.id,
        "name": p.name,
        "track_count": len(p.track_ids),
        "cover_url": f"/api/playlists/{p.id}/cover?v={p.cover_version}" if p.cover else None,
        "created_at": p.created_at,
        "updated_at": p.updated_at,
    }

def _playlist_detail(p: Playlist) -> dict:
    tracks = [library.get(t) for t in p.track_ids]
    return {**_playlist_summary(p), "tracks": [t.to_public_dict() for t in tracks if t is not None]}

def _own_playlist(playlist_id: str, user: User) -> Playlist:
    playlist = playlists.get(playlist_id, owner_id=user.id)
    if playlist is None:
        raise HTTPException(404, "Playlist no encontrada")
    return playlist

def _playlist_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except KeyError:
        raise HTTPException(404, "Playlist no encontrada")
    except PlaylistError as e:
        raise HTTPException(400, str(e))

def _known_tracks(track_ids: list[str]) -> list[str]:
    unknown = [t for t in track_ids if not library.exists(t)]
    if unknown:
        raise HTTPException(400, "Alguna de las pistas ya no existe")
    return track_ids

@router.get("/api/playlists")
def list_playlists(user: User = Depends(get_current_user)):
    return [_playlist_summary(p) for p in playlists.all(owner_id=user.id)]

@router.post("/api/playlists", status_code=201)
def create_playlist(body: PlaylistCreateRequest, user: User = Depends(get_current_user)):
    p = _playlist_call(playlists.create, body.name, _known_tracks(body.track_ids), owner_id=user.id)
    return _playlist_detail(p)

@router.get("/api/playlists/{playlist_id}")
def get_playlist(playlist_id: str, user: User = Depends(get_current_user)):
    return _playlist_detail(_own_playlist(playlist_id, user))

@router.patch("/api/playlists/{playlist_id}")
def rename_playlist(playlist_id: str, body: PlaylistRenameRequest, user: User = Depends(get_current_user)):
    return _playlist_detail(_playlist_call(playlists.rename, playlist_id, body.name, owner_id=user.id))

@router.delete("/api/playlists/{playlist_id}", status_code=204)
def delete_playlist(playlist_id: str, user: User = Depends(get_current_user)):
    _playlist_call(playlists.delete, playlist_id, owner_id=user.id)
    return Response(status_code=204)

@router.post("/api/playlists/{playlist_id}/tracks")
def add_playlist_tracks(playlist_id: str, body: TrackIdsRequest, user: User = Depends(get_current_user)):
    p = _playlist_call(playlists.add_tracks, playlist_id, _known_tracks(body.track_ids), owner_id=user.id)
    return _playlist_detail(p)

@router.delete("/api/playlists/{playlist_id}/tracks/{position}")
def remove_playlist_track(playlist_id: str, position: int, user: User = Depends(get_current_user)):
    return _playlist_detail(_playlist_call(playlists.remove_at, playlist_id, position, owner_id=user.id))

@router.post("/api/playlists/{playlist_id}/move")
def move_playlist_track(playlist_id: str, body: MoveRequest, user: User = Depends(get_current_user)):
    p = _playlist_call(playlists.move, playlist_id, body.from_position, body.to_position, owner_id=user.id)
    return _playlist_detail(p)

@router.post("/api/playlists/{playlist_id}/load")
def load_playlist(playlist_id: str, body: PlaylistLoadRequest, user: User = Depends(get_current_user)):
    """Pasa la playlist a la cola: reemplazándola o añadiéndola al final."""
    ids = [t for t in _playlist_call(playlists.track_ids, playlist_id, owner_id=user.id) if library.exists(t)]
    if body.mode == "replace":
        playback_queue.replace_all(ids)
    else:
        for track_id in ids:
            playback_queue.enqueue(track_id)
    return _queue_payload()

@router.put("/api/playlists/{playlist_id}/cover")
async def set_playlist_cover(playlist_id: str, file: UploadFile = File(...), user: User = Depends(get_current_user)):
    data = await file.read(playlists.MAX_COVER_BYTES + 1)
    return _playlist_summary(_playlist_call(playlists.set_cover, playlist_id, data, owner_id=user.id))

@router.delete("/api/playlists/{playlist_id}/cover")
def delete_playlist_cover(playlist_id: str, user: User = Depends(get_current_user)):
    return _playlist_summary(_playlist_call(playlists.remove_cover, playlist_id, owner_id=user.id))

@router.get("/api/playlists/{playlist_id}/cover")
def get_playlist_cover(playlist_id: str, user: User = Depends(get_current_user)):
    p = _own_playlist(playlist_id, user)
    if not p.cover:
        raise HTTPException(404, "La playlist no tiene portada")
    return Response(
        content=p.cover,
        media_type=p.cover_type,
        headers={
            # El tipo se verificó por contenido; nosniff evita que el navegador lo reinterprete
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'",
            "Cache-Control": "private, max-age=86400",
        },
    )

@router.get("/health")
def health():
    return {"status": "ok"}
