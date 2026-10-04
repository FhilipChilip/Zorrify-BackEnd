"""
Gestor de playlists en memoria.

- Índice: diccionario {playlist_id: Playlist} -> búsqueda O(1).
- Contenido de cada playlist: DoublyLinkedList de IDs de pista.
- Cada playlist pertenece a un usuario: nadie puede ver ni tocar las de otro
  (para un tercero una playlist ajena simplemente "no existe").
- Portada opcional: JPG, PNG o WebP de hasta 2 MB, validada por su contenido
  (no por la extensión). SVG no se acepta porque puede contener scripts.
"""

import threading
import time
import uuid
from typing import Optional

from .linked_list import DoublyLinkedList
from .models import Playlist


class PlaylistError(Exception):
    pass


def detect_image_type(data: bytes) -> Optional[str]:
    """Tipo MIME según la firma del archivo, o None si no es una imagen permitida."""
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


class PlaylistManager:
    MAX_NAME_LENGTH = 80
    MAX_TRACKS = 2000
    MAX_PLAYLISTS_PER_USER = 200
    MAX_COVER_BYTES = 2 * 1024 * 1024

    def __init__(self):
        self._playlists: dict[str, Playlist] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Utilidades internas
    # ------------------------------------------------------------------
    def _validate_name(self, name: str) -> str:
        clean = " ".join((name or "").split())
        if not clean:
            raise PlaylistError("Ponle un nombre a la playlist")
        if len(clean) > self.MAX_NAME_LENGTH:
            raise PlaylistError(f"El nombre admite hasta {self.MAX_NAME_LENGTH} caracteres")
        return clean

    def _require(self, playlist_id: str, owner_id: Optional[str] = None) -> Playlist:
        playlist = self._playlists.get(playlist_id)
        if playlist is None or (owner_id is not None and playlist.owner_id != owner_id):
            raise KeyError(playlist_id)
        return playlist

    def _ensure_capacity(self, playlist: Playlist, extra: int) -> None:
        if len(playlist.track_ids) + extra > self.MAX_TRACKS:
            raise PlaylistError(f"Una playlist admite hasta {self.MAX_TRACKS} pistas")

    @staticmethod
    def _touch(playlist: Playlist) -> None:
        playlist.updated_at = time.time()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------
    def all(self, owner_id: Optional[str] = None) -> list[Playlist]:
        with self._lock:
            found = [p for p in self._playlists.values() if owner_id is None or p.owner_id == owner_id]
            return sorted(found, key=lambda p: p.created_at)

    def get(self, playlist_id: str, owner_id: Optional[str] = None) -> Optional[Playlist]:
        try:
            return self._require(playlist_id, owner_id)
        except KeyError:
            return None

    def track_ids(self, playlist_id: str, owner_id: Optional[str] = None) -> list[str]:
        # Copia inmutable para lectores (evita iterar la lista mientras otro hilo la modifica)
        with self._lock:
            return self._require(playlist_id, owner_id).track_ids.to_list()

    def create(self, name: str, track_ids: Optional[list[str]] = None, owner_id: str = "") -> Playlist:
        with self._lock:
            if owner_id and len(self.all(owner_id)) >= self.MAX_PLAYLISTS_PER_USER:
                raise PlaylistError(f"Puedes tener hasta {self.MAX_PLAYLISTS_PER_USER} playlists")
            ids = list(track_ids or [])
            if len(ids) > self.MAX_TRACKS:
                raise PlaylistError(f"Una playlist admite hasta {self.MAX_TRACKS} pistas")
            playlist = Playlist(
                id=uuid.uuid4().hex[:12],
                name=self._validate_name(name),
                owner_id=owner_id,
                track_ids=DoublyLinkedList(ids),
            )
            self._playlists[playlist.id] = playlist
            return playlist

    def rename(self, playlist_id: str, name: str, owner_id: Optional[str] = None) -> Playlist:
        with self._lock:
            playlist = self._require(playlist_id, owner_id)
            playlist.name = self._validate_name(name)
            self._touch(playlist)
            return playlist

    def delete(self, playlist_id: str, owner_id: Optional[str] = None) -> None:
        with self._lock:
            self._require(playlist_id, owner_id).track_ids.clear()
            del self._playlists[playlist_id]

    # ------------------------------------------------------------------
    # Portada
    # ------------------------------------------------------------------
    def set_cover(self, playlist_id: str, data: bytes, owner_id: Optional[str] = None) -> Playlist:
        if len(data) > self.MAX_COVER_BYTES:
            raise PlaylistError("La imagen supera 2 MB")
        mime = detect_image_type(data)
        if mime is None:
            raise PlaylistError("La portada debe ser una imagen JPG, PNG o WebP")
        with self._lock:
            playlist = self._require(playlist_id, owner_id)
            playlist.cover = data
            playlist.cover_type = mime
            playlist.cover_version += 1
            self._touch(playlist)
            return playlist

    def remove_cover(self, playlist_id: str, owner_id: Optional[str] = None) -> Playlist:
        with self._lock:
            playlist = self._require(playlist_id, owner_id)
            playlist.cover = None
            playlist.cover_type = None
            playlist.cover_version += 1
            self._touch(playlist)
            return playlist

    # ------------------------------------------------------------------
    # Edición del contenido
    # ------------------------------------------------------------------
    def add_tracks(self, playlist_id: str, track_ids: list[str], owner_id: Optional[str] = None) -> Playlist:
        with self._lock:
            playlist = self._require(playlist_id, owner_id)
            self._ensure_capacity(playlist, len(track_ids))
            playlist.track_ids.extend(track_ids)  # cada append es O(1) gracias al puntero tail
            self._touch(playlist)
            return playlist

    def remove_at(self, playlist_id: str, position: int, owner_id: Optional[str] = None) -> Playlist:
        with self._lock:
            playlist = self._require(playlist_id, owner_id)
            try:
                playlist.track_ids.pop(position)
            except IndexError:
                raise PlaylistError("Posición fuera de rango")
            self._touch(playlist)
            return playlist

    def move(self, playlist_id: str, from_position: int, to_position: int, owner_id: Optional[str] = None) -> Playlist:
        # Usado por el Drag & Drop: solo se re-enlazan punteros prev/next
        with self._lock:
            playlist = self._require(playlist_id, owner_id)
            try:
                playlist.track_ids.move(from_position, to_position)
            except IndexError:
                raise PlaylistError("Posición fuera de rango")
            self._touch(playlist)
            return playlist

    def remove_track_everywhere(self, track_id: str) -> None:
        # Limpieza de referencias cuando una pista desaparece de la biblioteca
        with self._lock:
            for playlist in self._playlists.values():
                if playlist.track_ids.remove_all(track_id):
                    self._touch(playlist)
