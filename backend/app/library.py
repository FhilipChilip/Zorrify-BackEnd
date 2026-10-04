"""
Biblioteca de pistas en memoria.

- Las pistas escaneadas guardan solo la ruta en disco (los bytes se leen al reproducir).
- Las pistas subidas se guardan como `bytes` en un diccionario en memoria.
Ambos índices son diccionarios nativos de Python (búsqueda O(1) por ID).
"""

import hashlib
import io
import os
import threading
import unicodedata
import uuid
from pathlib import Path
from typing import Optional

from .models import Track

try:  # mutagen es opcional: solo se usa para leer etiquetas ID3 y duración
    from mutagen.mp3 import MP3  # type: ignore
except ImportError:  # pragma: no cover
    MP3 = None


SUPPORTED_EXTENSIONS = {".mp3"}


def _normalize(text: str) -> str:
    """Minúsculas y sin tildes para comparar ("Canción" == "cancion")."""
    decomposed = unicodedata.normalize("NFKD", text.lower())
    return "".join(c for c in decomposed if not unicodedata.combining(c))


class LibraryError(Exception):
    pass


def _looks_like_mp3(head: bytes) -> bool:
    # Cabecera ID3v2 o sincronización de trama MPEG (11 bits a 1)
    return head.startswith(b"ID3") or (len(head) >= 2 and head[0] == 0xFF and (head[1] & 0xE0) == 0xE0)


def _metadata_from_filename(filename: str) -> tuple[str, str]:
    # Convención "Artista - Título.mp3"; si no se cumple, artista desconocido
    stem = Path(filename).stem.replace("_", " ").strip()
    if " - " in stem:
        artist, title = stem.split(" - ", 1)
        return title.strip(), artist.strip()
    return stem, "Unknown artist"


def _read_tags(source) -> tuple[Optional[str], Optional[str], Optional[float]]:
    if MP3 is None:
        return None, None, None
    try:
        audio = MP3(source)
        tags = audio.tags or {}
        title = str(tags["TIT2"]) if "TIT2" in tags else None
        artist = str(tags["TPE1"]) if "TPE1" in tags else None
        return title, artist, round(audio.info.length, 2)
    except Exception:
        return None, None, None


class TrackLibrary:
    def __init__(self, music_root: Path, max_upload_bytes: int, max_total_upload_bytes: int):
        self.music_root = music_root.resolve()
        self.max_upload_bytes = max_upload_bytes
        self.max_total_upload_bytes = max_total_upload_bytes
        self._tracks: dict[str, Track] = {}
        self._upload_blobs: dict[str, bytes] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Consultas
    # ------------------------------------------------------------------
    def all(self) -> list[Track]:
        with self._lock:
            return sorted(self._tracks.values(), key=lambda t: (t.artist.lower(), t.title.lower()))

    def get(self, track_id: str) -> Optional[Track]:
        return self._tracks.get(track_id)

    def exists(self, track_id: str) -> bool:
        return track_id in self._tracks

    def search(self, query: str, limit: Optional[int] = None) -> list[Track]:
        """
        Búsqueda interactiva (mientras se escribe) por artista o nombre de canción.

        - Sin distinguir mayúsculas ni tildes ("cancion" encuentra "Canción").
        - Cada palabra debe aparecer en el artista o en el título
          ("queen bohemian" -> artista Queen + título Bohemian Rhapsody).
        - Orden por relevancia: empieza igual > alguna palabra empieza igual > contiene.
        """
        words = _normalize(query).split()
        if not words:
            return self.all()[:limit]
        needle = " ".join(words)
        ranked = []
        for track in self.all():
            artist, title = _normalize(track.artist), _normalize(track.title)
            haystack = f"{artist} {title}"
            if not all(w in haystack for w in words):
                continue
            if artist.startswith(needle) or title.startswith(needle):
                score = 0
            elif all(any(part.startswith(w) for part in haystack.split()) for w in words):
                score = 1
            else:
                score = 2
            ranked.append((score, track))
        ranked.sort(key=lambda item: item[0])  # estable: conserva artista/título
        return [track for _, track in ranked][:limit]

    # ------------------------------------------------------------------
    # Escaneo de directorio
    # ------------------------------------------------------------------
    def resolve_scan_directory(self, relative: str) -> Path:
        # Solo se permite escanear dentro de MUSIC_ROOT (evita recorrer todo el servidor)
        target = (self.music_root / relative).resolve()
        if target != self.music_root and self.music_root not in target.parents:
            raise LibraryError("Directory must be inside the configured music root")
        if not target.is_dir():
            raise LibraryError("Directory not found")
        return target

    def scan(self, relative: str = "") -> dict:
        directory = self.resolve_scan_directory(relative)
        added, found = 0, 0
        for root, _dirs, files in os.walk(directory):
            for name in files:
                if Path(name).suffix.lower() not in SUPPORTED_EXTENSIONS:
                    continue
                found += 1
                full_path = Path(root) / name
                # ID estable derivado de la ruta: re-escanear no duplica pistas
                track_id = "d_" + hashlib.sha1(str(full_path).encode("utf-8")).hexdigest()[:16]
                with self._lock:
                    if track_id in self._tracks:
                        continue
                tag_title, tag_artist, duration = _read_tags(str(full_path))
                file_title, file_artist = _metadata_from_filename(name)
                track = Track(
                    id=track_id,
                    title=tag_title or file_title,
                    artist=tag_artist or file_artist,
                    filename=name,
                    size_bytes=full_path.stat().st_size,
                    source="disk",
                    duration_seconds=duration,
                    path=str(full_path),
                )
                with self._lock:
                    self._tracks[track_id] = track
                added += 1
        return {"found": found, "added": added, "total": len(self._tracks)}

    def list_subdirectories(self) -> list[str]:
        result = [""]
        for root, dirs, _files in os.walk(self.music_root):
            for d in dirs:
                result.append(str((Path(root) / d).relative_to(self.music_root)).replace("\\", "/"))
        return sorted(result)

    # ------------------------------------------------------------------
    # Subida de archivos (se almacenan en memoria)
    # ------------------------------------------------------------------
    def _uploaded_total(self) -> int:
        return sum(len(b) for b in self._upload_blobs.values())

    def add_upload(self, filename: str, data: bytes) -> Track:
        safe_name = Path(filename or "track.mp3").name
        if Path(safe_name).suffix.lower() not in SUPPORTED_EXTENSIONS:
            raise LibraryError(f"{safe_name}: only .mp3 files are allowed")
        if len(data) > self.max_upload_bytes:
            raise LibraryError(f"{safe_name}: file exceeds the per-file size limit")
        if not _looks_like_mp3(data[:4]):
            raise LibraryError(f"{safe_name}: content is not a valid MP3 file")

        with self._lock:
            if self._uploaded_total() + len(data) > self.max_total_upload_bytes:
                raise LibraryError("In-memory upload storage is full")
            tag_title, tag_artist, duration = _read_tags(io.BytesIO(data))
            file_title, file_artist = _metadata_from_filename(safe_name)
            track = Track(
                id="u_" + uuid.uuid4().hex[:16],
                title=tag_title or file_title,
                artist=tag_artist or file_artist,
                filename=safe_name,
                size_bytes=len(data),
                source="upload",
                duration_seconds=duration,
            )
            self._tracks[track.id] = track
            self._upload_blobs[track.id] = data
            return track

    def remove(self, track_id: str) -> bool:
        with self._lock:
            self._upload_blobs.pop(track_id, None)
            return self._tracks.pop(track_id, None) is not None

    # ------------------------------------------------------------------
    # Lectura de bytes para streaming con soporte de rangos HTTP
    # ------------------------------------------------------------------
    def read_range(self, track: Track, start: int, end: int) -> bytes:
        # `end` es inclusivo, igual que en la cabecera Range
        if track.source == "upload":
            return self._upload_blobs[track.id][start : end + 1]
        with open(track.path, "rb") as fh:  # type: ignore[arg-type]
            fh.seek(start)
            return fh.read(end - start + 1)

    def iter_file(self, track: Track, start: int, end: int, chunk_size: int = 64 * 1024):
        # Generador por bloques para no cargar archivos grandes completos en memoria
        if track.source == "upload":
            blob = self._upload_blobs[track.id]
            for offset in range(start, end + 1, chunk_size):
                yield blob[offset : min(offset + chunk_size, end + 1)]
            return
        with open(track.path, "rb") as fh:  # type: ignore[arg-type]
            fh.seek(start)
            remaining = end - start + 1
            while remaining > 0:
                chunk = fh.read(min(chunk_size, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk
