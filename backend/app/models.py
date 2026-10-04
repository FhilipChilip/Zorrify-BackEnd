from dataclasses import dataclass, field, asdict
from typing import Optional
import time

from .linked_list import DoublyLinkedList


@dataclass
class Track:
    """Representa una pista de audio indexada en memoria."""

    id: str
    title: str
    artist: str
    filename: str
    size_bytes: int
    source: str  # "disk" (escaneada del directorio) o "upload" (subida por el usuario)
    duration_seconds: Optional[float] = None
    # Ruta absoluta en disco (solo para pistas escaneadas)
    path: Optional[str] = None
    added_at: float = field(default_factory=time.time)

    def to_public_dict(self) -> dict:
        # Nunca exponemos la ruta absoluta del servidor al cliente
        data = asdict(self)
        data.pop("path", None)
        data["stream_url"] = f"/api/tracks/{self.id}/stream"
        return data


@dataclass
class Playlist:
    """
    Lista de reproducción personalizada.
    Las pistas se guardan como IDs (referencias) dentro de una lista doblemente
    enlazada, de modo que reordenar con Drag & Drop solo re-enlaza punteros.
    """

    id: str
    name: str
    owner_id: str = ""
    track_ids: DoublyLinkedList = field(default_factory=DoublyLinkedList)
    # Portada opcional (bytes en memoria + tipo MIME verificado por contenido)
    cover: Optional[bytes] = None
    cover_type: Optional[str] = None
    cover_version: int = 0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
