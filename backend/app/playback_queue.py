"""
Cola de reproducción FIFO implementada sobre un array circular (ring buffer).

Punteros físicos (índices dentro del array subyacente):
    - head: posición física del elemento más antiguo (el que sale primero, FIFO).
    - tail: posición física donde se insertará el próximo elemento.
    - size: cantidad de elementos válidos.

Punteros lógicos de reproducción (posiciones relativas a head, 0..size-1):
    - cursor: pista actual.
    - previous = cursor - 1  (o None si no existe)
    - next     = cursor + 1  (o None si no existe)

Las pistas anteriores al cursor forman el historial. Cuando el historial supera
`history_limit`, se desencolan (dequeue) desde head, respetando FIFO.
"""

import threading
from typing import Optional


class PlaybackQueue:
    INITIAL_CAPACITY = 8

    def __init__(self, history_limit: int = 50):
        # Array de tamaño fijo; se duplica cuando se llena
        self._buffer: list[Optional[str]] = [None] * self.INITIAL_CAPACITY
        self._head = 0
        self._tail = 0
        self._size = 0
        # -1 significa "no hay pista actual"
        self._cursor = -1
        self._history_limit = history_limit
        # Bloqueo: FastAPI ejecuta endpoints síncronos en un pool de hilos
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Utilidades internas sobre el array circular
    # ------------------------------------------------------------------
    @property
    def _capacity(self) -> int:
        return len(self._buffer)

    def _physical(self, logical: int) -> int:
        # Convierte una posición lógica (0 = head) en índice físico del array
        return (self._head + logical) % self._capacity

    def _check_position(self, position: int) -> None:
        if not 0 <= position < self._size:
            raise IndexError(f"Position {position} out of range (size={self._size})")

    def _grow(self) -> None:
        # Duplica la capacidad y re-linealiza los elementos empezando en 0
        new_buffer: list[Optional[str]] = [None] * (self._capacity * 2)
        for i in range(self._size):
            new_buffer[i] = self._buffer[self._physical(i)]
        self._buffer = new_buffer
        self._head = 0
        self._tail = self._size

    def _to_list(self) -> list[str]:
        return [self._buffer[self._physical(i)] for i in range(self._size)]  # type: ignore[misc]

    def _rebuild(self, items: list[str]) -> None:
        # Reescribe el array completo a partir de una lista lógica ordenada
        capacity = self.INITIAL_CAPACITY
        while capacity < len(items) + 1:
            capacity *= 2
        self._buffer = [None] * capacity
        for i, track_id in enumerate(items):
            self._buffer[i] = track_id
        self._head = 0
        self._size = len(items)
        self._tail = self._size % capacity

    # ------------------------------------------------------------------
    # Operaciones FIFO básicas
    # ------------------------------------------------------------------
    def enqueue(self, track_id: str) -> None:
        """Inserta al final (tail). Complejidad amortizada O(1)."""
        with self._lock:
            if self._size == self._capacity:
                self._grow()
            self._buffer[self._tail] = track_id
            self._tail = (self._tail + 1) % self._capacity
            self._size += 1
            # Si la cola estaba vacía, la nueva pista pasa a ser la actual
            if self._cursor == -1:
                self._cursor = 0

    def dequeue(self) -> Optional[str]:
        """Extrae el elemento más antiguo (head). Complejidad O(1)."""
        with self._lock:
            if self._size == 0:
                return None
            track_id = self._buffer[self._head]
            self._buffer[self._head] = None
            self._head = (self._head + 1) % self._capacity
            self._size -= 1
            # Todas las posiciones lógicas se desplazan una unidad hacia atrás
            if self._size == 0:
                self._cursor = -1
            elif self._cursor > 0:
                self._cursor -= 1
            # Si cursor era 0 se eliminó la pista actual: la siguiente toma su lugar
            return track_id

    def peek(self) -> Optional[str]:
        with self._lock:
            return self._buffer[self._head] if self._size else None

    def clear(self) -> None:
        with self._lock:
            self._rebuild([])
            self._cursor = -1

    def __len__(self) -> int:
        return self._size

    # ------------------------------------------------------------------
    # Navegación con punteros (actual / anterior / siguiente)
    # ------------------------------------------------------------------
    def current(self) -> Optional[str]:
        with self._lock:
            return self._buffer[self._physical(self._cursor)] if self._cursor >= 0 else None

    def advance(self) -> Optional[str]:
        """Mueve el cursor a la siguiente pista y recorta el historial (FIFO)."""
        with self._lock:
            if self._cursor < 0 or self._cursor + 1 >= self._size:
                return None
            self._cursor += 1
            self._trim_history()
            return self.current()

    def rewind(self) -> Optional[str]:
        """Mueve el cursor a la pista anterior, si existe."""
        with self._lock:
            if self._cursor <= 0:
                return None
            self._cursor -= 1
            return self.current()

    def jump_to(self, position: int) -> str:
        with self._lock:
            self._check_position(position)
            self._cursor = position
            self._trim_history()
            return self.current()  # type: ignore[return-value]

    def _trim_history(self) -> None:
        # Desencola por head las pistas ya reproducidas que excedan el límite
        while self._cursor > self._history_limit:
            self.dequeue()

    # ------------------------------------------------------------------
    # Edición (usada por el drag & drop del frontend)
    # ------------------------------------------------------------------
    def move(self, from_position: int, to_position: int) -> None:
        """Reordena una pista conservando el puntero sobre la pista actual."""
        with self._lock:
            self._check_position(from_position)
            self._check_position(to_position)
            if from_position == to_position:
                return
            items = self._to_list()
            item = items.pop(from_position)
            items.insert(to_position, item)

            # Recalcula el cursor para que siga apuntando a la MISMA pista tras el reordenamiento
            cursor = self._cursor
            if cursor == from_position:
                cursor = to_position
            elif from_position < cursor <= to_position:
                cursor -= 1
            elif to_position <= cursor < from_position:
                cursor += 1

            self._rebuild(items)
            self._cursor = cursor

    def remove_at(self, position: int) -> str:
        with self._lock:
            self._check_position(position)
            if position == 0:
                return self.dequeue()  # type: ignore[return-value]
            items = self._to_list()
            removed = items.pop(position)
            cursor = self._cursor
            if position < cursor:
                cursor -= 1
            elif position == cursor and cursor >= len(items):
                # Se eliminó la última pista y era la actual: retrocede
                cursor = len(items) - 1
            self._rebuild(items)
            self._cursor = cursor if items else -1
            return removed

    def remove_track_everywhere(self, track_id: str) -> None:
        # Usado cuando una pista se elimina de la biblioteca
        with self._lock:
            position = 0
            while position < self._size:
                if self._buffer[self._physical(position)] == track_id:
                    self.remove_at(position)
                else:
                    position += 1

    def replace_all(self, track_ids: list[str]) -> None:
        with self._lock:
            self._rebuild(list(track_ids))
            self._cursor = 0 if track_ids else -1

    # ------------------------------------------------------------------
    # Instantánea del estado para la API
    # ------------------------------------------------------------------
    def snapshot(self) -> dict:
        with self._lock:
            cursor = self._cursor
            return {
                "items": self._to_list(),
                "pointers": {
                    "current": cursor if cursor >= 0 else None,
                    "previous": cursor - 1 if cursor > 0 else None,
                    "next": cursor + 1 if 0 <= cursor < self._size - 1 else None,
                },
                "buffer": {
                    # Vista física del array: permite visualizar head/tail y el "wrap-around"
                    "slots": list(self._buffer),
                    "head": self._head,
                    "tail": self._tail,
                    "size": self._size,
                    "capacity": self._capacity,
                    "history_limit": self._history_limit,
                },
            }
