"""
Lista doblemente enlazada (Doubly Linked List) usada por las playlists.

Cada nodo guarda dos punteros:
    prev -> nodo anterior (None si es la cabeza)
    next -> nodo siguiente (None si es la cola)

La lista mantiene además dos punteros de extremo:
    head -> primer nodo
    tail -> último nodo

Invariantes que SIEMPRE deben cumplirse (verificadas por `check_integrity`):
    1. head.prev is None y tail.next is None
    2. Para todo nodo n con n.next: n.next.prev is n
    3. Recorrer desde head visita exactamente `size` nodos y termina en tail
    4. Lista vacía  <=> head is None and tail is None and size == 0
"""

from typing import Any, Iterator, Optional


class _Node:
    # __slots__ reduce el consumo de memoria por nodo
    __slots__ = ("value", "prev", "next")

    def __init__(self, value: Any):
        self.value = value
        self.prev: Optional["_Node"] = None
        self.next: Optional["_Node"] = None


class DoublyLinkedList:
    def __init__(self, values=None):
        self._head: Optional[_Node] = None
        self._tail: Optional[_Node] = None
        self._size = 0
        for value in values or []:
            self.append(value)

    # ------------------------------------------------------------------
    # Primitivas de enlace: son las ÚNICAS que modifican punteros
    # ------------------------------------------------------------------
    def _link_last(self, node: _Node) -> None:
        # Engancha el nodo después de la cola actual: O(1)
        node.prev = self._tail
        node.next = None
        if self._tail is None:
            self._head = node  # la lista estaba vacía
        else:
            self._tail.next = node
        self._tail = node
        self._size += 1

    def _link_before(self, node: _Node, ref: _Node) -> None:
        # Inserta `node` justo antes de `ref`: O(1)
        node.prev = ref.prev
        node.next = ref
        if ref.prev is None:
            self._head = node  # ref era la cabeza
        else:
            ref.prev.next = node
        ref.prev = node
        self._size += 1

    def _unlink(self, node: _Node) -> Any:
        # Desengancha el nodo reconectando a sus vecinos entre sí: O(1)
        if node.prev is None:
            self._head = node.next
        else:
            node.prev.next = node.next
        if node.next is None:
            self._tail = node.prev
        else:
            node.next.prev = node.prev
        # Se limpian los punteros del nodo suelto para evitar referencias colgantes
        node.prev = node.next = None
        self._size -= 1
        return node.value

    def _node_at(self, index: int) -> _Node:
        # Recorre desde el extremo más cercano: O(min(i, n - i))
        if not 0 <= index < self._size:
            raise IndexError(f"Index {index} out of range (size={self._size})")
        if index < self._size // 2:
            node = self._head
            for _ in range(index):
                node = node.next  # type: ignore[union-attr]
        else:
            node = self._tail
            for _ in range(self._size - 1 - index):
                node = node.prev  # type: ignore[union-attr]
        return node  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # API pública (semántica equivalente a list de Python)
    # ------------------------------------------------------------------
    def append(self, value: Any) -> None:
        self._link_last(_Node(value))

    def extend(self, values) -> None:
        for value in values:
            self.append(value)

    def insert(self, index: int, value: Any) -> None:
        # index == size equivale a append (insertar al final)
        if not 0 <= index <= self._size:
            raise IndexError(f"Index {index} out of range for insert (size={self._size})")
        if index == self._size:
            self._link_last(_Node(value))
        else:
            self._link_before(_Node(value), self._node_at(index))

    def pop(self, index: int) -> Any:
        return self._unlink(self._node_at(index))

    def get(self, index: int) -> Any:
        return self._node_at(index).value

    def move(self, from_index: int, to_index: int) -> None:
        """
        Mueve un elemento re-enlazando su nodo (no se crean ni copian nodos).
        Semántica idéntica a: item = lst.pop(from_index); lst.insert(to_index, item)
        """
        if not 0 <= from_index < self._size:
            raise IndexError(f"from_index {from_index} out of range (size={self._size})")
        if not 0 <= to_index < self._size:
            raise IndexError(f"to_index {to_index} out of range (size={self._size})")
        if from_index == to_index:
            return
        node = self._node_at(from_index)
        self._unlink(node)
        # Tras desenganchar, la lista tiene size-1 nodos; to_index == size => al final
        if to_index == self._size:
            self._link_last(node)
        else:
            self._link_before(node, self._node_at(to_index))

    def remove_all(self, value: Any) -> int:
        """Elimina todas las apariciones de `value` en una sola pasada. Devuelve cuántas."""
        removed = 0
        node = self._head
        while node is not None:
            following = node.next  # se guarda antes de desenganchar
            if node.value == value:
                self._unlink(node)
                removed += 1
            node = following
        return removed

    def clear(self) -> None:
        # Rompe los enlaces explícitamente para ayudar al recolector de basura
        node = self._head
        while node is not None:
            following = node.next
            node.prev = node.next = None
            node = following
        self._head = self._tail = None
        self._size = 0

    def __len__(self) -> int:
        return self._size

    def __iter__(self) -> Iterator[Any]:
        node = self._head
        while node is not None:
            yield node.value
            node = node.next

    def __reversed__(self) -> Iterator[Any]:
        node = self._tail
        while node is not None:
            yield node.value
            node = node.prev

    def __contains__(self, value: Any) -> bool:
        return any(v == value for v in self)

    def to_list(self) -> list:
        return list(self)

    def __repr__(self) -> str:
        return "DoublyLinkedList([" + " <-> ".join(repr(v) for v in self) + "])"

    # ------------------------------------------------------------------
    # Verificación de invariantes (usada intensivamente en los tests)
    # ------------------------------------------------------------------
    def check_integrity(self) -> None:
        if self._size == 0:
            assert self._head is None and self._tail is None, "empty list must have no head/tail"
            return
        assert self._head is not None and self._tail is not None
        assert self._head.prev is None, "head.prev must be None"
        assert self._tail.next is None, "tail.next must be None"
        count, node, last = 0, self._head, None
        while node is not None:
            assert node.prev is last, f"broken back-pointer at position {count}"
            last, node = node, node.next
            count += 1
            assert count <= self._size, "cycle detected or size too small"
        assert last is self._tail, "forward traversal must end at tail"
        assert count == self._size, f"size mismatch: counted {count}, stored {self._size}"
