"""
Protocol tree data structure.
"""
from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass, field

from .fields import Field


@dataclass(slots=True)
class ProtocolTree:
    """
    Hierarchical representation of a dissected packet.

    Attributes
    ----------
    protocol: Name of the protocol this node represents (e.g. "TCP").
    fields: List of :class:`Field` belonging directly to this protocol.
    children: Sub‑protocols encapsulated inside this one.
    byte_range: Inclusive (start, end) byte indices in the raw packet that this node covers.
    """

    protocol: str
    fields: list[Field] = field(default_factory=list)
    children: list[ProtocolTree] = field(default_factory=list)
    byte_range: tuple[int, int] = (0, -1)  # empty by default

    # ------------------------------------------------------------------
    # Mutating helpers
    # ------------------------------------------------------------------
    def add_field(self, fld: Field) -> None:
        """Append a field and expand byte_range to include it."""
        self.fields.append(fld)
        self._expand_range(fld.offset, fld.offset + fld.length - 1)

    def add_child(self, child: ProtocolTree) -> None:
        """Append a child protocol node and expand byte_range."""
        self.children.append(child)
        self._expand_range(child.byte_range[0], child.byte_range[1])

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------
    def walk(self) -> Generator[ProtocolTree, None, None]:
        """Depth‑first traversal yielding self then all descendants."""
        yield self
        for child in self.children:
            yield from child.walk()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _expand_range(self, start: int, end: int) -> None:
        cur_start, cur_end = self.byte_range
        if cur_start > cur_end:  # empty
            self.byte_range = (start, end)
        else:
            self.byte_range = (min(cur_start, start), max(cur_end, end))