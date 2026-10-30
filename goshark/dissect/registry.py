"""
Dynamic dissector registry keyed by DLT (link‑layer type) or other integer keys.
"""
from __future__ import annotations

from collections.abc import Callable

from .tree import ProtocolTree


class DissectorRegistry:
    """
    Simple registry mapping an integer key (usually a DLT value) to a dissector
    callable.

    A dissector has the signature::

        def dissector(pkt_bytes: bytes) -> ProtocolTree

    An optional *heuristic* callable can be supplied; it receives the same
    ``pkt_bytes`` and should return ``True`` if the dissector believes it can
    handle the packet.  The registry does **not** automatically run heuristics –
    callers may iterate over registered heuristics themselves.
    """

    def __init__(self) -> None:
        self._dissectors: dict[int, Callable[[bytes], ProtocolTree]] = {}
        self._heuristics: dict[int, Callable[[bytes], bool]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def register(
        self,
        key: int,
        fn: Callable[[bytes], ProtocolTree],
        heuristic: Callable[[bytes], bool] | None = None,
    ) -> None:
        """Register ``fn`` for ``key``.  Overwrites any existing entry."""
        self._dissectors[key] = fn
        if heuristic is not None:
            self._heuristics[key] = heuristic

    def lookup(self, key: int) -> Callable[[bytes], ProtocolTree] | None:
        """Return the dissector for *key* or ``None`` if not registered."""
        return self._dissectors.get(key)

    def heuristic(self, key: int) -> Callable[[bytes], bool] | None:
        """Return the heuristic for *key* or ``None``."""
        return self._heuristics.get(key)

    def keys(self) -> list[int]:
        """All registered keys."""
        return list(self._dissectors.keys())


# Global singleton used by the rest of the code‑base.
registry = DissectorRegistry()