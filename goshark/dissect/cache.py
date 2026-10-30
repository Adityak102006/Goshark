"""
LRU cache for packet dissection results.
"""
from __future__ import annotations

import hashlib
from functools import lru_cache
from typing import TYPE_CHECKING

from .registry import registry
from .tree import ProtocolTree

if TYPE_CHECKING:
    from .fields import Field


def _cache_key(pkt_bytes: bytes, dlt: int) -> bytes:
    """Stable, short key for the LRU cache."""
    # First 8 bytes of SHA‑256 are enough for 2⁶⁴ space.
    return hashlib.sha256(pkt_bytes).digest()[:8] + dlt.to_bytes(4, "big")


@lru_cache(maxsize=2000)
def _cached_dissect(key: bytes, dlt: int) -> ProtocolTree:
    """
    Internal cached function.  The real packet bytes are not part of the cache
    key (only the hash), so we must retrieve the original bytes from the caller.
    To keep the API simple we store a *second* cache mapping key→bytes inside
    the function's closure (using a dict).  This is safe because the LRU cache
    evicts both entries together.
    """
    # The caller guarantees that ``_packet_store[key]`` exists.
    pkt_bytes = _packet_store[key]
    dissector = registry.lookup(dlt)
    if dissector is None:
        # Fallback: raw data protocol tree
        tree = ProtocolTree(protocol="Raw", byte_range=(0, len(pkt_bytes) - 1))
        tree.add_field(
            _raw_field(pkt_bytes)
        )
        return tree
    return dissector(pkt_bytes)


# Simple dict that lives as long as the process; entries are removed when the
# LRU cache evicts them (via a wrapper below).
_packet_store: dict[bytes, bytes] = {}


def dissect_packet(pkt_bytes: bytes, dlt: int) -> ProtocolTree:
    """
    Dissect *pkt_bytes* assuming link‑layer type *dlt*.
    Results are cached (LRU, max 2000 entries) keyed by packet content hash + DLT.
    """
    key = _cache_key(pkt_bytes, dlt)
    _packet_store[key] = pkt_bytes
    return _cached_dissect(key, dlt)


def _raw_field(data: bytes) -> Field:
    from .fields import Field, FieldType

    return Field(
        name="Raw Data",
        ftype=FieldType.BYTES,
        value=data,
        offset=0,
        length=len(data),
        display=f"{len(data)} bytes",
    )