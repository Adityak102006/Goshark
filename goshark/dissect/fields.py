"""
Field type definitions and Field dataclass.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Any


class FieldType(Enum):
    """Supported field types for protocol dissection."""

    UINT8 = auto()
    UINT16 = auto()
    UINT32 = auto()
    UINT64 = auto()
    INT8 = auto()
    INT16 = auto()
    INT32 = auto()
    INT64 = auto()
    STRING = auto()
    BYTES = auto()
    IPv4 = auto()
    IPv6 = auto()
    MAC = auto()
    BOOL = auto()
    ENUM = auto()


@dataclass(slots=True)
class Field:
    """
    A single dissected field.

    Attributes
    ----------
    name: Human‑readable name (e.g. "Source Port").
    ftype: Type of the field (see :class:`FieldType`).
    value: The decoded Python value.
    offset: Byte offset from the start of the raw packet.
    length: Number of bytes this field occupies.
    display: Optional pre‑formatted string for UI (e.g. "0x001A").
    """

    name: str
    ftype: FieldType
    value: Any
    offset: int
    length: int
    display: str | None = None

    def __post_init__(self) -> None:
        if self.offset < 0:
            raise ValueError("offset must be >= 0")
        if self.length <= 0:
            raise ValueError("length must be > 0")