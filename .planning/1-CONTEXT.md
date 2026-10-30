# Phase 1 – Registry & Field Model — CONTEXT.md

## Decisions Locked

| Area | Decision |
|------|----------|
| **DissectorRegistry** | `class DissectorRegistry:`<br>`    def __init__(self): self._by_dlt = {}`<br>`    def register(self, dlt: int, fn: Callable[[bytes], ProtocolTree], heuristic: Callable[[bytes], bool] | None = None): …`<br>`    def lookup(self, dlt: int) -> Callable[[bytes], ProtocolTree] | None: …`<br>Registry lives in `goshark/dissect/registry.py`. Single global instance `registry = DissectorRegistry()`. |
| **Field model** | `@dataclass(slots=True) class Field:`<br>`    name: str`<br>`    ftype: FieldType   # Enum: UINT8, UINT16, UINT32, UINT64, INT8…, STRING, BYTES, IPv4, IPv6, MAC, BOOL, ENUM`<br>`    value: Any`<br>`    offset: int   # byte offset in raw packet`<br>`    length: int   # byte length`<br>`    display: str | None = None  # optional formatted string`<br>Defined in `goshark/dissect/fields.py`. |
| **ProtocolTree** | `@dataclass(slots=True) class ProtocolTree:`<br>`    protocol: str`<br>`    fields: list[Field]`<br>`    children: list[ProtocolTree]`<br>`    byte_range: tuple[int, int]  # (start, end) inclusive`<br>Methods: `add_field`, `add_child`, `walk()` generator. |
| **Lazy dissection & cache** | `PacketTableModel` gets a `dissect_packet(pkt_bytes: bytes, dlt: int) -> ProtocolTree` function.<br>Cache: `functools.lru_cache(maxsize=2000)` keyed by `(packet_index, dlt)`. Cache lives in `goshark/dissect/cache.py`. |
| **Integration point** | New module `goshark/dissect/__init__.py` exports `registry`, `dissect_packet`, `ProtocolTree`, `Field`, `FieldType`. Existing `PacketTableModel.append_batch` unchanged; UI will call `dissect_packet` on demand (selection, follow‑stream). |
| **Testing** | `tests/test_dissect_registry.py`, `tests/test_fields.py`, `tests/test_protocol_tree.py` using `pytest`. Run via `pytest -q`. |
| **Dependencies** | No new third‑party packages. Only stdlib (`dataclasses`, `enum`, `functools`, `typing`). |
| **Type safety** | All new code annotated; `mypy --strict` passes. |
| **Formatting** | `ruff` (line‑length 100). |

## Gray Areas – Deferred (out of scope for Phase 1)

- Heuristic dissector selection (multiple candidates for same DLT) – Phase 2.
- Display‑filter VM – Phase 3.
- Actual protocol dissectors (Ethernet, IP, TCP…) – Phase 2.
- Persistence of dissected trees to disk – later milestone.

## Next Steps

1. Run **gsd-plan-phase 1** to generate detailed `PLAN.md` with tasks, ordering, and verification checklist.
2. Execute Phase 1 via **gsd-execute-phase 1**.
3. Verify with unit tests and a tiny demo script (`python -m goshark.demo_phase1`).