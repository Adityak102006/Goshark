# Phase 1 – Registry & Field Model — PLAN.md

## Goal
Deliver a **typed, test‑covered** dissector registry, field model, and protocol‑tree data structures that later phases can import without modification.

## Tasks (ordered, tracer‑first)

| # | Task | Description | Verification |
|---|------|-------------|--------------|
| T1 | **Create package skeleton** | `mkdir -p goshark/dissect` + `__init__.py` exporting public API. | `python -c "import goshark.dissect; print(goshark.dissect.__all__)"` |
| T2 | **FieldType enum & Field dataclass** | Implement `FieldType` (UINT8, UINT16, UINT32, UINT64, INT8, INT16, INT32, INT64, STRING, BYTES, IPv4, IPv6, MAC, BOOL, ENUM) and `Field` dataclass with slots. | Unit test `test_fields.py` creates each type, checks `offset`/`length`/`display`. |
| T3 | **ProtocolTree dataclass** | Implement `ProtocolTree` with `protocol`, `fields`, `children`, `byte_range`, helpers `add_field`, `add_child`, `walk()`. | Unit test builds a two‑level tree and asserts walk order. |
| T4 | **DissectorRegistry** | Class with `register(dlt, fn, heuristic=None)`, `lookup(dlt)`. Global instance `registry`. | Test registers a dummy dissector for DLT=1, lookup returns it; unknown DLT returns `None`. |
| T5 | **LRU dissection cache** | `cache.py` with `dissect_packet(pkt_bytes, dlt) -> ProtocolTree` decorated by `@lru_cache(maxsize=2000)`. Cache key = `(hash(pkt_bytes), dlt)` (use `hashlib.sha256(pkt_bytes).digest()[:8]` for stability). | Test: same packet twice → second call hits cache (instrument with counter). |
| T6 | **Wire into PacketTableModel (optional demo hook)** | Add a **stand‑alone demo script** `goshark/demo_phase1.py` that loads a tiny pcap (provided in `testdata/sample.pcapng`), iterates packets, calls `dissect_packet`, prints tree summary. Not required for core library but proves end‑to‑end path. | Running script prints at least one protocol tree without errors. |
| T7 | **Type‑check & lint** | Run `mypy --strict goshark/dissect` and `ruff check goshark/dissect`. | Zero errors. |
| T8 | **Unit test suite** | `tests/test_dissect_registry.py`, `tests/test_fields.py`, `tests/test_protocol_tree.py`, `tests/test_cache.py`. All pass under `pytest -q`. | `pytest -q` exits 0. |

## Acceptance Criteria (Definition of Done)

1. All tasks T1‑T8 verified.
2. `pytest -q` passes.
3. `mypy --strict` and `ruff` clean.
4. `python -m goshark.demo_phase1` runs and prints a protocol tree for the sample capture.

## Rollback / Reversibility

All tasks are **reversible** (pure additive code). No database migrations, no public API changes beyond new module.

## Estimated Effort

| Task | Est. |
|------|------|
| T1‑T4 | 2 h |
| T5 | 1 h |
| T6 | 1 h |
| T7‑T8 | 1 h |
**Total ~5 h** (single developer).

## Next Phase Dependency

Phase 2 will import `goshark.dissect.registry`, `ProtocolTree`, `Field`, `FieldType` and implement concrete dissectors (Ethernet, IPv4, IPv6, TCP, UDP, DNS, HTTP, TLS ClientHello).