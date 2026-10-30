# Roadmap – Milestone: Dissector‑Framework

| Phase | Title | Goal (vertical slice) | Depends on |
|-------|-------|-----------------------|------------|
| 1 | **Registry & Field Model** | Implement `DissectorRegistry`, `Field`, `ProtocolTree` classes; unit tests. | – |
| 2 | **Core Dissectors & Lazy Dissection** | Write Ethernet, IPv4, IPv6, TCP, UDP, DNS, HTTP, TLS ClientHello dissectors using the registry; integrate with `PacketTableModel` for on‑demand dissection + LRU cache. | 1 |
| 3 | **Display‑Filter VM & Test Harness** | Port a tiny filter VM (or embed `dfilter` via `ctypes`); wire filter bar → VM → packet list; full pytest suite. | 1,2 |

**Ordering rule:** each phase must produce a runnable demo (e.g., `python -m goshark.demo_phaseN`) so progress is visible.