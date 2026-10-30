# Requirements – Milestone: Dissector‑Framework

| ID | Requirement | Priority | Acceptance |
|----|-------------|----------|------------|
| R1 | **Dissector registry** – dynamic registration of protocol dissectors (Python callables or C extensions) keyed by DLT / EtherType / IP protocol / port. | Must | `registry.register(dlt, callable)` works; `registry.lookup(dlt)` returns callable. |
| R2 | **Field model** – typed fields (uint8/16/32/64, int, string, bytes, ipv4, ipv6, mac, bool, enum) with name, value, byte offset, length, display format. | Must | `Field(name, type, value, offset, length)` can be rendered in tree & hex highlight. |
| R3 | **Protocol tree** – hierarchical tree of protocols → fields; each node knows its byte range for hex‑view sync. | Must | Selecting tree node highlights correct bytes. |
| R4 | **Lazy dissection** – only dissect packets needed for UI (visible rows + follow‑stream). Cache dissected trees per packet with LRU eviction. | Must | Memory ≤ 200 MB for 1 M packets; UI stays responsive. |
| R5 | **Display‑filter VM** – parse Wireshark‑style filter strings (`tcp.port==80 && http.request.method=="GET"`), compile to bytecode, evaluate against field model. | Must | Filter applies in < 5 ms per 10 k packets. |
| R6 | **Built‑in core dissectors** – Ethernet, IPv4, IPv6, TCP, UDP, DNS, HTTP, TLS (ClientHello). | Should | Packets from sample pcaps show correct trees. |
| R7 | **Extensibility API** – `register_dissector(name, callable, heuristic)` plus `register_field_type`. | Should | Third‑party script can add a new protocol without core changes. |
| R8 | **Tests** – unit tests for registry, field model, filter VM, and each core dissector. | Must | `pytest -q` passes. |

**Non‑functional**
- No new external dependencies beyond current `requirements.txt`.
- All new code typed with `mypy --strict`.
- Code formatted with `ruff` (line‑length 100).