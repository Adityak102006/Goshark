# Project: Goshark

**Vision** – A fast, scriptable, Wireshark‑class packet analyzer built on Python + Qt that can dissect, filter, reassemble, and visualize captures at scale.

**Current stack**
- Python 3.11+
- PySide6 (Qt 6)
- `pcapng` / `pypcapng` for file I/O
- `dpkt` / `scapy` for quick prototyping (may be replaced by native dissectors)

**Milestones**
1. **Dissector‑Framework** – plug‑in dissector registry, field model, lazy dissection, display‑filter VM (this milestone)
2. Capture‑Engine & Ring‑Buffer
3. TCP Reassembly & Conversation Tracking
4. UI – Packet List, Detail, Hex, Follow‑Stream
5. Wiretap‑compatible File I/O (pcap/pcapng)
6. Extensibility (Lua/Python scripts, extcap)

**Active milestone:** Dissector‑Framework