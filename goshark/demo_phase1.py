#!/usr/bin/env python3
"""
Phase‑1 demonstration: dissect a dummy packet using the registry + cache.

No real dissectors are registered yet, so the output will be a single
"Raw" protocol node – this proves the plumbing works end‑to‑end.
"""
from __future__ import annotations

from goshark.dissect import dissect_packet, registry


def main() -> None:
    # Example Ethernet‑II frame (dst MAC, src MAC, EtherType=0x0800 IPv4)
    dummy_frame = bytes.fromhex(
        "ff ff ff ff ff ff 00 11 22 33 44 55 08 00"
        + "45 00 00 3c 1c 46 40 00 40 06 b1 e6 c0 a8 01 01 c0 a8 01 02"
        + "00 50 00 15 00 00 00 00 00 00 00 00 50 02 20 00 91 7c 00 00"
    )

    # DLT_EN10MB == 1 (Ethernet)
    DLT_EN10MB = 1

    tree = dissect_packet(dummy_frame, DLT_EN10MB)

    print("Dissected tree:")
    for node in tree.walk():
        indent = "  " * (node.byte_range[0] // 16)  # crude visual depth
        print(f"{indent}{node.protocol} [{node.byte_range[0]}:{node.byte_range[1]}]")
        for fld in node.fields:
            print(f"{indent}  • {fld.name} = {fld.display or fld.value}")

    print("\nRegistry keys:", registry.keys())


if __name__ == "__main__":
    main()