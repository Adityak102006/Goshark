"""
Tests for dissect.cache module.
"""
from goshark.dissect.cache import dissect_packet
from goshark.dissect.tree import ProtocolTree


def test_dissect_packet_fallback_raw():
    data = b"ABCDEF"
    tree = dissect_packet(data, dlt=999)  # unknown DLT
    assert isinstance(tree, ProtocolTree)
    assert tree.protocol == "Raw"
    assert len(tree.fields) == 1
    f = tree.fields[0]
    assert f.name == "Raw Data"
    assert f.value == data


def test_cache_hit():
    data = b"XYZ123"
    # First call
    t1 = dissect_packet(data, dlt=888)
    # Second call with same bytes should hit cache (same object not guaranteed,
    # but structure identical)
    t2 = dissect_packet(data, dlt=888)
    assert t1.protocol == t2.protocol
    assert t1.fields[0].value == t2.fields[0].value