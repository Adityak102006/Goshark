"""
Tests for dissect.tree module.
"""
import pytest

from goshark.dissect.fields import Field, FieldType
from goshark.dissect.tree import ProtocolTree


def test_protocol_tree_basic():
    root = ProtocolTree(protocol="TCP")
    f = Field(name="src port", ftype=FieldType.UINT16, value=1234, offset=0, length=2)
    root.add_field(f)
    assert len(root.fields) == 1
    assert root.byte_range == (0, 1)


def test_protocol_tree_children():
    parent = ProtocolTree(protocol="IPv4")
    child = ProtocolTree(protocol="TCP", byte_range=(20, 39))
    parent.add_child(child)
    assert len(parent.children) == 1
    assert parent.byte_range == (20, 39)


def test_walk_order():
    root = ProtocolTree(protocol="Frame")
    c1 = ProtocolTree(protocol="IPv4")
    c2 = ProtocolTree(protocol="TCP")
    c1.add_child(c2)
    root.add_child(c1)
    walked = [n.protocol for n in root.walk()]
    assert walked == ["Frame", "IPv4", "TCP"]