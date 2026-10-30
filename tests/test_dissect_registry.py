"""
Tests for dissect.registry module.
"""
import pytest

from goshark.dissect.registry import DissectorRegistry
from goshark.dissect.tree import ProtocolTree


def dummy_dissector(_: bytes) -> ProtocolTree:
    return ProtocolTree(protocol="Dummy")


def test_register_and_lookup():
    reg = DissectorRegistry()
    reg.register(99, dummy_dissector)
    assert reg.lookup(99) is dummy_dissector
    assert reg.lookup(100) is None


def test_heuristic_storage():
    reg = DissectorRegistry()

    def heur(_: bytes) -> bool:
        return True

    reg.register(5, dummy_dissector, heuristic=heur)
    assert reg.heuristic(5) is heur
    assert reg.heuristic(6) is None


def test_global_registry_singleton():
    from goshark.dissect import registry as global_reg

    assert isinstance(global_reg, DissectorRegistry)
    # ensure it's the same instance across imports
    from goshark.dissect import registry as global_reg2

    assert global_reg is global_reg2