"""
Tests for dissect.fields module.
"""
import pytest

from goshark.dissect.fields import Field, FieldType


def test_field_creation_all_types():
    for ft in FieldType:
        f = Field(name="test", ftype=ft, value=None, offset=0, length=1)
        assert f.ftype is ft


def test_field_validation():
    with pytest.raises(ValueError):
        Field(name="bad", ftype=FieldType.UINT8, value=0, offset=-1, length=1)
    with pytest.raises(ValueError):
        Field(name="bad", ftype=FieldType.UINT8, value=0, offset=0, length=0)


def test_field_display_optional():
    f = Field(name="x", ftype=FieldType.UINT8, value=10, offset=0, length=1, display="0x0A")
    assert f.display == "0x0A"