"""Canonical encoding (NFR-001) and the JSON Schema subset validator (REQ-003, NFR-007)."""

from __future__ import annotations

import pytest

from iac_change_control.canonical import digest_json_bytes, evidence_json_bytes, text_bytes
from iac_change_control.schema_validator import SchemaDefinitionError, Validator


def test_canonical_json_format():
    data = evidence_json_bytes({"b": 1, "a": {"z": "ü", "y": [2, 1]}})
    expected = (
        b'{\n  "a": {\n    "y": [\n      2,\n      1\n    ],\n'
        b'    "z": "\xc3\xbc"\n  },\n  "b": 1\n}\n'
    )
    assert data == expected
    assert b"\r" not in data and data.endswith(b"}\n")
    assert digest_json_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    assert text_bytes("x\r\ny\n\n\n") == b"x\ny\n"
    with pytest.raises(ValueError):
        evidence_json_bytes({"n": float("nan")})


def test_schema_validator_supported_keywords():
    schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["n", "s", "kind"],
        "properties": {
            "n": {"type": "integer", "minimum": 1, "maximum": 3},
            "s": {"type": "string", "pattern": "^ab$", "minLength": 2, "maxLength": 2},
            "kind": {"enum": ["x", "y"]},
            "flag": {"const": True},
            "list": {
                "type": "array",
                "minItems": 1,
                "maxItems": 2,
                "uniqueItems": True,
                "items": {"$ref": "#/$defs/small"},
            },
            "map": {
                "type": "object",
                "propertyNames": {"pattern": "^[a-z]+$"},
                "additionalProperties": {"type": "string"},
                "minProperties": 1,
            },
            "maybe": {"type": ["string", "null"]},
        },
        "allOf": [
            {
                "if": {"properties": {"kind": {"const": "y"}}},
                "then": {"required": ["flag"]},
                "else": {"required": ["maybe"]},
            }
        ],
        "$defs": {"small": {"type": "integer", "maximum": 5}},
    }
    v = Validator(schema)
    good = {"n": 2, "s": "ab", "kind": "x", "maybe": None, "list": [1, 2], "map": {"a": "b"}}
    assert v.validate(good) == []
    bad = {"n": True, "s": "ab\n", "kind": "y", "list": [1, 1, 9], "map": {"A1": "b"}, "extra": 1}
    keywords = {(e.path, e.keyword) for e in v.validate(bad)}
    assert ("$.n", "type") in keywords  # bool is not an integer
    assert ("$.s", "pattern") in keywords  # "$" must not match before a trailing newline
    assert ("$", "required") in keywords  # then-branch requires "flag"
    assert ("$.list", "maxItems") in keywords
    assert ("$.list", "uniqueItems") in keywords
    assert ("$.list[2]", "maximum") in keywords
    assert ("$.map.A1", "propertyNames") in keywords
    assert ("$.extra", "additionalProperties") in keywords


def test_schema_validator_rejects_unknown_keyword():
    with pytest.raises(SchemaDefinitionError):
        Validator({"type": "object", "oneOf": [{"type": "object"}]})
    with pytest.raises(SchemaDefinitionError):
        Validator({"properties": {"a": {"$ref": "#/$defs/missing"}}})
    with pytest.raises(SchemaDefinitionError):
        Validator({"$ref": "https://example.invalid/remote.json"})
