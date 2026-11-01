"""A small, strict subset of JSON Schema 2020-12 (REQ-003, REQ-005, REQ-006, NFR-007).

It covers only the keywords this lab's schemas use. Any other keyword raises
``SchemaDefinitionError``, so a schema can never silently rely on unsupported behaviour.

Error messages identify the JSON path and the failed keyword. They never echo input values;
only property names from the input may appear.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

ANNOTATION_KEYWORDS = frozenset(
    {"$schema", "$id", "$comment", "title", "description", "examples", "default"}
)
SUPPORTED_KEYWORDS = frozenset(
    {
        "$ref",
        "$defs",
        "type",
        "const",
        "enum",
        "properties",
        "required",
        "additionalProperties",
        "propertyNames",
        "minProperties",
        "items",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minLength",
        "maxLength",
        "pattern",
        "minimum",
        "maximum",
        "allOf",
        "if",
        "then",
        "else",
    }
)

_TYPE_CHECKS = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


class SchemaDefinitionError(Exception):
    """Raised when a schema uses an unsupported keyword or an unresolvable reference."""


@dataclass(frozen=True, order=True)
class SchemaViolation:
    path: str
    keyword: str
    message: str


def _child_path(path: str, key: str) -> str:
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        return f"{path}.{key}"
    escaped = key.replace("\\", "\\\\").replace('"', '\\"')
    return f'{path}["{escaped}"]'


def _pattern_matches(pattern: str, value: str) -> bool:
    """ECMA-262 semantics for this subset: ``$`` must not match before a trailing newline.

    Python's ``$`` also matches before a final ``\\n``. A pattern anchored at both ends is
    therefore applied with ``fullmatch``. Other patterns use ``search``, as JSON Schema requires.
    """
    if pattern.startswith("^") and pattern.endswith("$") and not pattern.endswith("\\$"):
        return re.fullmatch(pattern, value) is not None
    return re.search(pattern, value) is not None


def _json_equal(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    return a == b


class Validator:
    def __init__(self, root_schema: dict[str, Any]):
        self.root = root_schema
        self._check_definition(root_schema, "#")

    # -- schema self-check -------------------------------------------------------------------
    def _check_definition(self, schema: Any, where: str) -> None:
        if isinstance(schema, bool):
            return
        if not isinstance(schema, dict):
            raise SchemaDefinitionError(f"schema at {where} must be an object or boolean")
        for key, value in schema.items():
            if key in ANNOTATION_KEYWORDS:
                continue
            if key not in SUPPORTED_KEYWORDS:
                raise SchemaDefinitionError(f"unsupported keyword {key!r} at {where}")
            if key in ("properties", "$defs"):
                for name, sub in value.items():
                    self._check_definition(sub, f"{where}/{key}/{name}")
            elif key in ("items", "additionalProperties", "propertyNames", "if", "then", "else"):
                self._check_definition(value, f"{where}/{key}")
            elif key == "allOf":
                for index, sub in enumerate(value):
                    self._check_definition(sub, f"{where}/allOf/{index}")
            elif key == "$ref":
                self._resolve(value)

    def _resolve(self, ref: str) -> Any:
        if not ref.startswith("#/"):
            raise SchemaDefinitionError(f"only local references are supported: {ref!r}")
        node: Any = self.root
        for part in ref[2:].split("/"):
            if not isinstance(node, dict) or part not in node:
                raise SchemaDefinitionError(f"unresolvable reference {ref!r}")
            node = node[part]
        return node

    def subschema(self, ref: str) -> Any:
        return self._resolve(ref)

    # -- validation ----------------------------------------------------------------------------
    def validate(self, instance: Any, schema: Any = None, path: str = "$") -> list[SchemaViolation]:
        errors: list[SchemaViolation] = []
        self._validate(instance, self.root if schema is None else schema, path, errors)
        return sorted(set(errors))

    def is_valid(self, instance: Any, schema: Any) -> bool:
        errors: list[SchemaViolation] = []
        self._validate(instance, schema, "$", errors)
        return not errors

    def _validate(self, value: Any, schema: Any, path: str, errors: list[SchemaViolation]) -> None:
        if schema is True:
            return
        if schema is False:
            errors.append(SchemaViolation(path, "false", "value is not allowed here"))
            return

        if "$ref" in schema:
            self._validate(value, self._resolve(schema["$ref"]), path, errors)

        if "type" in schema:
            allowed = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
            if not any(_TYPE_CHECKS[name](value) for name in allowed):
                errors.append(
                    SchemaViolation(path, "type", f"expected type {' or '.join(allowed)}")
                )
                return  # further keywords would only cascade

        if "const" in schema and not _json_equal(value, schema["const"]):
            errors.append(
                SchemaViolation(path, "const", "value does not equal the required constant")
            )
        if "enum" in schema and not any(_json_equal(value, item) for item in schema["enum"]):
            errors.append(SchemaViolation(path, "enum", "value is not one of the allowed values"))

        if isinstance(value, dict):
            self._validate_object(value, schema, path, errors)
        elif isinstance(value, list):
            self._validate_array(value, schema, path, errors)
        elif isinstance(value, str):
            if "minLength" in schema and len(value) < schema["minLength"]:
                errors.append(SchemaViolation(path, "minLength", "string is too short"))
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                errors.append(SchemaViolation(path, "maxLength", "string is too long"))
            if "pattern" in schema and not _pattern_matches(schema["pattern"], value):
                errors.append(SchemaViolation(path, "pattern", "string does not match the pattern"))
        elif _TYPE_CHECKS["number"](value):
            if "minimum" in schema and value < schema["minimum"]:
                errors.append(SchemaViolation(path, "minimum", "number is below the minimum"))
            if "maximum" in schema and value > schema["maximum"]:
                errors.append(SchemaViolation(path, "maximum", "number is above the maximum"))

        for sub in schema.get("allOf", []):
            self._validate(value, sub, path, errors)

        if "if" in schema:
            if self.is_valid(value, schema["if"]):
                if "then" in schema:
                    self._validate(value, schema["then"], path, errors)
            elif "else" in schema:
                self._validate(value, schema["else"], path, errors)

    def _validate_object(
        self, value: dict[str, Any], schema: dict[str, Any], path: str, errors: list
    ) -> None:
        for name in schema.get("required", []):
            if name not in value:
                errors.append(
                    SchemaViolation(path, "required", f"missing required property '{name}'")
                )
        if "minProperties" in schema and len(value) < schema["minProperties"]:
            errors.append(SchemaViolation(path, "minProperties", "object has too few properties"))
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for key in sorted(value):
            child = _child_path(path, key)
            if "propertyNames" in schema and not self.is_valid(key, schema["propertyNames"]):
                errors.append(
                    SchemaViolation(child, "propertyNames", "property name is not allowed")
                )
                continue
            if key in properties:
                self._validate(value[key], properties[key], child, errors)
            elif additional is False:
                errors.append(SchemaViolation(child, "additionalProperties", "unexpected property"))
            elif isinstance(additional, dict):
                self._validate(value[key], additional, child, errors)

    def _validate_array(self, value: list, schema: dict[str, Any], path: str, errors: list) -> None:
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(SchemaViolation(path, "minItems", "array has too few items"))
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(SchemaViolation(path, "maxItems", "array has too many items"))
        if schema.get("uniqueItems"):
            seen: list[Any] = []
            for item in value:
                if any(_json_equal(item, other) for other in seen):
                    errors.append(
                        SchemaViolation(path, "uniqueItems", "array items are not unique")
                    )
                    break
                seen.append(item)
        if "items" in schema:
            for index, item in enumerate(value):
                self._validate(item, schema["items"], f"{path}[{index}]", errors)
