"""Deliberately small, bounded JSON Schema subset; no regex/ref/composition execution."""

import json
import math

from jsonschema import Draft202012Validator

from .decisions import DecisionError

_KEYS = {
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "minItems",
    "maxItems",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "enum",
    "description",
    "title",
}


def checked_schema(value):
    def bounded_copy(item, depth=0, budget=None):
        from collections.abc import Mapping

        budget = [0] if budget is None else budget
        budget[0] += 1
        if depth > 20 or budget[0] > 2048:
            raise DecisionError("unsupported_schema")
        if isinstance(item, Mapping):
            if any(not isinstance(k, str) or len(k) > 1024 for k in item):
                raise DecisionError("unsupported_schema")
            return {k: bounded_copy(v, depth + 1, budget) for k, v in item.items()}
        if isinstance(item, (tuple, list)):
            return [bounded_copy(v, depth + 1, budget) for v in item]
        if isinstance(item, str) and len(item) > 16384:
            raise DecisionError("unsupported_schema")
        if isinstance(item, float) and not math.isfinite(item):
            raise DecisionError("unsupported_schema")
        return item

    schema = bounded_copy(value)
    if len(json.dumps(schema).encode()) > 16384:
        raise DecisionError("unsupported_schema")
    budget = [0]

    def visit(node, depth=0):
        budget[0] += 1
        if depth > 8 or budget[0] > 128 or not isinstance(node, dict) or node.keys() - _KEYS:
            raise DecisionError("unsupported_schema")
        for key, item in node.items():
            if key in {"required", "type"} and isinstance(item, list) and len(item) > 64:
                raise DecisionError("unsupported_schema")
            if key == "properties":
                if not isinstance(item, dict) or len(item) > 64:
                    raise DecisionError("unsupported_schema")
                for child in item.values():
                    visit(child, depth + 1)
            elif key == "items":
                visit(item, depth + 1)
            elif key == "additionalProperties" and not isinstance(item, bool):
                raise DecisionError("unsupported_schema")
            elif key == "enum":
                if (
                    not isinstance(item, list)
                    or len(item) > 32
                    or any(isinstance(x, (dict, list)) for x in item)
                ):
                    raise DecisionError("unsupported_schema")

    visit(schema)
    try:
        Draft202012Validator.check_schema(schema)
    except Exception:
        raise DecisionError("unsupported_schema") from None
    return schema


def validate_payload(schema, arguments):
    schema = checked_schema(schema)
    try:
        Draft202012Validator(schema).validate(arguments)
    except Exception:
        raise DecisionError("invalid_arguments") from None
