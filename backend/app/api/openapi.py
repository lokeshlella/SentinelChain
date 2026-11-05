"""The OpenAPI document (``/docs``, ``/redoc``) of a build lists only the features it exposes.

Routes of a gated feature carry ``FEATURE_KEY`` in their OpenAPI operation (see ``deps.feature_gate``).
A Phase-1 build drops those operations, and the schemas only they used, so the interactive docs show the
same product the dashboard does.
"""

from __future__ import annotations

import copy
from typing import Any

FEATURE_KEY = "x-sentinel-feature"
_SCHEMA_REF = "#/components/schemas/"


def _schema_refs(node: Any, found: set[str]) -> set[str]:
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith(_SCHEMA_REF):
            found.add(ref[len(_SCHEMA_REF):])
        for value in node.values():
            _schema_refs(value, found)
    elif isinstance(node, list):
        for value in node:
            _schema_refs(value, found)
    return found


def filter_openapi(schema: dict[str, Any], enabled: dict[str, bool]) -> dict[str, Any]:
    """A copy of ``schema`` without the operations of disabled features; the marker is removed everywhere."""
    schema = copy.deepcopy(schema)
    paths: dict[str, Any] = {}
    for path, item in (schema.get("paths") or {}).items():
        kept: dict[str, Any] = {}
        for key, operation in item.items():
            if isinstance(operation, dict) and FEATURE_KEY in operation:
                feature = operation.pop(FEATURE_KEY)
                if not enabled.get(feature, False):
                    continue
            kept[key] = operation
        if any(isinstance(op, dict) and "responses" in op for op in kept.values()):
            paths[path] = kept
    schema["paths"] = paths

    components = (schema.get("components") or {}).get("schemas")
    if components:
        reachable = _schema_refs(paths, set())
        pending = list(reachable)
        while pending:
            for ref in _schema_refs(components.get(pending.pop(), {}), set()):
                if ref not in reachable:
                    reachable.add(ref)
                    pending.append(ref)
        schema["components"]["schemas"] = {name: s for name, s in components.items() if name in reachable}
    return schema
