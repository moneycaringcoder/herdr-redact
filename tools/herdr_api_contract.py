#!/usr/bin/env python3
"""Verify a Herdr API schema still carries everything redact depends on.

The input is Herdr's generated protocol schema — `docs/next/api/herdr-api.schema.json`
in the upstream tree, which is byte-compared against the running code by
upstream's own `generated_protocol_schema_artifact_is_current` test, or the
output of `herdr api schema` from a local build.

The contract below is deliberately narrow. It names the five methods redact
calls, the parameters it sends, and the response fields it reads, and nothing
else. Upstream is free to add, remove, and rename anything redact does not
touch; this only fails when the surface redact actually stands on moves.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys

MAX_SCHEMA_BYTES = 4 * 1024 * 1024
SCHEMA_VERSION = 1

# Protocol 19 shipped in Herdr 0.8.0, which is the floor in herdr-plugin.toml.
# Raise this only alongside that value.
MIN_PROTOCOL = 19

# Request methods redact calls, with the parameters it sends.
#
# "required" means redact always sends the field, so the schema must still
# accept it and still list it as required — a field that became optional
# upstream is not a break for us, but one that disappeared is. "optional" means
# redact sends it only sometimes; it must still exist.
REQUESTS: dict[str, dict[str, tuple[str, ...]]] = {
    "session.snapshot": {"required": (), "optional": ()},
    "pane.read": {"required": ("pane_id", "source"), "optional": ("lines",)},
    "workspace.report_metadata": {
        "required": ("workspace_id", "source", "tokens"),
        # Omitted entirely on a pure delete: Herdr rejects a TTL alongside a
        # null token value.
        "optional": ("ttl_ms",),
    },
    "pane.report_metadata": {
        "required": ("pane_id", "source"),
        # Tokens only. This is not `pane.report_agent`, so a badged pane never
        # starts rendering as a live idle agent.
        "optional": ("tokens", "ttl_ms"),
    },
    "notification.show": {"required": ("title",), "optional": ("body",)},
}

# Response variants redact reads, keyed by the `type` discriminant, with the
# properties it reaches for on the variant itself.
#
# Both of these are nesting traps the protocol notes call out: the payload lives
# under `snapshot` and under `read`, and a client that reads the result object
# directly finds nothing. For a plugin whose job is to notice a credential, that
# reads as "this pane is clean", so the nesting is part of the contract.
RESULTS: dict[str, tuple[str, ...]] = {
    "session_snapshot": ("snapshot",),
    "pane_read": ("read",),
}

# Response objects redact reads fields out of.
#
# "required" means redact treats absence as breakage rather than as an empty
# result. "optional" means redact reads it when present and copes when it is
# not, so the field must still exist but need not be mandatory.
OBJECTS: dict[str, dict[str, tuple[str, ...]]] = {
    "SessionSnapshot": {
        # An absent array is indistinguishable from a session with nothing in
        # it, which for this plugin means "no credentials found" — the one
        # wrong answer it must never give quietly.
        "required": ("panes", "workspaces", "agents"),
        "optional": (),
    },
    "PaneInfo": {
        "required": ("pane_id", "workspace_id", "tab_id"),
        # The agent name and title are display context for a finding; `cwd`
        # scopes it to a project.
        "optional": ("agent", "terminal_title", "terminal_title_stripped", "cwd"),
    },
    "WorkspaceInfo": {"required": ("workspace_id", "label"), "optional": ()},
    "AgentInfo": {
        "required": ("pane_id",),
        # `name` is the user's own label and wins over the program name.
        "optional": ("name", "agent"),
    },
    "PaneReadResult": {
        # An empty pane is legitimate, so an empty `text` is fine — but an
        # absent one is a protocol change, and reporting it as a clean pane is
        # exactly the invisible failure this plugin cannot afford. `truncated`
        # is what stops a partial read being presented as a whole one.
        "required": ("text", "truncated"),
        "optional": ("pane_id",),
    },
}

# Enumerations redact depends on by value.
ENUMS: dict[str, tuple[str, ...]] = {}

# Request-side enumerations. `source` on `pane.read` is sent as the literal
# `recent_unwrapped`, which joins soft-wrapped lines — a credential split across
# a wrap is one this scanner would otherwise miss.
REQUEST_ENUMS: dict[str, tuple[str, ...]] = {
    "ReadSource": ("recent_unwrapped",),
}


class ContractError(ValueError):
    pass


def reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant {value}")


def read_schema(path: Path) -> object:
    """Read one regular file as bounded, strict UTF-8 JSON."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ContractError("schema input must be a regular file")
        if metadata.st_size > MAX_SCHEMA_BYTES:
            raise ContractError(f"schema exceeds {MAX_SCHEMA_BYTES}-byte limit")
        schema_file = os.fdopen(descriptor, "rb")
        descriptor = None
        with schema_file:
            content = schema_file.read(MAX_SCHEMA_BYTES + 1)
    except ContractError:
        raise
    except OSError as error:
        raise ContractError("schema cannot be read") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(content) > MAX_SCHEMA_BYTES:
        raise ContractError(f"schema exceeds {MAX_SCHEMA_BYTES}-byte limit")
    try:
        return json.loads(
            content.decode("utf-8", errors="strict"),
            parse_constant=reject_json_constant,
        )
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ContractError("schema is not valid UTF-8 JSON") from error


def require_object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def resolve_reference(root: dict[str, object], reference: object, label: str) -> object:
    if not isinstance(reference, str) or not reference.startswith("#/"):
        raise ContractError(f"{label} has a non-local reference")
    current: object = root
    for encoded in reference[2:].split("/"):
        part = encoded.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            raise ContractError(f"{label} has an unresolved reference")
        current = current[part]
    return current


def resolved(root: dict[str, object], value: object, label: str) -> dict[str, object]:
    node = require_object(value, label)
    if "$ref" in node:
        node = require_object(resolve_reference(root, node["$ref"], label), label)
    return node


def check_protocol(root: dict[str, object]) -> int:
    version = root.get("schema_version")
    if isinstance(version, bool) or not isinstance(version, int) or version != SCHEMA_VERSION:
        raise ContractError(f"schema_version must be integer {SCHEMA_VERSION}")
    protocol = root.get("protocol")
    if isinstance(protocol, bool) or not isinstance(protocol, int) or protocol < 0:
        raise ContractError("schema protocol must be a non-negative integer")
    if protocol < MIN_PROTOCOL:
        raise ContractError(
            f"schema protocol {protocol} is older than the declared floor {MIN_PROTOCOL}"
        )
    return protocol


def check_requests(root: dict[str, object]) -> None:
    request = require_object(
        require_object(root.get("schemas"), "schemas").get("request"), "schemas.request"
    )
    variants = request.get("oneOf")
    if not isinstance(variants, list):
        raise ContractError("schemas.request.oneOf must be an array")

    found: dict[str, list[dict[str, object]]] = {}
    for variant in variants:
        if not isinstance(variant, dict):
            continue
        properties = variant.get("properties")
        if not isinstance(properties, dict):
            continue
        method_schema = properties.get("method")
        if not isinstance(method_schema, dict):
            continue
        method = method_schema.get("const")
        if isinstance(method, str):
            found.setdefault(method, []).append(properties)

    missing = sorted(set(REQUESTS).difference(found))
    if missing:
        raise ContractError("missing request methods: " + ", ".join(missing))

    for method in sorted(REQUESTS):
        matches = found[method]
        if len(matches) != 1:
            raise ContractError(f"request method {method} is defined more than once")
        label = f"request method {method} params"
        params = resolved(root, matches[0].get("params"), label)
        if params.get("type") != "object":
            raise ContractError(f"{label} must describe an object")
        properties = params.get("properties")
        properties = properties if isinstance(properties, dict) else {}
        mandatory = params.get("required")
        mandatory = set(mandatory) if isinstance(mandatory, list) else set()
        expected = REQUESTS[method]
        for field in expected["required"]:
            if field not in properties:
                raise ContractError(f"{label} no longer accepts `{field}`")
            if field not in mandatory:
                raise ContractError(f"{label} no longer requires `{field}`")
        for field in expected["optional"]:
            if field not in properties:
                raise ContractError(f"{label} no longer accepts `{field}`")


def response_definitions(root: dict[str, object]) -> dict[str, object]:
    response = require_object(
        require_object(root.get("schemas"), "schemas").get("success_response"),
        "schemas.success_response",
    )
    return require_object(response.get("$defs"), "schemas.success_response.$defs")


def check_results(root: dict[str, object]) -> None:
    definitions = response_definitions(root)
    result = require_object(definitions.get("ResponseResult"), "ResponseResult")
    variants = result.get("oneOf")
    if not isinstance(variants, list):
        raise ContractError("ResponseResult.oneOf must be an array")

    found: dict[str, dict[str, object]] = {}
    for variant in variants:
        if not isinstance(variant, dict):
            continue
        properties = variant.get("properties")
        if not isinstance(properties, dict):
            continue
        discriminant = properties.get("type")
        if isinstance(discriminant, dict) and isinstance(discriminant.get("const"), str):
            found[discriminant["const"]] = variant

    for name in sorted(RESULTS):
        variant = found.get(name)
        if variant is None:
            raise ContractError(f"missing response variant `{name}`")
        properties = variant.get("properties")
        properties = properties if isinstance(properties, dict) else {}
        mandatory = variant.get("required")
        mandatory = set(mandatory) if isinstance(mandatory, list) else set()
        for field in RESULTS[name]:
            if field not in properties:
                raise ContractError(f"response variant `{name}` no longer carries `{field}`")
            if field not in mandatory:
                raise ContractError(f"response variant `{name}` no longer requires `{field}`")


def check_objects(root: dict[str, object]) -> None:
    definitions = response_definitions(root)
    for name in sorted(OBJECTS):
        definition = definitions.get(name)
        if not isinstance(definition, dict):
            raise ContractError(f"missing response object `{name}`")
        properties = definition.get("properties")
        properties = properties if isinstance(properties, dict) else {}
        mandatory = definition.get("required")
        mandatory = set(mandatory) if isinstance(mandatory, list) else set()
        expected = OBJECTS[name]
        for field in expected["required"]:
            if field not in properties:
                raise ContractError(f"`{name}` no longer carries `{field}`")
            if field not in mandatory:
                raise ContractError(f"`{name}.{field}` is no longer always present")
        for field in expected["optional"]:
            if field not in properties:
                raise ContractError(f"`{name}` no longer carries `{field}`")


def request_definitions(root: dict[str, object]) -> dict[str, object]:
    request = require_object(
        require_object(root.get("schemas"), "schemas").get("request"), "schemas.request"
    )
    return require_object(request.get("$defs"), "schemas.request.$defs")


def check_enum_group(
    definitions: dict[str, object], expected: dict[str, tuple[str, ...]]
) -> None:
    for name in sorted(expected):
        definition = definitions.get(name)
        if not isinstance(definition, dict):
            raise ContractError(f"missing enumeration `{name}`")
        members = definition.get("enum")
        if not isinstance(members, list):
            raise ContractError(f"enumeration `{name}` has no members")
        for member in expected[name]:
            if member not in members:
                raise ContractError(f"enumeration `{name}` no longer has `{member}`")


def check_enums(root: dict[str, object]) -> None:
    check_enum_group(response_definitions(root), ENUMS)
    if REQUEST_ENUMS:
        check_enum_group(request_definitions(root), REQUEST_ENUMS)


def validate(schema: object) -> tuple[int, int]:
    root = require_object(schema, "schema root")
    protocol = check_protocol(root)
    check_requests(root)
    check_results(root)
    check_objects(root)
    check_enums(root)
    return protocol, len(REQUESTS)


def main() -> None:
    parser = argparse.ArgumentParser(description="Check Herdr's API against redact's needs")
    parser.add_argument("schema", type=Path, help="path to herdr-api.schema.json")
    args = parser.parse_args()
    try:
        protocol, methods = validate(read_schema(args.schema))
    except ContractError as error:
        print(f"Herdr API contract error: {error}", file=sys.stderr)
        raise SystemExit(1)
    print(f"Herdr API contract verified: protocol {protocol}; {methods} methods")


if __name__ == "__main__":
    main()
