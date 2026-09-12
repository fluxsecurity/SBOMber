#!/usr/bin/env python3
"""Validate the two S4-09 sample VEX documents against their official schemas.

OpenVEX: the JSON Schema published by the OpenVEX project (spec v0.2.0),
committed alongside for reproducibility. The OpenVEX project ships no
`vexctl validate` command, so schema validation is the strongest check
available.

CycloneDX: cyclonedx-python-lib's JsonStrictValidator for spec 1.6, which
embeds the official bom-1.6 schema.

Requires: jsonschema, cyclonedx-python-lib[json-validation]
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ok = True

try:
    from jsonschema import Draft202012Validator
    schema = json.load(open(HERE / "samples" / "openvex_json_schema_0.2.0.json"))
    doc = json.load(open(HERE / "samples" / "sample.openvex.json"))
    errors = list(Draft202012Validator(schema).iter_errors(doc))
    print("OpenVEX 0.2.0 schema:", "VALID" if not errors else "INVALID")
    for e in errors:
        ok = False
        print("  -", "/".join(str(p) for p in e.path), e.message)
    tokens = {s["status"] for s in doc["statements"]}
    print("  statuses used:", sorted(tokens))
except ImportError:
    print("OpenVEX: jsonschema not installed, skipped")

try:
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator
    text = open(HERE / "samples" / "sample.cdx-vex.json").read()
    err = JsonStrictValidator(SchemaVersion.V1_6).validate_str(text)
    print("CycloneDX 1.6 JsonStrictValidator:", "VALID" if err is None else "INVALID")
    if err is not None:
        ok = False
        print("  -", err)
    states = {v["analysis"]["state"] for v in json.loads(text)["vulnerabilities"]}
    print("  analysis states used:", sorted(states))
except ImportError:
    print("CycloneDX: cyclonedx-python-lib not installed, skipped")

sys.exit(0 if ok else 1)
