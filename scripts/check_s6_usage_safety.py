#!/usr/bin/env python3
"""Validate conservative usage-evidence properties for Sprint 6 fixtures."""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

try:
    from .evaluate_usage_constructs import identity_import, expected_binding
except ImportError:
    from evaluate_usage_constructs import identity_import, expected_binding


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(labels, graph):
    fixture = labels["fixture"]
    observations = graph.get("observations", [])

    require(
        graph.get("analysis", {}).get("status") == "complete",
        "Analysis is not complete",
    )

    # Every labelled unanalysed occurrence must remain visible.
    expected = Counter(
        (item["purl"], item["reason"])
        for item in labels["expected"].get("unanalysedOccurrences", [])
    )
    actual = Counter(
        (item.get("purl"), item.get("reason"))
        for item in graph.get("unanalysedOccurrences", [])
    )

    for identity, count in expected.items():
        require(
            actual[identity] >= count,
            f"Missing unanalysed occurrence: {identity}",
        )

    # Expectations live in expected.json, so a new fixture gets the same checks.
    imports = labels['expected']['thirdPartyImports']
    for labelled in imports:
        matches = [obs for obs in observations
                   if identity_import(obs, True) == identity_import(labelled)]
        require(len(matches) == 1, f"Expected one binding: {labelled}")
        obs = matches[0]
        for field, default in (('purl', ''), ('computedSpecifier', False),
                               ('unresolvedReason', ''), ('evidenceLevel', 0)):
            if field in labelled:
                require(obs.get(field, default) == labelled[field],
                        f"{fixture}: {field} differs from label")
    for category in ('thirdPartyCalls', 'unresolvedCalls'):
        for labelled in labels['expected'].get(category, []):
            binding = expected_binding(labelled, imports)
            calls = [call for obs in observations if identity_import(obs, True) == binding
                     for call in obs.get('callSites', [])
                     if (call['file'], call['line'], call.get('calledSymbol', '')) ==
                        (labelled['file'], labelled['line'], labelled.get('symbol', ''))]
            require(len(calls) == 1, f"Expected one call: {labelled}")
            for field in ('reachability', 'unresolvedReason'):
                if field in labelled:
                    require(calls[0].get(field) == labelled[field],
                            f"{fixture}: call {field} differs from label")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--graph", type=Path, required=True)
    args = parser.parse_args()

    labels = json.loads(args.labels.read_text())
    graph = json.loads(args.graph.read_text())

    validate(labels, graph)

    print(f"PASS: {labels['fixture']} safety checks")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
