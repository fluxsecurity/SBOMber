#!/usr/bin/env python3
"""Validate conservative usage-evidence properties for Sprint 6 fixtures."""

import argparse
import json
from collections import Counter
from pathlib import Path


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

    if fixture == "component2-s6-dynamic-computed":
        require(len(observations) == 1, "Expected one computed import")
        obs = observations[0]

        require(obs["importKind"] == "dynamic_computed", "Wrong import kind")
        require(obs["resolution"] == "unresolved", "Import was resolved")
        require(
            obs.get("unresolvedReason") == "computed_specifier",
            "Computed uncertainty reason missing",
        )
        require(
            obs.get("computedSpecifier") is True,
            "Computed specifier flag missing",
        )
        require(not obs["callSites"], "Unexpected computed-import calls")

    elif fixture == "component2-s6-reexport":
        require(len(observations) == 1, "Expected one re-export")
        obs = observations[0]

        require(obs["importKind"] == "esm_reexport", "Wrong re-export kind")
        require(obs["resolution"] == "resolved", "Re-export import unresolved")
        require(obs["evidenceLevel"] == 1, "Wrong evidence level")
        require(len(obs["callSites"]) == 1, "Expected one unresolved use")

        call = obs["callSites"][0]
        require(call["resolution"] == "unresolved", "Re-export call resolved")
        require(
            call.get("unresolvedReason") == "reexport_chain",
            "Re-export chain reason missing",
        )
        require(call["reachability"] == "unknown", "Wrong reachability")
        require(
            not call.get("calledSymbol"),
            "Re-export incorrectly attributed to a direct function call",
        )

    elif fixture == "component2-s6-side-effect":
        require(len(observations) == 1, "Expected one side-effect import")
        obs = observations[0]

        require(obs["importKind"] == "esm_side_effect", "Wrong import kind")
        require(obs["resolution"] == "resolved", "Import unresolved")
        require(obs["evidenceLevel"] == 1, "Wrong evidence level")
        require(not obs["callSites"], "Invented call for side-effect import")

    elif fixture in (
        "component2-s6-import-type",
        "component2-s6-import-type-alias",
    ):
        require(len(observations) == 1, "Expected one type-only import")
        obs = observations[0]

        require(obs["importKind"] == "esm_type_only", "Wrong import kind")
        require(obs["resolution"] == "type_only", "Wrong resolution")
        require(not obs["callSites"], "Type-only import has runtime calls")

    elif fixture == "component2-s6-ts-path-alias":
        require(len(observations) == 1, "Unexpected third-party observation")
        obs = observations[0]

        require(
            obs["importedSpecifier"] == "lodash",
            "Local alias treated as a package",
        )
        require(
            obs["purl"] == "pkg:npm/lodash@4.17.21",
            "Lodash package identity changed",
        )
        require(obs["resolution"] == "resolved", "Lodash import unresolved")
        require(len(obs["callSites"]) == 1, "Expected genuine Lodash call")
        require(
            obs["callSites"][0].get("calledSymbol") == "merge",
            "Genuine Lodash merge call missing",
        )
        require(
            obs["callSites"][0]["resolution"] == "resolved",
            "Genuine Lodash call unresolved",
        )


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
    main()
