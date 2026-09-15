package canonicalscan

import "testing"

func TestJoinFindingsByPURL(t *testing.T) {
	components := []Component{
		{Purl: "pkg:npm/lodash@4.18.1", Name: "lodash", Version: "4.18.1", Ecosystem: "npm"},
	}
	findings := []Finding{
		{FindingID: "SAMPLE-FIXTURE-VULN-0001|pkg:npm/lodash@4.18.1", VulnerabilityID: "SAMPLE-FIXTURE-VULN-0001", ComponentPurl: "pkg:npm/lodash@4.18.1", Severity: "medium"},
	}

	result := JoinFindingsByPURL(findings, components)

	if len(result.Joined) != 1 {
		t.Fatalf("expected 1 joined finding, got %d", len(result.Joined))
	}
	if len(result.Unjoined) != 0 {
		t.Fatalf("expected 0 unjoined findings, got %d", len(result.Unjoined))
	}
	if result.Joined[0].ComponentPurl != "pkg:npm/lodash@4.18.1" {
		t.Errorf("expected joined finding to keep its componentPurl, got %q", result.Joined[0].ComponentPurl)
	}
}

func TestJoinFindingsByPURLMissingPURL(t *testing.T) {
	components := []Component{
		{Purl: "pkg:npm/lodash@4.18.1", Name: "lodash", Version: "4.18.1", Ecosystem: "npm"},
	}
	findings := []Finding{
		{FindingID: "CVE-2024-11111", VulnerabilityID: "CVE-2024-11111", ComponentPurl: "", Severity: "medium"},
	}

	result := JoinFindingsByPURL(findings, components)

	if len(result.Joined) != 0 {
		t.Fatalf("expected 0 joined findings for an empty PURL, got %d", len(result.Joined))
	}
	if len(result.Unjoined) != 1 {
		t.Fatalf("expected 1 unjoined finding, got %d", len(result.Unjoined))
	}
}

func TestJoinFindingsByPURLExactVersionOnly(t *testing.T) {
	// Boundary case: a finding against a *different version* of the same
	// package must NOT join. Matching on name alone (ignoring version) is
	// exactly the false-positive/false-negative class this identity model
	// exists to prevent.
	components := []Component{
		{Purl: "pkg:npm/lodash@4.18.1", Name: "lodash", Version: "4.18.1", Ecosystem: "npm"},
	}
	findings := []Finding{
		{FindingID: "CVE-2024-22222|pkg:npm/lodash@4.17.21", VulnerabilityID: "CVE-2024-22222", ComponentPurl: "pkg:npm/lodash@4.17.21", Severity: "high"},
	}

	result := JoinFindingsByPURL(findings, components)

	if len(result.Joined) != 0 {
		t.Fatalf("expected a different-version PURL not to join, got %d joined", len(result.Joined))
	}
	if len(result.Unjoined) != 1 {
		t.Fatalf("expected the mismatched-version finding to be unjoined, got %d", len(result.Unjoined))
	}
}
