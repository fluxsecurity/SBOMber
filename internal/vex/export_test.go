package vex

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	decisionsFixture = "../../contracts/fixtures/decision-results.sample.json"
	scanFixture      = "../../contracts/fixtures/canonical-scan.sample.json"
	demoAppProduct   = "pkg:generic/demo-app@8f2a1c9d4e7b3a5f6c8d9e0a1b2c3d4e5f6a7b8c"
)

var fixedTime = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)

func loadFixtures(t *testing.T) (DecisionResults, *CanonicalScan) {
	t.Helper()
	dr, err := LoadDecisionResults(decisionsFixture)
	if err != nil {
		t.Fatal(err)
	}
	scan, err := LoadCanonicalScan(scanFixture)
	if err != nil {
		t.Fatal(err)
	}
	return dr, scan
}

func statementFor(t *testing.T, doc Document, vuln string) Statement {
	t.Helper()
	for _, s := range doc.Statements {
		if s.Vulnerability.Name == vuln {
			return s
		}
	}
	t.Fatalf("no statement for %s", vuln)
	return Statement{}
}

func TestExportFixturePackageSubject(t *testing.T) {
	dr, scan := loadFixtures(t)
	res, err := Export(dr, Options{Subject: SubjectPackage, Scan: scan, Timestamp: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	doc := res.Document
	if doc.Context != Context || doc.Version != 1 || doc.Author != "SBOMber" || doc.Timestamp != "2026-10-04T00:00:00Z" {
		t.Fatalf("document header = %+v", doc)
	}
	if !strings.HasPrefix(doc.ID, "urn:sbomber:vex:scan-2026-08-12-0001:") {
		t.Fatalf("@id = %s", doc.ID)
	}

	want := Summary{Decisions: 4, Affected: 1, UnderInvestigation: 3}
	if !reflect.DeepEqual(res.Summary, want) {
		t.Fatalf("summary = %+v, want %+v", res.Summary, want)
	}

	tests := []struct {
		vuln, purl, status string
		aliases            []string
	}{
		{"CVE-2021-23337", "pkg:npm/lodash@4.17.20", StatusAffected, []string{"GHSA-35jh-r3h4-6jhm"}},
		{"CVE-2020-28168", "pkg:npm/axios@0.21.0", StatusUnderInvestigation, nil},
		{"CVE-2021-44906", "pkg:npm/minimist@1.2.5", StatusUnderInvestigation, nil},
		{"CVE-2019-10744", "pkg:npm/lodash@3.10.1", StatusUnderInvestigation, nil},
	}
	for _, tt := range tests {
		s := statementFor(t, doc, tt.vuln)
		if s.Status != tt.status {
			t.Errorf("%s status = %s, want %s", tt.vuln, s.Status, tt.status)
		}
		if len(s.Products) != 1 || s.Products[0].ID != tt.purl || len(s.Products[0].Subcomponents) != 0 {
			t.Errorf("%s products = %+v, want the package purl %s", tt.vuln, s.Products, tt.purl)
		}
		if tt.aliases != nil && !reflect.DeepEqual(s.Vulnerability.Aliases, tt.aliases) {
			t.Errorf("%s aliases = %v, want %v", tt.vuln, s.Vulnerability.Aliases, tt.aliases)
		}
		if s.Status == StatusAffected && (s.ActionStatement == "" || s.ActionStatementTimestamp == "") {
			t.Errorf("%s affected without action statement and timestamp", tt.vuln)
		}
		if s.Status != StatusAffected && s.ActionStatement != "" {
			t.Errorf("%s carries an action statement on %s", tt.vuln, s.Status)
		}
		if s.StatusNotes == "" {
			t.Errorf("%s has no status notes", tt.vuln)
		}
	}
}

func TestExportFixtureApplicationSubject(t *testing.T) {
	dr, scan := loadFixtures(t)
	res, err := Export(dr, Options{Subject: SubjectApplication, Scan: scan, Timestamp: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range res.Document.Statements {
		if len(s.Products) != 1 {
			t.Fatalf("%s products = %+v", s.Vulnerability.Name, s.Products)
		}
		p := s.Products[0]
		if p.ID != demoAppProduct {
			t.Errorf("%s product = %s, want %s", s.Vulnerability.Name, p.ID, demoAppProduct)
		}
		if len(p.Subcomponents) != 1 || !strings.HasPrefix(p.Subcomponents[0].ID, "pkg:npm/") {
			t.Errorf("%s subcomponents = %+v, want the package purl", s.Vulnerability.Name, p.Subcomponents)
		}
	}
	if got := statementFor(t, res.Document, "CVE-2019-10744").Products[0].Subcomponents[0].ID; got != "pkg:npm/lodash@3.10.1" {
		t.Errorf("nested lodash subcomponent = %s, want pkg:npm/lodash@3.10.1", got)
	}
}

func TestDefaultSubjectIsApplication(t *testing.T) {
	if DefaultSubject != SubjectApplication {
		t.Fatalf("DefaultSubject = %s; change this test deliberately when issue #128 is settled", DefaultSubject)
	}
	got, err := ParseSubject("")
	if err != nil || got != DefaultSubject {
		t.Fatalf("ParseSubject(\"\") = %s, %v", got, err)
	}
	if _, err := ParseSubject("repo"); err == nil {
		t.Fatal("ParseSubject accepted an unknown model")
	}
}

func TestExportApplicationSubjectNeedsIdentity(t *testing.T) {
	dr, scan := loadFixtures(t)

	if _, err := Export(dr, Options{Subject: SubjectApplication}); err == nil || !strings.Contains(err.Error(), "--canonical-scan") {
		t.Fatalf("no scan, no product: error = %v, want a pointer to --canonical-scan", err)
	}

	scan.Scan.Repositories[0].Commit = ""
	if _, err := Export(dr, Options{Subject: SubjectApplication, Scan: scan}); err == nil || !strings.Contains(err.Error(), "no commit SHA") {
		t.Fatalf("missing commit: error = %v, want a commit error", err)
	}

	res, err := Export(dr, Options{Subject: SubjectApplication, Product: "pkg:github/acme/demo-app@v1.2.0", Timestamp: fixedTime})
	if err != nil {
		t.Fatalf("product override: %v", err)
	}
	if got := res.Document.Statements[0].Products[0].ID; got != "pkg:github/acme/demo-app@v1.2.0" {
		t.Fatalf("product override ignored: %s", got)
	}

	if _, err := Export(dr, Options{Subject: SubjectPackage, Product: "x"}); err == nil {
		t.Fatal("product override accepted with the package subject")
	}
}

func TestExportUnsupportedIsOmittedButCounted(t *testing.T) {
	dr := DecisionResults{ScanID: "scan-1", Decisions: []Decision{
		{FindingID: "find-001", VulnerabilityID: "CVE-1", PURL: "pkg:npm/a@1.0.0", State: StateUnsupported, VEXMapping: &VEXMapping{Statement: "omit"}},
		{FindingID: "find-002", VulnerabilityID: "CVE-2", PURL: "pkg:npm/b@1.0.0", State: StateUnknown, VEXMapping: &VEXMapping{Statement: "under_investigation"}},
	}}
	res, err := Export(dr, Options{Subject: SubjectPackage, Timestamp: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Document.Statements) != 1 || res.Document.Statements[0].Vulnerability.Name != "CVE-2" {
		t.Fatalf("statements = %+v, want only CVE-2", res.Document.Statements)
	}
	if res.Summary.Omitted != 1 || !reflect.DeepEqual(res.Summary.OmittedFindingIDs, []string{"find-001"}) {
		t.Fatalf("summary = %+v, want find-001 omitted", res.Summary)
	}
}

func TestExportManualNotAffected(t *testing.T) {
	dr := DecisionResults{ScanID: "scan-1", Decisions: []Decision{{
		FindingID: "find-001", VulnerabilityID: "CVE-1", PURL: "pkg:npm/a@1.0.0", State: StateNoUsageDetected,
		Justification: "Reviewer confirmed the vulnerable branch is compiled out.",
		VEXMapping:    &VEXMapping{Statement: "not_affected", ManuallyReviewedBy: "A. Reviewer"},
	}}}
	res, err := Export(dr, Options{Subject: SubjectPackage, Timestamp: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	s := res.Document.Statements[0]
	if s.Status != StatusNotAffected || !strings.Contains(s.ImpactStatement, "A. Reviewer") {
		t.Fatalf("statement = %+v, want not_affected naming the reviewer", s)
	}
}

func TestExportRejectsJoinMismatch(t *testing.T) {
	dr, scan := loadFixtures(t)
	dr.Decisions[0].PURL = "pkg:npm/lodash@4.17.21"
	if _, err := Export(dr, Options{Subject: SubjectPackage, Scan: scan}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error = %v, want a purl mismatch", err)
	}

	dr, scan = loadFixtures(t)
	scan.Scan.ScanID = "scan-other"
	if _, err := Export(dr, Options{Subject: SubjectPackage, Scan: scan}); err == nil {
		t.Fatal("accepted a canonical-scan from a different scan")
	}
}

func TestExportIDIsDeterministic(t *testing.T) {
	dr, scan := loadFixtures(t)
	a, err := Export(dr, Options{Subject: SubjectPackage, Scan: scan, Timestamp: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Export(dr, Options{Subject: SubjectPackage, Scan: scan, Timestamp: fixedTime.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if a.Document.ID != b.Document.ID {
		t.Fatalf("@id changed with the timestamp: %s vs %s", a.Document.ID, b.Document.ID)
	}
	c, err := Export(dr, Options{Subject: SubjectApplication, Scan: scan, Timestamp: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if a.Document.ID == c.Document.ID {
		t.Fatal("package and application documents share an @id")
	}
}

// The document must never contain not_affected or a banned phrase when
// built from the fixture, whichever subject is used.
func TestExportFixtureOutputIsClean(t *testing.T) {
	dr, scan := loadFixtures(t)
	for _, subject := range []SubjectModel{SubjectApplication, SubjectPackage} {
		res, err := Export(dr, Options{Subject: subject, Scan: scan, Timestamp: fixedTime})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(res.Document)
		text := strings.ToLower(string(raw))
		if strings.Contains(text, `"not_affected"`) {
			t.Errorf("%s: fixture produced not_affected", subject)
		}
		if strings.Contains(text, "in_triage") {
			t.Errorf("%s: fixture produced in_triage", subject)
		}
		for _, p := range BannedPhrases {
			if strings.Contains(text, p) {
				t.Errorf("%s: document contains %q", subject, p)
			}
		}
	}
}
