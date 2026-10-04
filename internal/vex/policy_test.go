package vex

import (
	"errors"
	"strings"
	"testing"
)

func TestMap(t *testing.T) {
	tests := []struct {
		name       string
		d          Decision
		wantStatus string
		wantOmit   bool
		wantErr    string
	}{
		{
			name:       "usage detected is affected",
			d:          Decision{FindingID: "f", State: StateUsageDetected, VEXMapping: &VEXMapping{Statement: "affected", ActionStatement: "Upgrade lodash to 4.17.21."}},
			wantStatus: StatusAffected,
		},
		{
			name:       "usage detected with no statement still derives affected",
			d:          Decision{FindingID: "f", State: StateUsageDetected, VEXMapping: &VEXMapping{ActionStatement: "Upgrade."}},
			wantStatus: StatusAffected,
		},
		{
			name:    "affected without an action statement is rejected",
			d:       Decision{FindingID: "f", State: StateUsageDetected, VEXMapping: &VEXMapping{Statement: "affected"}},
			wantErr: "action statement",
		},
		{
			name:    "affected with no vexMapping at all is rejected",
			d:       Decision{FindingID: "f", State: StateUsageDetected},
			wantErr: "action statement",
		},
		{
			name:       "no usage detected is under_investigation",
			d:          Decision{FindingID: "f", State: StateNoUsageDetected, VEXMapping: &VEXMapping{Statement: "under_investigation"}},
			wantStatus: StatusUnderInvestigation,
		},
		{
			name:       "unknown is under_investigation",
			d:          Decision{FindingID: "f", State: StateUnknown, VEXMapping: &VEXMapping{Statement: "under_investigation"}},
			wantStatus: StatusUnderInvestigation,
		},
		{
			name:       "unknown with no vexMapping derives under_investigation",
			d:          Decision{FindingID: "f", State: StateUnknown},
			wantStatus: StatusUnderInvestigation,
		},
		{
			name:     "unsupported is omitted",
			d:        Decision{FindingID: "f", State: StateUnsupported, VEXMapping: &VEXMapping{Statement: "omit"}},
			wantOmit: true,
		},
		{
			name:    "no usage detected never becomes not_affected without a reviewer",
			d:       Decision{FindingID: "f", State: StateNoUsageDetected, VEXMapping: &VEXMapping{Statement: "not_affected"}},
			wantErr: "named manual reviewer",
		},
		{
			name:    "blank reviewer does not count",
			d:       Decision{FindingID: "f", State: StateUnknown, VEXMapping: &VEXMapping{Statement: "not_affected", ManuallyReviewedBy: "  "}},
			wantErr: "named manual reviewer",
		},
		{
			name:       "manual not_affected with a named reviewer is kept",
			d:          Decision{FindingID: "f", State: StateNoUsageDetected, VEXMapping: &VEXMapping{Statement: "not_affected", ManuallyReviewedBy: "A. Reviewer"}},
			wantStatus: StatusNotAffected,
		},
		{
			name:    "not_affected on unsupported is rejected",
			d:       Decision{FindingID: "f", State: StateUnsupported, VEXMapping: &VEXMapping{Statement: "not_affected", ManuallyReviewedBy: "A. Reviewer"}},
			wantErr: "unsupported",
		},
		{
			name:    "unknown cannot assert affected",
			d:       Decision{FindingID: "f", State: StateUnknown, VEXMapping: &VEXMapping{Statement: "affected", ActionStatement: "Upgrade."}},
			wantErr: "maps to under_investigation",
		},
		{
			name:    "usage detected cannot be downgraded to under_investigation",
			d:       Decision{FindingID: "f", State: StateUsageDetected, VEXMapping: &VEXMapping{Statement: "under_investigation"}},
			wantErr: "maps to affected",
		},
		{
			name:    "unsupported cannot assert a status",
			d:       Decision{FindingID: "f", State: StateUnsupported, VEXMapping: &VEXMapping{Statement: "under_investigation"}},
			wantErr: "maps to omit",
		},
		{
			name:    "in_triage is the wrong vocabulary",
			d:       Decision{FindingID: "f", State: StateNoUsageDetected, VEXMapping: &VEXMapping{Statement: "in_triage"}},
			wantErr: "mixed VEX vocabulary",
		},
		{
			name:    "unknown state is rejected",
			d:       Decision{FindingID: "f", State: "safe"},
			wantErr: "unknown decision state",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Map(tt.d)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Map() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Map() unexpected error: %v", err)
			}
			if m.Omitted() != tt.wantOmit {
				t.Fatalf("Omitted() = %v, want %v", m.Omitted(), tt.wantOmit)
			}
			if m.Status != tt.wantStatus {
				t.Fatalf("Status = %q, want %q", m.Status, tt.wantStatus)
			}
		})
	}
}

// No state may ever produce not_affected on its own.
func TestMapNeverDerivesNotAffected(t *testing.T) {
	for _, state := range []string{StateUsageDetected, StateNoUsageDetected, StateUnknown, StateUnsupported} {
		m, _ := Map(Decision{FindingID: "f", State: state, VEXMapping: &VEXMapping{ActionStatement: "Upgrade."}})
		if m.Status == StatusNotAffected {
			t.Errorf("state %s derived not_affected", state)
		}
	}
}

func TestExportRejectsMixedVocabulary(t *testing.T) {
	dr := DecisionResults{
		ScanID: "scan-1",
		Decisions: []Decision{
			{FindingID: "find-001", VulnerabilityID: "CVE-1", PURL: "pkg:npm/a@1.0.0", State: StateNoUsageDetected, VEXMapping: &VEXMapping{Statement: "under_investigation"}},
			{FindingID: "find-002", VulnerabilityID: "CVE-2", PURL: "pkg:npm/b@1.0.0", State: StateUnknown, VEXMapping: &VEXMapping{Statement: "in_triage"}},
			{FindingID: "find-003", VulnerabilityID: "CVE-3", PURL: "pkg:npm/c@1.0.0", State: StateNoUsageDetected, VEXMapping: &VEXMapping{Statement: "in_triage"}},
		},
	}
	res, err := Export(dr, Options{Subject: SubjectPackage})
	if err == nil {
		t.Fatalf("Export() accepted a mixed-vocabulary document: %+v", res.Document)
	}
	if !errors.Is(err, ErrMixedVocabulary) {
		t.Fatalf("error = %v, want ErrMixedVocabulary", err)
	}
	for _, id := range []string{"find-002", "find-003"} {
		if !strings.Contains(err.Error(), id) {
			t.Errorf("error %q does not name %s", err, id)
		}
	}
}

func TestExportRejectsBannedLanguage(t *testing.T) {
	for _, phrase := range BannedPhrases {
		dr := DecisionResults{ScanID: "scan-1", Decisions: []Decision{{
			FindingID: "find-001", VulnerabilityID: "CVE-1", PURL: "pkg:npm/a@1.0.0", State: StateNoUsageDetected,
			Justification: "The analysis suggests this " + strings.ToUpper(phrase) + ".",
			VEXMapping:    &VEXMapping{Statement: "under_investigation"},
		}}}
		if _, err := Export(dr, Options{Subject: SubjectPackage}); err == nil || !strings.Contains(err.Error(), "banned phrase") {
			t.Errorf("phrase %q: error = %v, want banned phrase rejection", phrase, err)
		}
	}
}
