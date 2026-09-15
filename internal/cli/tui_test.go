package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

const testCycloneDXXML = `<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <components>
    <component type="library"><name>lodash</name><version>4.18.1</version><purl>pkg:npm/lodash@4.18.1</purl></component>
  </components>
</bom>`

const testGroundTruthJSON = `{"bomFormat":"CycloneDX","components":[{"type":"library","name":"lodash","version":"4.18.1","purl":"pkg:npm/lodash@4.18.1"}]}`

// TestResultsModelGroundTruthCheckSuccess is the success case: selecting
// "Check ground-truth accuracy" on a single-repo results screen, entering
// a matching ground-truth SBOM path, and confirming shows a full report.
func TestResultsModelGroundTruthCheckSuccess(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	generatedPath := filepath.Join(dir, "sbom-cyclonedx.xml")
	if err := os.WriteFile(generatedPath, []byte(testCycloneDXXML), 0o644); err != nil {
		t.Fatalf("write generated sbom: %v", err)
	}
	groundTruthPath := filepath.Join(dir, "ground-truth.json")
	if err := os.WriteFile(groundTruthPath, []byte(testGroundTruthJSON), 0o644); err != nil {
		t.Fatalf("write ground truth: %v", err)
	}

	content := "output folder: " + dir + "\nexported SBOM: sbom-cyclonedx.xml\n"
	m := newResultsModel(content, dir)

	if m.groundTruthSBOM != generatedPath {
		t.Fatalf("expected groundTruthSBOM to be %q, got %q", generatedPath, m.groundTruthSBOM)
	}
	if !actionsInclude(m.actions, "Check ground-truth accuracy") {
		t.Fatalf("expected the ground-truth action to be offered, got %v", m.actions)
	}

	m.cursor = len(m.actions) - 1
	m = updateResultsModel(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.gtState != gtStatePathInput {
		t.Fatalf("expected gtStatePathInput after selecting the action, got %d", m.gtState)
	}

	m = updateResultsModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(groundTruthPath)})
	m = updateResultsModel(t, m, tea.KeyMsg{Type: tea.KeyEnter})

	if m.gtState != gtStateReport {
		t.Fatalf("expected gtStateReport after a successful check, got %d, err=%q", m.gtState, m.gtErr)
	}
	if !strings.Contains(m.gtReport, "Version Accuracy: 100.0%") {
		t.Fatalf("expected the report to show 100%% version accuracy, got %q", m.gtReport)
	}
}

// TestResultsModelGroundTruthCheckMissingFile is the failure/unknown-path
// case: entering a ground-truth path that does not exist must show an
// error and stay on the input screen, not crash or silently proceed.
func TestResultsModelGroundTruthCheckMissingFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sbom-cyclonedx.xml"), []byte(testCycloneDXXML), 0o644); err != nil {
		t.Fatalf("write generated sbom: %v", err)
	}

	content := "output folder: " + dir + "\nexported SBOM: sbom-cyclonedx.xml\n"
	m := newResultsModel(content, dir)
	m.cursor = len(m.actions) - 1
	m = updateResultsModel(t, m, tea.KeyMsg{Type: tea.KeyEnter})

	missing := filepath.Join(dir, "does-not-exist.json")
	m = updateResultsModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(missing)})
	m = updateResultsModel(t, m, tea.KeyMsg{Type: tea.KeyEnter})

	if m.gtState != gtStatePathInput {
		t.Fatalf("expected to stay on gtStatePathInput after a failed check, got %d", m.gtState)
	}
	if m.gtErr == "" {
		t.Fatal("expected gtErr to be set for a missing ground-truth file")
	}
}

// TestResultsModelSkipsGroundTruthActionForMultiRepo is the boundary case:
// when the scan output represents more than one repo, there is no single
// generated SBOM to compare, so the action must not be offered at all.
func TestResultsModelSkipsGroundTruthActionForMultiRepo(t *testing.T) {
	t.Parallel()

	dirA := t.TempDir()
	dirB := t.TempDir()
	content := "output folder: " + dirA + "\nexported SBOM: sbom-cyclonedx.xml\n" +
		"output folder: " + dirB + "\nexported SBOM: sbom-cyclonedx.xml\n"

	m := newResultsModel(content, dirA)

	if m.groundTruthSBOM != "" {
		t.Fatalf("expected no groundTruthSBOM for a multi-repo scan, got %q", m.groundTruthSBOM)
	}
	if actionsInclude(m.actions, "Check ground-truth accuracy") {
		t.Fatalf("expected the ground-truth action not to be offered, got %v", m.actions)
	}
}

func actionsInclude(actions []string, target string) bool {
	for _, a := range actions {
		if a == target {
			return true
		}
	}
	return false
}

func updateResultsModel(t *testing.T, m resultsModel, msg tea.Msg) resultsModel {
	t.Helper()
	updated, _ := m.Update(msg)
	next, ok := updated.(resultsModel)
	if !ok {
		t.Fatalf("Update returned unexpected model type %T", updated)
	}
	return next
}
