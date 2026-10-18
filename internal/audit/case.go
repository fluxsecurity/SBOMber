package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/Xsamsx/SBOMber/internal/decision"
)

// File names inside a case directory. The three inputs are the upstream
// contract files exactly as Components 1-3 produced them for the pinned
// repository; the harness never edits them.
const (
	CanonicalScanFile = "canonical-scan.json"
	UsageGraphFile    = "usage-graph.json"
	LocalisationFile  = "localisation.json"
	LabelsFile        = "labels.json"
)

// Case is one labelled end-to-end case on disk.
type Case struct {
	Dir    string
	Labels LabelSet
	Scan   decision.CanonicalScan
	Graph  decision.UsageGraph
	Loc    decision.LocalisationReport
}

// DiscoverCases returns every immediate subdirectory of root that contains
// a labels.json, sorted by name. A subdirectory without labels.json is
// ignored, so work-in-progress material can sit alongside finished cases.
func DiscoverCases(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		if _, err := os.Stat(filepath.Join(dir, LabelsFile)); err == nil {
			dirs = append(dirs, dir)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	sort.Strings(dirs)
	return dirs, nil
}

// LoadCase reads one case directory: the labels and the three upstream
// contract files.
func LoadCase(dir string) (Case, error) {
	c := Case{Dir: dir}
	var err error
	if c.Labels, err = LoadLabels(filepath.Join(dir, LabelsFile)); err != nil {
		return c, err
	}
	if c.Scan, err = decision.LoadCanonicalScan(filepath.Join(dir, CanonicalScanFile)); err != nil {
		return c, fmt.Errorf("%s: %w", dir, err)
	}
	if c.Graph, err = decision.LoadUsageGraph(filepath.Join(dir, UsageGraphFile)); err != nil {
		return c, fmt.Errorf("%s: %w", dir, err)
	}
	if c.Loc, err = decision.LoadLocalisationReport(filepath.Join(dir, LocalisationFile)); err != nil {
		return c, fmt.Errorf("%s: %w", dir, err)
	}
	if c.Scan.Scan.ScanID == "" {
		return c, fmt.Errorf("%s: %s has no scan.scanId", dir, CanonicalScanFile)
	}
	// The join is keyed on findingId and occurrenceId, which are positions
	// within one scan. Inputs from different scans would join silently, so
	// all three must name the same scanId.
	for _, name := range []string{UsageGraphFile, LocalisationFile} {
		id, err := readScanID(filepath.Join(dir, name))
		if err != nil {
			return c, fmt.Errorf("%s: %w", dir, err)
		}
		if id != c.Scan.Scan.ScanID {
			return c, fmt.Errorf("%s: %s has scanId %q, %s has %q (inputs must come from one scan)",
				dir, name, id, CanonicalScanFile, c.Scan.Scan.ScanID)
		}
	}
	return c, nil
}

// readScanID reads the top-level scanId of usage-graph.json or
// localisation.json, which the decision package's input types do not keep.
func readScanID(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var v struct {
		ScanID string `json:"scanId"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return "", fmt.Errorf("decode %s: %w", path, err)
	}
	return v.ScanID, nil
}

// Replay runs the case through the same function `sbomber decide` uses, so
// the harness measures the shipped decision path, not a copy of it.
func (c Case) Replay() (decision.Results, error) {
	res, err := decision.BuildResults(c.Scan, c.Graph, c.Loc)
	if err != nil {
		return decision.Results{}, fmt.Errorf("%s: %w", c.Dir, err)
	}
	return res, nil
}
