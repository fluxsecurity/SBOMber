package usagegraph

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Xsamsx/SBOMber/internal/canonicalscan"
)

// DefaultMaxCanonicalScanBytes bounds how much of canonical-scan.json is read.
const DefaultMaxCanonicalScanBytes = int64(64 << 20)

// CanonicalScan is the subset of canonical-scan.json (contract 1.0.0) that
// Component 2 reads. Field names follow the published contract, not the
// internal canonicalscan Go types, which use different names.
type CanonicalScan struct {
	SchemaVersion string                `json:"schemaVersion"`
	Scan          CanonicalScanHeader   `json:"scan"`
	Occurrences   []CanonicalOccurrence `json:"occurrences"`
}

// CanonicalScanHeader is canonical-scan.json's scan object.
type CanonicalScanHeader struct {
	ScanID       string                `json:"scanId"`
	Status       string                `json:"status"`
	Repositories []CanonicalRepository `json:"repositories"`
}

// CanonicalRepository is one scanned repository.
type CanonicalRepository struct {
	RepositoryID string `json:"repositoryId"`
	Path         string `json:"path"`
	Source       string `json:"source"`
}

// CanonicalOccurrence is one package occurrence as published in the contract.
type CanonicalOccurrence struct {
	OccurrenceID   string   `json:"occurrenceId"`
	PURL           string   `json:"purl"`
	RepositoryID   string   `json:"repositoryId"`
	Workspace      string   `json:"workspace"`
	Manifest       string   `json:"manifest"`
	Relationship   string   `json:"relationship"`
	DependencyPath []string `json:"dependencyPath"`
	InstallPath    string   `json:"installPath"`
	Scope          string   `json:"scope"`
}

// ReadCanonicalScan decodes and checks the parts of canonical-scan.json the
// usage graph depends on. Input larger than maxBytes is rejected rather than
// truncated, so a partial document is never analysed as if it were whole.
func ReadCanonicalScan(reader io.Reader, maxBytes int64) (CanonicalScan, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxCanonicalScanBytes
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return CanonicalScan{}, fmt.Errorf("read canonical scan: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return CanonicalScan{}, fmt.Errorf("canonical scan is larger than %d bytes", maxBytes)
	}

	var scan CanonicalScan
	if err := json.Unmarshal(data, &scan); err != nil {
		return CanonicalScan{}, fmt.Errorf("decode canonical scan: %w", err)
	}
	if err := scan.validate(); err != nil {
		return CanonicalScan{}, err
	}
	return scan, nil
}

func (scan CanonicalScan) validate() error {
	var problems []string
	if scan.SchemaVersion != "1.0.0" {
		problems = append(problems, fmt.Sprintf(
			"schemaVersion is %q, this reader supports 1.0.0", scan.SchemaVersion))
	}
	if scan.Scan.ScanID == "" {
		problems = append(problems, "scan.scanId is missing")
	}

	repositories := make(map[string]struct{})
	for index, repository := range scan.Scan.Repositories {
		if repository.RepositoryID == "" {
			problems = append(problems, fmt.Sprintf("scan.repositories[%d] has no repositoryId", index))
			continue
		}
		if _, duplicate := repositories[repository.RepositoryID]; duplicate {
			problems = append(problems, fmt.Sprintf("duplicate repositoryId %q", repository.RepositoryID))
		}
		repositories[repository.RepositoryID] = struct{}{}
	}

	occurrences := make(map[string]struct{})
	for index, occurrence := range scan.Occurrences {
		where := "occurrences[" + strconv.Itoa(index) + "]"
		switch {
		case occurrence.OccurrenceID == "":
			problems = append(problems, where+" has no occurrenceId")
		case occurrence.PURL == "":
			problems = append(problems, where+" has no purl")
		case occurrence.RepositoryID == "":
			problems = append(problems, where+" has no repositoryId")
		case occurrence.Relationship != "direct" && occurrence.Relationship != "transitive":
			problems = append(problems, fmt.Sprintf(
				"%s relationship is %q, want direct or transitive", where, occurrence.Relationship))
		}
		if _, duplicate := occurrences[occurrence.OccurrenceID]; duplicate && occurrence.OccurrenceID != "" {
			problems = append(problems, fmt.Sprintf("duplicate occurrenceId %q", occurrence.OccurrenceID))
		}
		occurrences[occurrence.OccurrenceID] = struct{}{}
		if _, known := repositories[occurrence.RepositoryID]; !known && occurrence.RepositoryID != "" {
			problems = append(problems, fmt.Sprintf(
				"%s references repositoryId %q, which is not in scan.repositories", where, occurrence.RepositoryID))
		}
	}

	if len(problems) == 0 {
		return nil
	}
	if len(problems) > 5 {
		problems = append(problems[:5], fmt.Sprintf("and %d more", len(problems)-5))
	}
	return errors.New("canonical scan is not valid: " + strings.Join(problems, "; "))
}

// OccurrenceInputs maps contract occurrences onto the producer's input.
// relationship carries direct/transitive; scope is the build scope.
func (scan CanonicalScan) OccurrenceInputs() []OccurrenceInput {
	inputs := make([]OccurrenceInput, 0, len(scan.Occurrences))
	for _, occurrence := range scan.Occurrences {
		dependencyPath := occurrence.DependencyPath
		if dependencyPath == nil {
			dependencyPath = []string{}
		}
		inputs = append(inputs, OccurrenceInput{
			RepositoryID: occurrence.RepositoryID,
			Occurrence: canonicalscan.Occurrence{
				OccurrenceID:   occurrence.OccurrenceID,
				ComponentPurl:  occurrence.PURL,
				Workspace:      occurrence.Workspace,
				ManifestPath:   occurrence.Manifest,
				DependencyPath: dependencyPath,
				Scope:          occurrence.Relationship,
				BuildScope:     occurrence.Scope,
			},
		})
	}
	return inputs
}

// ParseDeclaredEntryPoint reads an entry point written as
// [repositoryId=]file:function[:line]. Use <module> as the function to
// declare a file's top-level code. defaultRepository applies when no
// repositoryId is given.
func ParseDeclaredEntryPoint(spec string, defaultRepository string) (DeclaredEntryPoint, error) {
	invalid := func(reason string) (DeclaredEntryPoint, error) {
		return DeclaredEntryPoint{}, fmt.Errorf(
			"entry point %q: %s (want [repositoryId=]file:function[:line])", spec, reason)
	}

	repository := defaultRepository
	rest := spec
	// A repositoryId prefix comes before the first "=" and has no "/", so a
	// path such as src/a=b.js is still read as a file.
	if equals := strings.Index(spec, "="); equals >= 0 &&
		!strings.Contains(spec[:equals], "/") {
		colon := strings.Index(spec, ":")
		if colon < 0 || equals < colon {
			repository = spec[:equals]
			rest = spec[equals+1:]
		}
	}
	if repository == "" {
		return invalid("name the repository with repositoryId= when the scan has more than one")
	}

	parts := strings.Split(rest, ":")
	line := 0
	if len(parts) == 3 {
		parsed, err := strconv.Atoi(parts[2])
		if err != nil || parsed < 1 {
			return invalid("line must be a positive number")
		}
		line = parsed
		parts = parts[:2]
	}
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return invalid("missing file or function")
	}
	return DeclaredEntryPoint{
		RepositoryID: repository,
		File:         parts[0],
		Function:     parts[1],
		Line:         line,
	}, nil
}
