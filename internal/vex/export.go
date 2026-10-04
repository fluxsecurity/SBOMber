package vex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

// SubjectModel selects what a statement's product is.
type SubjectModel string

const (
	// SubjectApplication is R5 rule 1: the scanned application at a commit
	// is the product and the vulnerable package is a versioned subcomponent.
	// Grype 0.112.0 and Trivy 0.70.0 do not act on this shape (issue #128).
	SubjectApplication SubjectModel = "application"
	// SubjectPackage makes the vulnerable package purl the product. This is
	// the shape the pinned consumers act on, but it reads as a claim about
	// the package rather than about this application.
	SubjectPackage SubjectModel = "package"
)

// DefaultSubject is the subject model used when none is given. Issue #128 is
// still open; flip this constant when the team settles it.
const DefaultSubject = SubjectApplication

// ParseSubject validates a --subject value.
func ParseSubject(s string) (SubjectModel, error) {
	switch SubjectModel(s) {
	case SubjectApplication, SubjectPackage:
		return SubjectModel(s), nil
	case "":
		return DefaultSubject, nil
	}
	return "", fmt.Errorf("unknown subject model %q (want %s or %s)", s, SubjectApplication, SubjectPackage)
}

// Options controls Export.
type Options struct {
	Subject SubjectModel
	// Product overrides the application product @id for every statement.
	// Only meaningful with SubjectApplication.
	Product string
	// Scan supplies repository identity and alias IDs. Optional for
	// SubjectPackage; SubjectApplication needs it unless Product is set.
	Scan *CanonicalScan
	// Timestamp stamps the document; zero means time.Now().
	Timestamp time.Time
	// Tooling is recorded in the document's tooling field.
	Tooling string
}

// Result is the exported document and what it covers.
type Result struct {
	Document Document
	Summary  Summary
}

// Export maps every decision through Map and builds the OpenVEX document.
// Any rejected decision fails the whole export: a VEX document that silently
// drops a finding is worse than none.
func Export(dr DecisionResults, opts Options) (*Result, error) {
	if dr.ScanID == "" {
		return nil, fmt.Errorf("decision-results has no scanId")
	}
	subject := opts.Subject
	if subject == "" {
		subject = DefaultSubject
	}
	if subject != SubjectApplication && subject != SubjectPackage {
		return nil, fmt.Errorf("unknown subject model %q", subject)
	}
	if opts.Product != "" && subject != SubjectApplication {
		return nil, fmt.Errorf("a product override applies only to the %s subject", SubjectApplication)
	}
	if opts.Scan != nil && opts.Scan.Scan.ScanID != "" && opts.Scan.Scan.ScanID != dr.ScanID {
		return nil, fmt.Errorf("canonical-scan is %s but decision-results is %s", opts.Scan.Scan.ScanID, dr.ScanID)
	}
	if err := checkVocabulary(dr.Decisions); err != nil {
		return nil, err
	}

	idx := indexScan(opts.Scan)
	summary := Summary{Decisions: len(dr.Decisions)}
	statements := make([]Statement, 0, len(dr.Decisions))
	for _, d := range dr.Decisions {
		m, err := Map(d)
		if err != nil {
			return nil, err
		}
		if m.Omitted() {
			summary.Omitted++
			summary.OmittedFindingIDs = append(summary.OmittedFindingIDs, d.FindingID)
			continue
		}
		st, err := buildStatement(d, m, subject, opts.Product, idx)
		if err != nil {
			return nil, err
		}
		switch m.Status {
		case StatusAffected:
			summary.Affected++
		case StatusUnderInvestigation:
			summary.UnderInvestigation++
		case StatusNotAffected:
			summary.NotAffected++
		}
		statements = append(statements, st)
	}

	// The @id is derived from the content, before timestamps are applied, so
	// the same decisions always produce the same identifier.
	content, err := json.Marshal(struct {
		ScanID     string
		Subject    SubjectModel
		Statements []Statement
	}{dr.ScanID, subject, statements})
	if err != nil {
		return nil, fmt.Errorf("hash statements: %w", err)
	}
	sum := sha256.Sum256(content)

	ts := opts.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	stamp := ts.UTC().Format(time.RFC3339)
	for i := range statements {
		if statements[i].Status == StatusAffected {
			statements[i].ActionStatementTimestamp = stamp
		}
	}

	return &Result{
		Document: Document{
			Context:    Context,
			ID:         fmt.Sprintf("urn:sbomber:vex:%s:%s", url.PathEscape(dr.ScanID), hex.EncodeToString(sum[:8])),
			Author:     "SBOMber",
			Role:       "Document Creator",
			Timestamp:  stamp,
			Version:    1,
			Tooling:    opts.Tooling,
			Statements: statements,
		},
		Summary: summary,
	}, nil
}

func buildStatement(d Decision, m Mapping, subject SubjectModel, product string, idx scanIndex) (Statement, error) {
	if d.VulnerabilityID == "" {
		return Statement{}, fmt.Errorf("%s: decision has no vulnerabilityId", d.FindingID)
	}
	if !strings.HasPrefix(d.PURL, "pkg:") {
		return Statement{}, fmt.Errorf("%s: decision has no package purl", d.FindingID)
	}
	f, inScan := idx.findings[d.FindingID]
	if inScan {
		if f.PURL != "" && f.PURL != d.PURL {
			return Statement{}, fmt.Errorf("%s: decision purl %s does not match canonical-scan purl %s", d.FindingID, d.PURL, f.PURL)
		}
		if f.VulnerabilityID != "" && f.VulnerabilityID != d.VulnerabilityID {
			return Statement{}, fmt.Errorf("%s: decision vulnerability %s does not match canonical-scan %s", d.FindingID, d.VulnerabilityID, f.VulnerabilityID)
		}
	}

	st := Statement{
		Vulnerability: Vulnerability{Name: d.VulnerabilityID, Aliases: aliases(d.VulnerabilityID, f.Aliases)},
		Status:        m.Status,
	}

	switch subject {
	case SubjectPackage:
		st.Products = []Product{{ID: d.PURL}}
	case SubjectApplication:
		ids, err := applicationIDs(d, product, idx)
		if err != nil {
			return Statement{}, err
		}
		for _, id := range ids {
			st.Products = append(st.Products, Product{ID: id, Subcomponents: []Subcomponent{{ID: d.PURL}}})
		}
	}

	notes := strings.TrimSpace(d.Justification)
	if err := checkLanguage(d.FindingID, "justification", notes); err != nil {
		return Statement{}, err
	}
	switch m.Status {
	case StatusAffected:
		if err := checkLanguage(d.FindingID, "action statement", m.ActionStatement); err != nil {
			return Statement{}, err
		}
		st.ActionStatement = m.ActionStatement
		st.StatusNotes = notes
	case StatusNotAffected:
		impact := "Manually reviewed by " + m.Reviewer + "."
		if notes != "" {
			impact += " " + notes
		}
		if err := checkLanguage(d.FindingID, "impact statement", impact); err != nil {
			return Statement{}, err
		}
		st.ImpactStatement = impact
	default:
		st.StatusNotes = notes
	}
	return st, nil
}

// applicationIDs resolves the application product for a decision: the
// override if given, otherwise every repository the finding occurs in, at its
// commit. Nothing is invented: a missing commit is an error.
func applicationIDs(d Decision, product string, idx scanIndex) ([]string, error) {
	if product != "" {
		return []string{product}, nil
	}
	f, ok := idx.findings[d.FindingID]
	if !ok {
		return nil, fmt.Errorf("%s: the %s subject needs the repository identity; pass --canonical-scan containing this finding, or --product", d.FindingID, SubjectApplication)
	}
	seen := map[string]bool{}
	var ids []string
	for _, oid := range f.OccurrenceIDs {
		repoID, ok := idx.occurrenceRepo[oid]
		if !ok {
			return nil, fmt.Errorf("%s: occurrence %s is not in canonical-scan", d.FindingID, oid)
		}
		repo, ok := idx.repos[repoID]
		if !ok {
			return nil, fmt.Errorf("%s: repository %s is not in canonical-scan", d.FindingID, repoID)
		}
		id, err := ApplicationPURL(repo)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", d.FindingID, err)
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("%s: finding has no occurrences to place it in a repository; pass --product", d.FindingID)
	}
	sort.Strings(ids)
	return ids, nil
}

// ApplicationPURL is the stable product identifier R5 rule 1 asks for: the
// repository's directory name at its commit SHA.
func ApplicationPURL(r Repository) (string, error) {
	if strings.TrimSpace(r.Commit) == "" {
		return "", fmt.Errorf("repository %s has no commit SHA; R5 needs a version or commit for the application subject, pass --product", r.RepositoryID)
	}
	name := path.Base(strings.TrimRight(strings.ReplaceAll(r.Path, "\\", "/"), "/"))
	if name == "" || name == "." || name == "/" {
		name = r.RepositoryID
	}
	if name == "" {
		return "", fmt.Errorf("repository has neither a path nor an id")
	}
	return "pkg:generic/" + url.PathEscape(name) + "@" + url.PathEscape(r.Commit), nil
}

func aliases(name string, from []string) []string {
	seen := map[string]bool{name: true}
	var out []string
	for _, a := range from {
		if a != "" && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

type scanIndex struct {
	findings       map[string]Finding
	occurrenceRepo map[string]string
	repos          map[string]Repository
}

func indexScan(s *CanonicalScan) scanIndex {
	idx := scanIndex{findings: map[string]Finding{}, occurrenceRepo: map[string]string{}, repos: map[string]Repository{}}
	if s == nil {
		return idx
	}
	for _, f := range s.Findings {
		idx.findings[f.FindingID] = f
	}
	for _, o := range s.Occurrences {
		idx.occurrenceRepo[o.OccurrenceID] = o.RepositoryID
	}
	for _, r := range s.Scan.Repositories {
		idx.repos[r.RepositoryID] = r
	}
	return idx
}
