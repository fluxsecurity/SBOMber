package sbom

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Xsamsx/SBOMber/internal/deps"
)

const (
	cycloneDXFilename     = "sbom-cyclonedx.xml"
	cycloneDXJSONFilename = "sbom-cyclonedx.json"
	spdxFilename          = "sbom.spdx"
)

type cycloneDXBom struct {
	XMLName      xml.Name          `xml:"bom"`
	Xmlns        string            `xml:"xmlns,attr"`
	Version      int               `xml:"version,attr"`
	Metadata     cycloneDXMetadata `xml:"metadata"`
	Components   *componentList    `xml:"components,omitempty"`
	Dependencies *dependenciesList `xml:"dependencies,omitempty"`
}

type cycloneDXMetadata struct {
	Timestamp string             `xml:"timestamp"`
	Component cycloneDXComponent `xml:"component"`
}

type componentList struct {
	Components []cycloneDXComponent `xml:"component"`
}

type dependenciesList struct {
	Dependencies []cycloneDXDependency `xml:"dependency"`
}

type cycloneDXDependency struct {
	Ref          string          `xml:"ref,attr"`
	Dependencies []dependencyRef `xml:"dependency,omitempty"`
}

type dependencyRef struct {
	Ref string `xml:"ref,attr"`
}

type cycloneDXComponent struct {
	Type       string          `xml:"type,attr"`
	BomRef     string          `xml:"bom-ref,attr,omitempty"`
	Name       string          `xml:"name"`
	Version    string          `xml:"version,omitempty"`
	Scope      string          `xml:"scope,omitempty"`
	Purl       string          `xml:"purl,omitempty"`
	Properties *propertiesList `xml:"properties,omitempty"`
}

type propertiesList struct {
	Properties []cycloneDXProperty `xml:"property"`
}

type cycloneDXProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

// CycloneDX JSON structures

type cycloneDXJSONBom struct {
	BOMFormat    string                   `json:"bomFormat"`
	SpecVersion  string                   `json:"specVersion"`
	Version      int                      `json:"version"`
	Metadata     cycloneDXJSONMetadata    `json:"metadata"`
	Components   []cycloneDXJSONComponent `json:"components"`
	Dependencies []cycloneDXJSONDep       `json:"dependencies"`
}

type cycloneDXJSONMetadata struct {
	Timestamp string                 `json:"timestamp"`
	Component cycloneDXJSONComponent `json:"component"`
}

type cycloneDXJSONComponent struct {
	Type       string                  `json:"type"`
	BOMRef     string                  `json:"bom-ref,omitempty"`
	Name       string                  `json:"name"`
	Version    string                  `json:"version,omitempty"`
	Scope      string                  `json:"scope,omitempty"`
	Purl       string                  `json:"purl,omitempty"`
	Properties []cycloneDXJSONProperty `json:"properties,omitempty"`
}

type cycloneDXJSONProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cycloneDXJSONDep struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// SaveSBOM writes one or more SBOM files for the repository.
// Returns the list of saved file paths and the output directory path.
// Output is stored in ~/.sbomber/reports/<project-name>/
func SaveSBOM(repoDir, repoName string, summary deps.Summary, format string) ([]string, string, error) {
	saved := make([]string, 0, 2)
	if format == "" {
		return saved, "", nil
	}

	// Get central output directory
	outputDir, err := GetOutputDir(repoDir)
	if err != nil {
		return nil, "", err
	}

	if format == "cyclonedx" || format == "both" {
		path, err := saveCycloneDX(outputDir, repoName, summary)
		if err != nil {
			return nil, "", err
		}
		saved = append(saved, path)
	}

	if format == "cyclonedx-json" {
		path, err := saveCycloneDXJSON(outputDir, repoName, summary)
		if err != nil {
			return nil, "", err
		}
		saved = append(saved, path)
	}

	if format == "spdx" || format == "both" {
		path, err := saveSPDX(outputDir, repoName, summary)
		if err != nil {
			return nil, "", err
		}
		saved = append(saved, path)
	}

	return saved, outputDir, nil
}

// SaveSBOMToDir writes SBOM files directly to the specified directory.
// Unlike SaveSBOM, this does not create a subdirectory.
func SaveSBOMToDir(outputDir, repoName string, summary deps.Summary, format string) ([]string, error) {
	saved := make([]string, 0, 2)
	if format == "" {
		return saved, nil
	}

	if format == "cyclonedx" || format == "both" {
		path, err := saveCycloneDX(outputDir, repoName, summary)
		if err != nil {
			return nil, err
		}
		saved = append(saved, path)
	}

	if format == "cyclonedx-json" {
		path, err := saveCycloneDXJSON(outputDir, repoName, summary)
		if err != nil {
			return nil, err
		}
		saved = append(saved, path)
	}

	if format == "spdx" || format == "both" {
		path, err := saveSPDX(outputDir, repoName, summary)
		if err != nil {
			return nil, err
		}
		saved = append(saved, path)
	}

	return saved, nil
}

func saveCycloneDXJSON(repoDir, repoName string, summary deps.Summary) (string, error) {
	if summary.DependencyGraph == nil {
		summary.BuildGraph(repoName)
	}

	rootPurl := fmt.Sprintf("pkg:generic/%s", strings.ToLower(repoName))

	bom := cycloneDXJSONBom{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: cycloneDXJSONMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Component: cycloneDXJSONComponent{
				Type:   "application",
				BOMRef: rootPurl,
				Name:   repoName,
			},
		},
		Components:   make([]cycloneDXJSONComponent, 0),
		Dependencies: make([]cycloneDXJSONDep, 0),
	}

	// nameRefs tracks every bom-ref (exact PURL, so two occurrences of the
	// same package at different versions never collide) seen for a given
	// package name. It is used only to resolve a Children entry (a bare
	// name, not a versioned reference — see buildJSONProperties and
	// Dependency.Children) when there is exactly one occurrence of that
	// name. When a name has more than one occurrence, a bare-name child
	// reference is inherently ambiguous about which version it depends on,
	// so it is left unresolved rather than guessed. See
	// docs/design/canonical-scan.md.
	nameRefs := make(map[string][]string)

	addComponent := func(dep deps.Dependency, isDirect bool) {
		purl := dep.Purl()
		nameRefs[dep.Name] = append(nameRefs[dep.Name], purl)

		props := buildJSONProperties(dep, isDirect)
		bom.Components = append(bom.Components, cycloneDXJSONComponent{
			Type:       "library",
			BOMRef:     purl,
			Name:       dep.Name,
			Version:    dep.Version,
			Scope:      cycloneDXScope(dep),
			Purl:       purl,
			Properties: props,
		})
	}

	for _, d := range summary.Direct {
		addComponent(d, true)
	}
	for _, d := range summary.Transitive {
		addComponent(d, false)
	}

	resolveChildRef := func(name string) (string, bool) {
		refs := nameRefs[name]
		if len(refs) != 1 {
			return "", false
		}
		return refs[0], true
	}

	// Root dependency entry
	rootDeps := make([]string, 0, len(summary.Direct))
	for _, d := range summary.Direct {
		rootDeps = append(rootDeps, d.Purl())
	}
	bom.Dependencies = append(bom.Dependencies, cycloneDXJSONDep{Ref: rootPurl, DependsOn: rootDeps})

	for _, dep := range append(append([]deps.Dependency{}, summary.Direct...), summary.Transitive...) {
		if len(dep.Children) == 0 {
			continue
		}
		ref := dep.Purl()
		childRefs := make([]string, 0, len(dep.Children))
		for _, child := range dep.Children {
			if cr, ok := resolveChildRef(child); ok {
				childRefs = append(childRefs, cr)
			}
		}
		if len(childRefs) > 0 {
			bom.Dependencies = append(bom.Dependencies, cycloneDXJSONDep{Ref: ref, DependsOn: childRefs})
		}
	}

	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal cyclonedx json sbom: %w", err)
	}

	path := filepath.Join(repoDir, cycloneDXJSONFilename)
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return "", fmt.Errorf("write cyclonedx json sbom: %w", err)
	}

	return path, nil
}

func buildJSONProperties(dep deps.Dependency, isDirect bool) []cycloneDXJSONProperty {
	depType := "transitive"
	if isDirect {
		depType = "direct"
	}
	ecosystem := dep.Ecosystem
	if ecosystem == "" {
		ecosystem = "unknown"
	}
	chain := dep.Chain
	if chain == "" {
		chain = dep.Name
	}
	sourceFile := dep.SourceFile
	if sourceFile == "" {
		sourceFile = "unknown"
	}
	return []cycloneDXJSONProperty{
		{Name: "supplychain:dependency-type", Value: depType},
		{Name: "supplychain:ecosystem", Value: ecosystem},
		{Name: "supplychain:build-scope", Value: dep.BuildScope()},
		{Name: "supplychain:depth", Value: fmt.Sprintf("%d", dep.Depth)},
		{Name: "supplychain:chain", Value: chain},
		{Name: "supplychain:source-file", Value: sourceFile},
	}
}

func saveCycloneDX(repoDir, repoName string, summary deps.Summary) (string, error) {
	// Build dependency graph if not already built
	if summary.DependencyGraph == nil {
		summary.BuildGraph(repoName)
	}

	rootPurl := fmt.Sprintf("pkg:generic/%s", strings.ToLower(repoName))

	bom := cycloneDXBom{
		Xmlns:   "http://cyclonedx.org/schema/bom/1.5",
		Version: 1,
		Metadata: cycloneDXMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Component: cycloneDXComponent{
				Type:   "application",
				BomRef: rootPurl,
				Name:   repoName,
			},
		},
	}

	components := make([]cycloneDXComponent, 0, len(summary.Direct)+len(summary.Transitive))
	// nameRefs tracks every bom-ref (exact PURL) seen for a given package
	// name, so buildDependenciesSection can resolve a Children entry (a
	// bare name) when there is exactly one occurrence of that name. See
	// the equivalent comment in saveCycloneDXJSON and
	// docs/design/canonical-scan.md.
	nameRefs := make(map[string][]string)

	// Process direct dependencies
	for _, dependency := range summary.Direct {
		purl := dependency.Purl()
		nameRefs[dependency.Name] = append(nameRefs[dependency.Name], purl)

		props := buildProperties(dependency, true)
		components = append(components, cycloneDXComponent{
			Type:       "library",
			BomRef:     purl,
			Name:       dependency.Name,
			Version:    dependency.Version,
			Scope:      cycloneDXScope(dependency),
			Purl:       purl,
			Properties: props,
		})
	}

	// Process transitive dependencies
	for _, dependency := range summary.Transitive {
		purl := dependency.Purl()
		nameRefs[dependency.Name] = append(nameRefs[dependency.Name], purl)

		props := buildProperties(dependency, false)
		components = append(components, cycloneDXComponent{
			Type:       "library",
			BomRef:     purl,
			Name:       dependency.Name,
			Version:    dependency.Version,
			Scope:      cycloneDXScope(dependency),
			Purl:       purl,
			Properties: props,
		})
	}

	if len(components) > 0 {
		bom.Components = &componentList{Components: components}
	}

	// Build dependencies section
	dependencies := buildDependenciesSection(rootPurl, summary, nameRefs)
	if len(dependencies) > 0 {
		bom.Dependencies = &dependenciesList{Dependencies: dependencies}
	}

	content, err := xml.MarshalIndent(bom, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal cyclonedx sbom: %w", err)
	}

	out := xml.Header + string(content) + "\n"
	path := filepath.Join(repoDir, cycloneDXFilename)
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		return "", fmt.Errorf("write cyclonedx sbom: %w", err)
	}

	return path, nil
}

// buildProperties creates the supply chain properties for a component.
func buildProperties(dep deps.Dependency, isDirect bool) *propertiesList {
	depType := "transitive"
	if isDirect {
		depType = "direct"
	}

	ecosystem := dep.Ecosystem
	if ecosystem == "" {
		ecosystem = "unknown"
	}

	depth := dep.Depth
	chain := dep.Chain
	if chain == "" {
		chain = dep.Name
	}

	sourceFile := dep.SourceFile
	if sourceFile == "" {
		sourceFile = "unknown"
	}

	sourceLocation := dep.SourceLocation
	if sourceLocation == "" {
		sourceLocation = "unknown"
	}

	props := []cycloneDXProperty{
		{Name: "supplychain:dependency-type", Value: depType},
		{Name: "supplychain:ecosystem", Value: ecosystem},
		{Name: "supplychain:build-scope", Value: dep.BuildScope()},
		{Name: "supplychain:depth", Value: fmt.Sprintf("%d", depth)},
		{Name: "supplychain:chain", Value: chain},
		{Name: "supplychain:source-file", Value: sourceFile},
		{Name: "supplychain:source-location", Value: sourceLocation},
	}

	return &propertiesList{Properties: props}
}

// buildDependenciesSection creates the CycloneDX dependencies mapping.
// nameRefs maps a package name to every bom-ref (exact PURL) it occurs
// under; a Children entry (a bare name) resolves only when its name has
// exactly one occurrence, since a name with several versioned occurrences
// gives no way to tell which one a bare name reference actually meant.
func buildDependenciesSection(rootRef string, summary deps.Summary, nameRefs map[string][]string) []cycloneDXDependency {
	dependencies := make([]cycloneDXDependency, 0)

	resolveRef := func(name string) (string, bool) {
		refs := nameRefs[name]
		if len(refs) != 1 {
			return "", false
		}
		return refs[0], true
	}

	// Root depends on all direct dependencies
	rootDeps := make([]dependencyRef, 0, len(summary.Direct))
	for _, d := range summary.Direct {
		rootDeps = append(rootDeps, dependencyRef{Ref: d.Purl()})
	}
	if len(rootDeps) > 0 {
		dependencies = append(dependencies, cycloneDXDependency{
			Ref:          rootRef,
			Dependencies: rootDeps,
		})
	}

	// Add dependency relationships for all packages
	allDeps := make([]deps.Dependency, 0, len(summary.Direct)+len(summary.Transitive))
	allDeps = append(allDeps, summary.Direct...)
	allDeps = append(allDeps, summary.Transitive...)
	for _, dep := range allDeps {
		if len(dep.Children) == 0 {
			continue
		}

		ref := dep.Purl()

		childRefs := make([]dependencyRef, 0, len(dep.Children))
		for _, childName := range dep.Children {
			if childRef, ok := resolveRef(childName); ok {
				childRefs = append(childRefs, dependencyRef{Ref: childRef})
			}
		}

		if len(childRefs) > 0 {
			dependencies = append(dependencies, cycloneDXDependency{
				Ref:          ref,
				Dependencies: childRefs,
			})
		}
	}

	return dependencies
}

// cycloneDXScope maps a dependency's build scope to CycloneDX's
// required/optional scope, independent of whether it is a direct or
// transitive dependency. CycloneDX's "optional" scope means "not needed to
// build or run" (e.g. dev/test/build tooling) — it does not mean
// "transitive". A transitive runtime dependency is exactly as required as
// a direct one; whether a component is direct or transitive is already
// carried separately via the "supplychain:dependency-type" property.
func cycloneDXScope(dep deps.Dependency) string {
	switch dep.BuildScope() {
	case "dev", "test", "build-tooling":
		return "optional"
	default:
		return "required"
	}
}

func saveSPDX(repoDir, repoName string, summary deps.Summary) (string, error) {
	repoID := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(repoName)), " ", "-")
	namespace := fmt.Sprintf("http://spdx.org/spdxdocs/%s-%s", repoID, "sbom")

	lines := []string{
		"SPDXVersion: SPDX-2.3",
		"DataLicense: CC0-1.0",
		"SPDXID: SPDXRef-DOCUMENT",
		fmt.Sprintf("DocumentName: %s", repoName),
		fmt.Sprintf("DocumentNamespace: %s", namespace),
		"Creator: Tool: SBOMber",
		fmt.Sprintf("Created: %s", time.Now().UTC().Format(time.RFC3339)),
	}

	packageIndex := 1
	for _, dependency := range summary.Direct {
		packageID := fmt.Sprintf("SPDXRef-Package-%d", packageIndex)
		lines = append(lines,
			fmt.Sprintf("PackageName: %s", dependency.Name),
			fmt.Sprintf("SPDXID: %s", packageID),
			fmt.Sprintf("PackageVersion: %s", dependency.Version),
			"PackageSupplier: NOASSERTION",
			"PackageDownloadLocation: NOASSERTION",
			"FilesAnalyzed: false",
			"PackageLicenseConcluded: NOASSERTION",
			"PackageLicenseDeclared: NOASSERTION",
			"PackageCopyrightText: NONE",
			fmt.Sprintf("Relationship: SPDXRef-DOCUMENT DESCRIBES %s", packageID),
		)
		packageIndex++
	}

	for _, dependency := range summary.Transitive {
		packageID := fmt.Sprintf("SPDXRef-Package-%d", packageIndex)
		lines = append(lines,
			fmt.Sprintf("PackageName: %s", dependency.Name),
			fmt.Sprintf("SPDXID: %s", packageID),
			fmt.Sprintf("PackageVersion: %s", dependency.Version),
			"PackageSupplier: NOASSERTION",
			"PackageDownloadLocation: NOASSERTION",
			"FilesAnalyzed: false",
			"PackageLicenseConcluded: NOASSERTION",
			"PackageLicenseDeclared: NOASSERTION",
			"PackageCopyrightText: NONE",
			fmt.Sprintf("Relationship: SPDXRef-DOCUMENT DESCRIBES %s", packageID),
		)
		packageIndex++
	}

	if len(summary.Direct)+len(summary.Transitive) == 0 {
		lines = append(lines, "PackageName: NOASSERTION", "SPDXID: SPDXRef-Package-1", "PackageVersion: NOASSERTION", "PackageSupplier: NOASSERTION", "PackageDownloadLocation: NOASSERTION", "FilesAnalyzed: false", "PackageLicenseConcluded: NOASSERTION", "PackageLicenseDeclared: NOASSERTION", "PackageCopyrightText: NONE", "Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-1")
	}

	out := strings.Join(lines, "\n") + "\n"
	path := filepath.Join(repoDir, spdxFilename)
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		return "", fmt.Errorf("write spdx sbom: %w", err)
	}

	return path, nil
}
