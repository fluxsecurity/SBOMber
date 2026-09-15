package diff

import (
	"fmt"
	"strings"

	"github.com/Xsamsx/SBOMber/internal/verify"
)

// Change categorizes how a component changed between two SBOMs.
type Change struct {
	Name       string
	OldVersion string
	NewVersion string
	Kind       string // added, removed, upgraded, downgraded, unchanged
}

// Result holds the full diff between two SBOMs.
type Result struct {
	OldPath    string
	NewPath    string
	Added      []Change
	Removed    []Change
	Upgraded   []Change
	Downgraded []Change
	Unchanged  int
}

// DiffFiles compares two SBOM files and returns the diff result.
func DiffFiles(oldPath, newPath string) (*Result, error) {
	oldComponents, err := verify.ParseSBOM(oldPath)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", oldPath, err)
	}

	newComponents, err := verify.ParseSBOM(newPath)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", newPath, err)
	}

	result := &Result{OldPath: oldPath, NewPath: newPath}

	oldMap := make(map[string]string) // name -> version
	for _, c := range oldComponents {
		oldMap[normalizeKey(c.Name)] = c.Version
	}

	newMap := make(map[string]string)
	for _, c := range newComponents {
		newMap[normalizeKey(c.Name)] = c.Version
	}

	// Find added and changed
	for _, c := range newComponents {
		key := normalizeKey(c.Name)
		oldVer, existed := oldMap[key]
		if !existed {
			result.Added = append(result.Added, Change{Name: c.Name, NewVersion: c.Version, Kind: "added"})
			continue
		}
		if oldVer == c.Version {
			result.Unchanged++
			continue
		}
		ch := Change{Name: c.Name, OldVersion: oldVer, NewVersion: c.Version}
		if versionNewer(c.Version, oldVer) {
			ch.Kind = "upgraded"
			result.Upgraded = append(result.Upgraded, ch)
		} else {
			ch.Kind = "downgraded"
			result.Downgraded = append(result.Downgraded, ch)
		}
	}

	// Find removed
	for _, c := range oldComponents {
		key := normalizeKey(c.Name)
		if _, found := newMap[key]; !found {
			result.Removed = append(result.Removed, Change{Name: c.Name, OldVersion: c.Version, Kind: "removed"})
		}
	}

	return result, nil
}

// PrintReport returns a formatted diff report.
func (r *Result) PrintReport() string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║                        SBOM DIFF REPORT                      ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n\n")
	_, _ = fmt.Fprintf(&sb, "  Old: %s\n", r.OldPath)
	_, _ = fmt.Fprintf(&sb, "  New: %s\n\n", r.NewPath)

	total := len(r.Added) + len(r.Removed) + len(r.Upgraded) + len(r.Downgraded)
	_, _ = fmt.Fprintf(&sb, "  Changes: %d  (+ %d added, - %d removed, ↑ %d upgraded, ↓ %d downgraded, = %d unchanged)\n\n",
		total, len(r.Added), len(r.Removed), len(r.Upgraded), len(r.Downgraded), r.Unchanged)

	if len(r.Added) > 0 {
		_, _ = fmt.Fprintf(&sb, "+ Added (%d):\n", len(r.Added))
		for _, c := range r.Added {
			_, _ = fmt.Fprintf(&sb, "  + %-40s %s\n", c.Name, c.NewVersion)
		}
		sb.WriteString("\n")
	}

	if len(r.Removed) > 0 {
		_, _ = fmt.Fprintf(&sb, "- Removed (%d):\n", len(r.Removed))
		for _, c := range r.Removed {
			_, _ = fmt.Fprintf(&sb, "  - %-40s %s\n", c.Name, c.OldVersion)
		}
		sb.WriteString("\n")
	}

	if len(r.Upgraded) > 0 {
		_, _ = fmt.Fprintf(&sb, "↑ Upgraded (%d):\n", len(r.Upgraded))
		for _, c := range r.Upgraded {
			_, _ = fmt.Fprintf(&sb, "  ↑ %-40s %s → %s\n", c.Name, c.OldVersion, c.NewVersion)
		}
		sb.WriteString("\n")
	}

	if len(r.Downgraded) > 0 {
		_, _ = fmt.Fprintf(&sb, "↓ Downgraded (%d):\n", len(r.Downgraded))
		for _, c := range r.Downgraded {
			_, _ = fmt.Fprintf(&sb, "  ↓ %-40s %s → %s\n", c.Name, c.OldVersion, c.NewVersion)
		}
		sb.WriteString("\n")
	}

	if total == 0 {
		sb.WriteString("  No changes detected between the two SBOMs.\n\n")
	}

	return sb.String()
}

func normalizeKey(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// versionNewer does a simple lexicographic comparison — sufficient for semver-like strings.
func versionNewer(a, b string) bool {
	aParts := strings.Split(strings.TrimPrefix(a, "v"), ".")
	bParts := strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < len(aParts) && i < len(bParts); i++ {
		if aParts[i] > bParts[i] {
			return true
		}
		if aParts[i] < bParts[i] {
			return false
		}
	}
	return len(aParts) > len(bParts)
}
