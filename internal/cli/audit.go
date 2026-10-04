package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/Xsamsx/SBOMber/internal/audit"
)

const auditUsage = "Usage: sbomber audit [--cases testdata/audit] [--out audit-results.json]\n"

// runAudit is S5-14's (#124) harness: it replays every hand-labelled case
// under --cases through the decision pipeline and prints a per-case
// comparison. Exit codes: 0 when no labelled genuine usage was moved out of
// usage detected, 1 when one was (or labels no longer match the scan), 2 on
// a usage or input error.
func runAudit(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cases := fs.String("cases", "testdata/audit", "directory holding one subdirectory per labelled case")
	out := fs.String("out", "", "also write the comparison as JSON (audit-results.json)")

	if err := fs.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprint(stderr, auditUsage)
		return 2
	}

	rep, err := audit.Run(*cases)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if err := audit.RenderText(stdout, rep); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if *out != "" {
		if err := writeJSONFile(*out, rep); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return 2
		}
		_, _ = fmt.Fprintf(stdout, "Wrote %s\n", *out)
	}
	if rep.Totals.Failed() {
		return 1
	}
	return 0
}
