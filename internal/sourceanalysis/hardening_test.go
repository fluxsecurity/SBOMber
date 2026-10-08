package sourceanalysis

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeSourceBytesMatchesFileEntryPoint(t *testing.T) {
	source := []byte(`
import { merge } from "lodash";

export function run() {
	return merge({}, {});
}
`)

	path := filepath.Join(t.TempDir(), "app.js")
	if err := os.WriteFile(path, source, 0o600); err != nil {
		t.Fatal(err)
	}

	fromFile, err := AnalyzeSource(path)
	if err != nil {
		t.Fatalf("AnalyzeSource: %v", err)
	}

	fromBytes, err := AnalyzeSourceBytes(path, source)
	if err != nil {
		t.Fatalf("AnalyzeSourceBytes: %v", err)
	}

	if !reflect.DeepEqual(fromFile, fromBytes) {
		t.Fatalf(
			"byte analysis differs from file analysis\nfile: %+v\nbytes: %+v",
			fromFile,
			fromBytes,
		)
	}
}

func TestExtractSourceHonorsParseTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Tree-sitter sub-millisecond timeout timing is unreliable on Windows")
	}

	// Large malformed input ensures parsing cannot complete before the
	// deliberately tiny test timeout.
	source := []byte(strings.Repeat("(", 1<<20))

	_, err := extractSourceWithTimeout(
		"timeout.js",
		source,
		time.Microsecond,
	)
	if err == nil {
		t.Fatal("expected parser timeout")
	}

	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error = %v, want parser timeout", err)
	}
}
