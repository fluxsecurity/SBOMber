package ecosystem

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectSingleEcosystem(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "package.json"))
	mustWriteFile(t, filepath.Join(root, "yarn.lock"))

	detection, err := Detect(root)
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}

	if len(detection.Names) != 1 || detection.Names[0] != NPM {
		t.Fatalf("expected npm detection, got %#v", detection.Names)
	}

	if len(detection.Evidence[NPM]) != 2 {
		t.Fatalf("expected 2 npm evidence files, got %#v", detection.Evidence[NPM])
	}
}

func TestDetectMultipleEcosystems(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "package.json"))
	mustWriteFile(t, filepath.Join(root, "pom.xml"))
	mustWriteFile(t, filepath.Join(root, "Gemfile"))
	mustWriteFile(t, filepath.Join(root, "demo.gemspec"))

	detection, err := Detect(root)
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}

	expected := []Name{Maven, NPM, Ruby}
	if len(detection.Names) != len(expected) {
		t.Fatalf("expected %d ecosystems, got %#v", len(expected), detection.Names)
	}

	for i, name := range expected {
		if detection.Names[i] != name {
			t.Fatalf("expected %s at index %d, got %#v", name, i, detection.Names)
		}
	}
}

func mustWriteFile(t *testing.T, path string) {
	t.Helper()

	if err := os.WriteFile(path, []byte("test"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
