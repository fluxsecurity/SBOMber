package usagegraph

import "testing"

func TestCurrentAnalyserReportsRuntimeVersions(t *testing.T) {
	metadata := CurrentAnalyser(false)

	if metadata.Parser != "tree-sitter" || metadata.Binding != bindingModule {
		t.Fatalf("unexpected parser metadata: %+v", metadata)
	}
	if metadata.BindingVersion != "0.25.0" {
		t.Fatalf("binding version = %q, want 0.25.0", metadata.BindingVersion)
	}
	if metadata.GrammarVersions["javascript"] != "0.25.0" {
		t.Fatalf("JavaScript grammar version = %q", metadata.GrammarVersions["javascript"])
	}
	if metadata.GrammarVersions["typescript"] != "0.23.2" {
		t.Fatalf("TypeScript grammar version = %q", metadata.GrammarVersions["typescript"])
	}
	if !metadata.CGOEnabled {
		t.Fatal("selected production binding must record its CGO requirement")
	}
	if len(metadata.Ecosystems) != 1 || metadata.Ecosystems[0] != "npm" {
		t.Fatalf("unexpected ecosystems: %v", metadata.Ecosystems)
	}
}
