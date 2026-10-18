package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain keeps every test in this package from shelling out to the real
// GitHub CLI and pulling the developer's own token into the test process.
func TestMain(m *testing.M) {
	ghAuthToken = func() string { return "" }
	os.Exit(m.Run())
}

func stubGHAuthToken(t *testing.T, token string) {
	t.Helper()
	orig := ghAuthToken
	ghAuthToken = func() string { return token }
	t.Cleanup(func() { ghAuthToken = orig })
}

func TestEnsureGitHubTokenKeepsExplicitToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "from-env")
	stubGHAuthToken(t, "from-gh")

	if src := ensureGitHubToken(); src != "GITHUB_TOKEN" {
		t.Errorf("source = %q, want GITHUB_TOKEN", src)
	}
	if got := os.Getenv("GITHUB_TOKEN"); got != "from-env" {
		t.Errorf("GITHUB_TOKEN = %q, want it left as from-env", got)
	}
}

func TestEnsureGitHubTokenFallsBackToGHCLI(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("HOME", t.TempDir()) // no saved sbomber config
	stubGHAuthToken(t, "from-gh")

	if src := ensureGitHubToken(); src != "gh auth token" {
		t.Errorf("source = %q, want gh auth token", src)
	}
	if got := os.Getenv("GITHUB_TOKEN"); got != "from-gh" {
		t.Errorf("GITHUB_TOKEN = %q, want from-gh", got)
	}
}

func TestEnsureGitHubTokenPrefersSavedConfigOverGHCLI(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("HOME", home)
	mustMkdirAll(t, filepath.Join(home, ".sbomber"))
	mustWriteFile(t, filepath.Join(home, ".sbomber", "config.json"), `{"github_token":"from-config"}`)
	stubGHAuthToken(t, "from-gh")

	if src := ensureGitHubToken(); src != "sbomber config" {
		t.Errorf("source = %q, want sbomber config", src)
	}
	if got := os.Getenv("GITHUB_TOKEN"); got != "from-config" {
		t.Errorf("GITHUB_TOKEN = %q, want from-config", got)
	}
}

func TestEnsureGitHubTokenNoneAvailable(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("HOME", t.TempDir())
	stubGHAuthToken(t, "")

	if src := ensureGitHubToken(); src != "" {
		t.Errorf("source = %q, want none", src)
	}
	if got := os.Getenv("GITHUB_TOKEN"); got != "" {
		t.Errorf("GITHUB_TOKEN = %q, want empty", got)
	}
}

// The exporter writes sbom-cyclonedx.xml, which the github command's old
// ".cdx.xml" suffix check never matched, so Grype silently never ran there.
func TestPickSBOMForGrypePrefersCycloneDX(t *testing.T) {
	cases := []struct {
		paths []string
		want  string
	}{
		{[]string{"out/sbom.spdx", "out/sbom-cyclonedx.xml"}, "out/sbom-cyclonedx.xml"},
		{[]string{"out/sbom-cyclonedx.json"}, "out/sbom-cyclonedx.json"},
		{[]string{"out/sbom.spdx", "ref.cdx.xml"}, "ref.cdx.xml"},
		{[]string{"out/sbom.spdx"}, "out/sbom.spdx"},
		{nil, ""},
	}
	for _, c := range cases {
		if got := pickSBOMForGrype(c.paths); got != c.want {
			t.Errorf("pickSBOMForGrype(%v) = %q, want %q", c.paths, got, c.want)
		}
	}
}
