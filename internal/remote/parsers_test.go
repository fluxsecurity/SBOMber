package remote

import (
	"testing"

	"github.com/Xsamsx/SBOMber/internal/deps"
)

func TestParsePackageJSON(t *testing.T) {
	content := []byte(`{
		"dependencies": {
			"express": "^4.18.2",
			"lodash": "4.17.21"
		},
		"devDependencies": {
			"jest": "^29.0.0"
		}
	}`)

	summary, err := parsePackageJSON(content)
	if err != nil {
		t.Fatalf("parsePackageJSON failed: %v", err)
	}

	if len(summary.Direct) != 3 {
		t.Errorf("expected 3 dependencies, got %d", len(summary.Direct))
	}

	found := make(map[string]deps.Dependency)
	for _, dep := range summary.Direct {
		found[dep.Name] = dep
	}

	if dep, ok := found["express"]; !ok {
		t.Error("missing express dependency")
	} else if dep.Version != "4.18.2" {
		t.Errorf("express version = %s, want 4.18.2", dep.Version)
	} else if dep.Ecosystem != "npm" {
		t.Errorf("express ecosystem = %s, want npm", dep.Ecosystem)
	}

	if dep, ok := found["jest"]; !ok {
		t.Error("missing jest dependency")
	} else if dep.Scope != deps.ScopeDev {
		t.Errorf("jest scope = %s, want development", dep.Scope)
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	content := []byte(`
# Comment line
requests==2.28.1
flask>=2.0.0
django[argon2]>=4.0
-r base.txt
numpy
`)

	summary, err := parseRequirementsTxt(content)
	if err != nil {
		t.Fatalf("parseRequirementsTxt failed: %v", err)
	}

	if len(summary.Direct) != 4 {
		t.Errorf("expected 4 dependencies, got %d", len(summary.Direct))
	}

	found := make(map[string]deps.Dependency)
	for _, dep := range summary.Direct {
		found[dep.Name] = dep
	}

	if dep, ok := found["requests"]; !ok {
		t.Error("missing requests dependency")
	} else if dep.Version != "2.28.1" {
		// A bare version, not the "==2.28.1" specifier: the specifier made
		// SBOM purls (pkg:pypi/requests@==2.28.1) that Grype cannot match.
		t.Errorf("requests version = %s, want 2.28.1", dep.Version)
	}
	if dep := found["flask"]; dep.Version != "" {
		t.Errorf("flask>=2.0.0 is a range, not a version; got %q", dep.Version)
	}

	if _, ok := found["django"]; !ok {
		t.Error("missing django dependency")
	}
}

func TestParseGoMod(t *testing.T) {
	content := []byte(`
module example.com/myapp

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/spf13/cobra v1.7.0
	golang.org/x/text v0.14.0 // indirect
)

require github.com/single/dep v1.0.0
`)

	summary, err := parseGoMod(content)
	if err != nil {
		t.Fatalf("parseGoMod failed: %v", err)
	}

	if len(summary.Direct) != 3 {
		t.Errorf("expected 3 direct dependencies, got %d", len(summary.Direct))
	}

	found := make(map[string]deps.Dependency)
	for _, dep := range summary.Direct {
		found[dep.Name] = dep
	}

	if dep, ok := found["github.com/gin-gonic/gin"]; !ok {
		t.Error("missing gin dependency")
	} else if dep.Version != "v1.9.1" {
		t.Errorf("gin version = %s, want v1.9.1", dep.Version)
	}

	if _, ok := found["golang.org/x/text"]; ok {
		t.Error("indirect dependency should be excluded")
	}
}

func TestParsePomXML(t *testing.T) {
	content := []byte(`
<?xml version="1.0"?>
<project>
	<dependencies>
		<dependency>
			<groupId>org.springframework</groupId>
			<artifactId>spring-core</artifactId>
			<version>5.3.20</version>
		</dependency>
		<dependency>
			<groupId>junit</groupId>
			<artifactId>junit</artifactId>
			<version>4.13.2</version>
		</dependency>
	</dependencies>
</project>
`)

	summary, err := parsePomXML(content)
	if err != nil {
		t.Fatalf("parsePomXML failed: %v", err)
	}

	if len(summary.Direct) != 2 {
		t.Errorf("expected 2 dependencies, got %d", len(summary.Direct))
	}

	found := make(map[string]deps.Dependency)
	for _, dep := range summary.Direct {
		found[dep.Name] = dep
	}

	if dep, ok := found["org.springframework:spring-core"]; !ok {
		t.Error("missing spring-core dependency")
	} else if dep.Version != "5.3.20" {
		t.Errorf("spring-core version = %s, want 5.3.20", dep.Version)
	}
}

func TestParseGemfileLock(t *testing.T) {
	content := []byte(`
GEM
  remote: https://rubygems.org/
  specs:
    actioncable (7.0.4)
    activerecord (7.0.4)
    rails (7.0.4)

PLATFORMS
  ruby
`)

	summary, err := parseGemfileLock(content)
	if err != nil {
		t.Fatalf("parseGemfileLock failed: %v", err)
	}

	if len(summary.Direct) != 3 {
		t.Errorf("expected 3 dependencies, got %d", len(summary.Direct))
	}

	found := make(map[string]deps.Dependency)
	for _, dep := range summary.Direct {
		found[dep.Name] = dep
	}

	if dep, ok := found["rails"]; !ok {
		t.Error("missing rails dependency")
	} else if dep.Version != "7.0.4" {
		t.Errorf("rails version = %s, want 7.0.4", dep.Version)
	}
}

func TestPackageLockPackageName(t *testing.T) {
	tests := map[string]string{
		"node_modules/lodash":                  "lodash",
		"node_modules/@babel/core":             "@babel/core",
		"node_modules/a/node_modules/b":        "b",
		"node_modules/a/node_modules/@scope/b": "@scope/b",
		"packages/app/node_modules/left-pad":   "left-pad",
		"packages/app":                         "",
		"":                                     "",
	}
	for path, want := range tests {
		if got := packageLockPackageName(path); got != want {
			t.Errorf("packageLockPackageName(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestParsePackageLockJSONKeepsNestedVersions(t *testing.T) {
	content := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "root"},
			"node_modules/debug": {"version": "4.3.4"},
			"node_modules/express/node_modules/debug": {"version": "2.6.9"},
			"packages/app": {"version": "1.0.0"},
			"node_modules/app": {"resolved": "packages/app", "link": true}
		}
	}`)
	summary, err := parsePackageLockJSON(content)
	if err != nil {
		t.Fatal(err)
	}
	versions := map[string]bool{}
	for _, d := range summary.Transitive {
		if d.Name == "debug" {
			versions[d.Version] = true
		}
		if d.Name == "packages/app" {
			t.Errorf("workspace folder reported as a package: %+v", d)
		}
	}
	if !versions["4.3.4"] || !versions["2.6.9"] {
		t.Errorf("want both debug versions, got %v", versions)
	}
}
