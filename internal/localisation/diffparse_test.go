package localisation

import (
	"strings"
	"testing"
)

// A GitHub-style commit diff: a modified file whose hunk header has no
// function context (lodash inside an IIFE), an added file, and a binary.
const sampleDiff = `diff --git a/lodash.js b/lodash.js
index 1111111..2222222 100644
--- a/lodash.js
+++ b/lodash.js
@@ -19,7 +19,8 @@
 
   /** Error message constants. */
   var CORE_ERROR_TEXT = 'Unsupported core-js use.',
-      FUNC_ERROR_TEXT = 'Expected a function';
+      FUNC_ERROR_TEXT = 'Expected a function',
+      INVALID_TEMPL_VAR_ERROR_TEXT = 'Invalid variable option';
 
   /** Used to stand-in for undefined hash values. */
   var HASH_UNDEFINED = '__lodash_hash_undefined__';
@@ -14866,6 +14879,12 @@
       if (!variable) {
         source = 'with (obj) {\n' + source + '\n}\n';
       }
+      // Throw an error if a forbidden character was found in variable
+      else if (reForbiddenIdentifierChars.test(variable)) {
+        throw new Error(INVALID_TEMPL_VAR_ERROR_TEXT);
+      }
+
       // Cleanup code by stripping empty strings.
diff --git a/test/proto.js b/test/proto.js
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/test/proto.js
@@ -0,0 +1,2 @@
+var test = require('tape');
+test('x', function (t) { t.end() });
\ No newline at end of file
diff --git a/logo.png b/logo.png
index 4444444..5555555 100644
Binary files a/logo.png and b/logo.png differ
`

func TestParseUnifiedDiff_GitHubCommitShape(t *testing.T) {
	files, err := ParseUnifiedDiff(strings.NewReader(sampleDiff))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("want 3 files, got %d", len(files))
	}
	lodash := files[0]
	if lodash.Path() != "lodash.js" || lodash.Status != "modified" || len(lodash.Hunks) != 2 {
		t.Fatalf("lodash: %+v", lodash)
	}
	if lodash.Hunks[0].Context != "" {
		t.Errorf("IIFE hunk should have empty context, got %q", lodash.Hunks[0].Context)
	}
	added, removed := lodash.ChangedLines()
	wantAdded := []int{22, 23, 14882, 14883, 14884, 14885, 14886}
	if len(added) != len(wantAdded) {
		t.Fatalf("added = %v, want %v", added, wantAdded)
	}
	for i := range added {
		if added[i] != wantAdded[i] {
			t.Errorf("added[%d] = %d, want %d", i, added[i], wantAdded[i])
		}
	}
	if len(removed) != 1 || removed[0] != 22 {
		t.Errorf("removed = %v, want [22]", removed)
	}
	test := files[1]
	if test.Status != "added" || test.Path() != "test/proto.js" {
		t.Errorf("added file: %+v", test)
	}
	if a, _ := test.ChangedLines(); len(a) != 2 || a[0] != 1 {
		t.Errorf("added-file lines = %v", a)
	}
	if !files[2].Binary || files[2].Path() != "logo.png" {
		t.Errorf("binary: %+v", files[2])
	}
}

// Failure path: garbage and malformed hunk headers do not panic and do not
// invent line numbers.
func TestParseUnifiedDiff_MalformedInput(t *testing.T) {
	cases := []string{
		"",
		"not a diff at all\n+++ nothing\n@@ garbage @@\n",
		"diff --git a/x.js b/x.js\n--- a/x.js\n+++ b/x.js\n@@ -a,b +c,d @@\n+line\n",
		"diff --git a/x.js b/x.js\n@@ -1,1 +1,1 @@ missing file headers\n-a\n+b\n",
		strings.Repeat("\x00\xff", 1000),
	}
	for i, c := range cases {
		files, err := ParseUnifiedDiff(strings.NewReader(c))
		if err != nil {
			t.Errorf("case %d: unexpected error %v", i, err)
		}
		for _, f := range files {
			for _, h := range f.Hunks {
				for _, l := range h.Lines {
					if l.Kind == '+' && l.NewNo <= 0 || l.Kind == '-' && l.OldNo <= 0 {
						t.Errorf("case %d: invented line number in %+v", i, l)
					}
				}
			}
		}
	}
	// The third case has an unreadable header and must yield no hunks.
	files, _ := ParseUnifiedDiff(strings.NewReader(cases[2]))
	if len(files) == 1 && len(files[0].Hunks) != 0 {
		t.Errorf("malformed hunk header must not produce hunks: %+v", files[0].Hunks)
	}
	// The fourth is a legal minimal diff and must parse.
	files, _ = ParseUnifiedDiff(strings.NewReader(cases[3]))
	if len(files) != 1 || len(files[0].Hunks) != 1 {
		t.Errorf("minimal diff should parse: %+v", files)
	}
}

// Boundary: a diff beyond the line cap is refused.
func TestParseUnifiedDiff_LineCap(t *testing.T) {
	var b strings.Builder
	b.WriteString("diff --git a/x.js b/x.js\n--- a/x.js\n+++ b/x.js\n@@ -1,0 +1,300000 @@\n")
	for i := 0; i < maxDiffLines+10; i++ {
		b.WriteString("+x\n")
	}
	if _, err := ParseUnifiedDiff(strings.NewReader(b.String())); err == nil {
		t.Error("expected line-cap error")
	}
}

func TestDiffLines_PatienceAndExact(t *testing.T) {
	old := []string{"a", "b", "c", "d", "e", "f"}
	updated := []string{"a", "b", "X", "d", "e", "f", "g"}
	ed := DiffLines(old, updated)
	if ed.Approximate {
		t.Error("small diff must be exact")
	}
	if len(ed.Removed) != 1 || ed.Removed[0] != 3 {
		t.Errorf("removed = %v, want [3]", ed.Removed)
	}
	if len(ed.Added) != 2 || ed.Added[0] != 3 || ed.Added[1] != 7 {
		t.Errorf("added = %v, want [3 7]", ed.Added)
	}

	// Repeated lines (blank lines, braces) must not derail the anchors.
	old = []string{"{", "  a", "}", "", "{", "  b", "}"}
	updated = []string{"{", "  a", "}", "", "{", "  b2", "}"}
	ed = DiffLines(old, updated)
	if len(ed.Removed) != 1 || ed.Removed[0] != 6 || len(ed.Added) != 1 || ed.Added[0] != 6 {
		t.Errorf("repeated-line diff: %+v", ed)
	}

	// Identical inputs: nothing changed.
	if ed := DiffLines(old, old); len(ed.Added)+len(ed.Removed) != 0 {
		t.Errorf("identical inputs: %+v", ed)
	}
	// Empty sides.
	if ed := DiffLines(nil, []string{"x", "y"}); len(ed.Added) != 2 {
		t.Errorf("all added: %+v", ed)
	}
	if ed := DiffLines([]string{"x"}, nil); len(ed.Removed) != 1 {
		t.Errorf("all removed: %+v", ed)
	}
}

// Boundary: a region with no unique anchor and too many cells is reported as
// approximate and over-inclusive rather than aligned wrongly or hanging.
func TestDiffLines_LargeUnanchoredRegionIsApproximate(t *testing.T) {
	n := 2500 // 2500*2500 > maxExactCells
	old := make([]string, n)
	updated := make([]string, n)
	for i := range old {
		old[i] = "x"
		updated[i] = "y"
	}
	ed := DiffLines(old, updated)
	if !ed.Approximate {
		t.Error("expected approximate")
	}
	if len(ed.Removed) != n || len(ed.Added) != n {
		t.Errorf("approximate diff must include every line: %d/%d", len(ed.Removed), len(ed.Added))
	}
}
