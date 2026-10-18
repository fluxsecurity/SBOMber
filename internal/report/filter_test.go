package report

import (
	"reflect"
	"strings"
	"testing"
)

func shownIDs(r Report) map[string]bool {
	ids := map[string]bool{}
	for _, sg := range r.Sections {
		for _, pg := range sg.Groups {
			for _, f := range pg.Findings {
				ids[f.FindingID] = true
			}
		}
	}
	return ids
}

func hiddenBySection(r Report) map[Section]int {
	out := map[Section]int{}
	for _, sg := range r.Sections {
		out[sg.Section] = sg.Hidden
	}
	return out
}

func TestApply_NoFilterIsIdentity(t *testing.T) {
	r := BuildReport(mixedResults())
	if got := r.Apply(Filter{}); !reflect.DeepEqual(got, r) {
		t.Fatal("an empty filter changed the report")
	}
}

func TestApply_SectionFilterKeepsMandatorySectionsWithHiddenCounts(t *testing.T) {
	r := BuildReport(mixedResults()).Apply(Filter{Sections: []string{"update-first"}})
	if got, want := shownIDs(r), map[string]bool{"f-use": true, "f-orphan": true}; !reflect.DeepEqual(got, want) {
		t.Errorf("shown %v, want %v", got, want)
	}
	h := hiddenBySection(r)
	if _, ok := h[SectionInsufficientInfo]; !ok {
		t.Error("insufficient-information section dropped by the filter")
	}
	if h[SectionNoDirectUsage] != 3 {
		t.Errorf("no-direct-usage hidden = %d, want 3", h[SectionNoDirectUsage])
	}
	if r.TotalBeforeFilter != 5 || !strings.Contains(filterLine(r), "showing 2 of 5 finding(s)") {
		t.Errorf("filter line = %q", filterLine(r))
	}
	// The KEV pointer entry has no findings of its own and stays when only
	// section and package filters are set.
	if _, ok := entriesFor(r, "pkg:npm/kevpkg@1.0.0")[SectionUpdateFirst]; !ok {
		t.Error("KEV pointer entry dropped by a section-only filter")
	}
}

func TestApply_StateFilter(t *testing.T) {
	r := BuildReport(mixedResults()).Apply(Filter{States: []string{StateNoUsageDetected}})
	if got, want := shownIDs(r), map[string]bool{"f-none-1": true, "f-none-2": true, "f-kev": true}; !reflect.DeepEqual(got, want) {
		t.Errorf("shown %v, want %v", got, want)
	}
	if h := hiddenBySection(r); h[SectionUpdateFirst] != 2 {
		t.Errorf("update-first hidden = %d, want 2", h[SectionUpdateFirst])
	}
	if _, ok := entriesFor(r, "pkg:npm/kevpkg@1.0.0")[SectionUpdateFirst]; ok {
		t.Error("KEV pointer entry kept although a state filter is set")
	}
}

func TestApply_PackageAndBandFilters(t *testing.T) {
	r := BuildReport(mixedResults()).Apply(Filter{Packages: []string{"LODASH"}, Bands: []string{BandLowerPriority}})
	if got, want := shownIDs(r), map[string]bool{"f-none-1": true, "f-none-2": true}; !reflect.DeepEqual(got, want) {
		t.Errorf("shown %v, want %v", got, want)
	}
}

func TestFilter_ValidateAndParse(t *testing.T) {
	if err := (Filter{Sections: []string{"update-first"}, Bands: []string{"act_now"}, States: []string{"unknown"}}).Validate(); err != nil {
		t.Errorf("valid filter rejected: %v", err)
	}
	for name, f := range map[string]Filter{
		"section": {Sections: []string{"Update first"}},
		"band":    {Bands: []string{"urgent"}},
		"state":   {States: []string{"safe"}},
		"package": {Packages: []string{" "}},
	} {
		if err := f.Validate(); err == nil {
			t.Errorf("%s: invalid filter accepted", name)
		}
	}
	if got, want := ParseList(" b, a ,b"), []string{"a", "b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ParseList = %v, want %v", got, want)
	}
	if ParseList("") != nil {
		t.Error("ParseList of empty input should be nil")
	}
}

func TestRender_FilteredReportSaysWhatIsHidden(t *testing.T) {
	r := BuildReport(mixedResults()).Apply(Filter{Sections: []string{"update-first"}})
	text := RenderText(r)
	html, err := RenderHTML(r)
	if err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"text": text, "html": html} {
		if !strings.Contains(out, "showing 2 of 5 finding(s)") {
			t.Errorf("%s: filter line missing", name)
		}
		if !strings.Contains(out, hiddenLine(3)) {
			t.Errorf("%s: hidden count for the no-direct-usage section missing", name)
		}
		if !strings.Contains(out, string(SectionInsufficientInfo)) || !strings.Contains(out, string(SectionNoDirectUsage)) {
			t.Errorf("%s: a mandatory section heading is missing from a filtered report", name)
		}
	}
	banned := []string{"safe", "clean", "unaffected", "not affected", "false positive",
		"not reachable", "low urgency", "informational", "no risk"}
	out := strings.ToLower(RenderText(withoutJustifications(r)))
	for _, p := range banned {
		if strings.Contains(out, p) {
			t.Errorf("filtered report contains %q", p)
		}
	}
}
