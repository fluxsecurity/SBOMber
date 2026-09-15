package supplychain

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/netstatus"
)

func withMockRegistry(t *testing.T, registryHandler, downloadsHandler http.HandlerFunc) {
	t.Helper()

	registrySrv := httptest.NewServer(registryHandler)
	t.Cleanup(registrySrv.Close)
	downloadsSrv := httptest.NewServer(downloadsHandler)
	t.Cleanup(downloadsSrv.Close)

	origRegistry, origDownloads := npmRegistryBaseURL, npmDownloadsBaseURL
	npmRegistryBaseURL = registrySrv.URL
	npmDownloadsBaseURL = downloadsSrv.URL
	t.Cleanup(func() {
		npmRegistryBaseURL = origRegistry
		npmDownloadsBaseURL = origDownloads
	})
}

func TestFetchNpmRegistrySignalsSuccess(t *testing.T) {
	withMockRegistry(t,
		func(w http.ResponseWriter, r *http.Request) {
			doc := npmPackageDoc{}
			doc.DistTags.Latest = "1.2.3"
			doc.Maintainers = []struct {
				Name string `json:"name"`
			}{{Name: "alice"}, {Name: "bob"}}
			doc.Versions = map[string]struct {
				Deprecated string `json:"deprecated"`
			}{
				"1.2.3": {Deprecated: ""},
			}
			_ = json.NewEncoder(w).Encode(doc)
		},
		func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(npmDownloadsDoc{Downloads: 42000})
		},
	)

	signals, status, err := FetchNpmRegistrySignals(context.Background(), "left-pad", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != netstatus.Success {
		t.Errorf("status = %v, want %v", status, netstatus.Success)
	}
	if signals.MaintainerCount != 2 {
		t.Errorf("MaintainerCount = %d, want 2", signals.MaintainerCount)
	}
	if signals.WeeklyDownloads != 42000 {
		t.Errorf("WeeklyDownloads = %d, want 42000", signals.WeeklyDownloads)
	}
	if signals.Deprecated {
		t.Error("Deprecated = true, want false")
	}
}

func TestFetchNpmRegistrySignalsDeprecated(t *testing.T) {
	withMockRegistry(t,
		func(w http.ResponseWriter, r *http.Request) {
			doc := npmPackageDoc{}
			doc.DistTags.Latest = "2.0.0"
			doc.Versions = map[string]struct {
				Deprecated string `json:"deprecated"`
			}{
				"2.0.0": {Deprecated: "use package-b instead"},
			}
			_ = json.NewEncoder(w).Encode(doc)
		},
		func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(npmDownloadsDoc{Downloads: 5})
		},
	)

	signals, status, err := FetchNpmRegistrySignals(context.Background(), "old-package", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != netstatus.Success {
		t.Errorf("status = %v, want %v", status, netstatus.Success)
	}
	if !signals.Deprecated || signals.DeprecatedNote != "use package-b instead" {
		t.Errorf("expected deprecated flag with note, got %+v", signals)
	}
}

func TestFetchNpmRegistrySignalsUnavailable(t *testing.T) {
	withMockRegistry(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		},
		func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(npmDownloadsDoc{Downloads: 5})
		},
	)

	signals, status, err := FetchNpmRegistrySignals(context.Background(), "broken-package", "")
	if err == nil {
		t.Fatal("expected an error when the registry returns 500")
	}
	if status != netstatus.Unavailable {
		t.Errorf("status = %v, want %v", status, netstatus.Unavailable)
	}
	// The downloads endpoint still succeeded, so its data must not be lost
	// just because the registry endpoint failed.
	if signals.WeeklyDownloads != 5 {
		t.Errorf("WeeklyDownloads = %d, want 5 even though the registry call failed", signals.WeeklyDownloads)
	}
}

func TestFetchNpmRegistrySignalsRateLimited(t *testing.T) {
	withMockRegistry(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		},
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		},
	)

	_, status, err := FetchNpmRegistrySignals(context.Background(), "popular-package", "")
	if err == nil {
		t.Fatal("expected an error when both endpoints are rate limited")
	}
	if status != netstatus.RateLimited {
		t.Errorf("status = %v, want %v", status, netstatus.RateLimited)
	}
}

func TestFetchNpmRegistrySignalsMissingDownloadHistory(t *testing.T) {
	withMockRegistry(t,
		func(w http.ResponseWriter, r *http.Request) {
			doc := npmPackageDoc{}
			doc.DistTags.Latest = "0.0.1"
			_ = json.NewEncoder(w).Encode(doc)
		},
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		},
	)

	signals, status, err := FetchNpmRegistrySignals(context.Background(), "brand-new-package", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != netstatus.Success {
		t.Errorf("status = %v, want %v (a 404 downloads response is a real zero-downloads answer)", status, netstatus.Success)
	}
	if signals.WeeklyDownloads != 0 {
		t.Errorf("WeeklyDownloads = %d, want 0", signals.WeeklyDownloads)
	}
}

func TestCheckMalwareReportsSkipped(t *testing.T) {
	report := CheckMalware(context.Background(), "any-package")
	if report.Source != "malware" {
		t.Errorf("Source = %q, want %q", report.Source, "malware")
	}
	if report.Status != netstatus.Skipped {
		t.Errorf("Status = %v, want %v", report.Status, netstatus.Skipped)
	}
	if report.Detail == "" {
		t.Error("expected a detail explaining why malware scanning was skipped")
	}
}
