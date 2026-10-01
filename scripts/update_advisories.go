package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	cisaKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	epssBaseURL = "https://api.first.org/data/v1/epss"
)

func main() {
	outDir := flag.String("out", "testdata/advisories", "output directory for fixtures")
	flag.Parse()
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Fetching CISA KEV...")
	kevBody, err := fetchURL(cisaKEVURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to fetch KEV: %v\n", err)
		os.Exit(1)
	}
	kevPath := filepath.Join(*outDir, "kev.json")
	_ = os.WriteFile(kevPath, kevBody, 0644)
	fmt.Println("Saved", kevPath)

	// Extract CVE IDs from KEV file
	cves := extractCvesFromKEV(kevBody)
	if len(cves) == 0 {
		fmt.Println("No CVEs found in KEV payload; skipping EPSS fetch")
		return
	}

	fmt.Printf("Found %d CVEs; fetching EPSS in batches...\n", len(cves))
	epssMap := make(map[string]map[string]string)
	client := &http.Client{Timeout: 30 * time.Second}
	for i := 0; i < len(cves); i += 100 {
		end := i + 100
		if end > len(cves) {
			end = len(cves)
		}
		batch := cves[i:end]
		reqURL := epssBaseURL + "?cve=" + strings.Join(batch, ",")
		req, _ := http.NewRequest("GET", reqURL, nil)
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "EPSS request failed: %v\n", err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		var r struct {
			Data []struct {
				CVE        string `json:"cve"`
				EPSS       string `json:"epss"`
				Percentile string `json:"percentile"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			fmt.Fprintf(os.Stderr, "failed parse EPSS response: %v\n", err)
			continue
		}
		for _, d := range r.Data {
			epssMap[strings.ToUpper(d.CVE)] = map[string]string{"epss": d.EPSS, "percentile": d.Percentile}
		}
		// avoid hammering the API
		time.Sleep(500 * time.Millisecond)
	}

	epssPath := filepath.Join(*outDir, "epss.json")
	b, _ := json.MarshalIndent(epssMap, "", "  ")
	_ = os.WriteFile(epssPath, b, 0644)
	fmt.Println("Saved", epssPath)
	fmt.Println("Done")
}

func fetchURL(url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(resp.Body)
}

func extractCvesFromKEV(body []byte) []string {
	var v struct {
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return nil
	}
	out := make([]string, 0, len(v.Vulnerabilities))
	for _, item := range v.Vulnerabilities {
		id := strings.TrimSpace(item.CveID)
		if id != "" {
			out = append(out, id)
		}
	}
	return out
}
