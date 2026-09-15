// Package netstatus gives every network-dependent enrichment source (EPSS,
// KEV, GHSA, npm registry signals, malware scanning) a common, visible
// outcome instead of silently swallowing errors. Without it, a source that
// returned nothing because the network was unreachable looks identical to
// one that ran cleanly and genuinely found nothing — an operator has no way
// to tell "clean" apart from "we don't know."
package netstatus

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
)

// Status is the outcome of one attempt to reach a network data source.
type Status string

const (
	// Success means the source was reached and returned usable data (or a
	// definitive "not found" answer, which is still a real answer).
	Success Status = "success"
	// Unavailable means the source could not be reached or returned an
	// error response that was not a rate limit (DNS failure, connection
	// refused, 5xx, malformed response, etc.).
	Unavailable Status = "unavailable"
	// TimedOut means the request exceeded its deadline.
	TimedOut Status = "timed_out"
	// RateLimited means the source responded but refused the request
	// because of a rate limit (HTTP 429, or a source-specific equivalent).
	RateLimited Status = "rate_limited"
	// Skipped means no attempt was made at all — nothing needed the source
	// this run (e.g. zero CVEs to look up), or it was disabled.
	Skipped Status = "skipped"
)

// severity ranks statuses from best to worst so a batch of attempts against
// the same source can be collapsed into one representative outcome.
var severity = map[Status]int{
	Success:     0,
	Skipped:     1,
	RateLimited: 2,
	TimedOut:    3,
	Unavailable: 4,
}

// Worse returns whichever of a and b represents the more serious outcome.
// Unrecognized statuses are treated as equal to Unavailable.
func Worse(a, b Status) Status {
	ra, ok := severity[a]
	if !ok {
		ra = severity[Unavailable]
	}
	rb, ok := severity[b]
	if !ok {
		rb = severity[Unavailable]
	}
	if rb > ra {
		return b
	}
	return a
}

// Report is one data source's outcome for a scan.
type Report struct {
	// Source names the data source, e.g. "epss", "kev", "ghsa",
	// "npm_registry", "malware".
	Source string
	Status Status
	// Detail is a short, plain-language reason, populated when Status is
	// not Success (e.g. the underlying error message). Empty on success.
	Detail string
}

// Collector accumulates Reports from concurrent goroutines.
type Collector struct {
	mu      sync.Mutex
	reports []Report
}

// Add records one report.
func (c *Collector) Add(r Report) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reports = append(c.reports, r)
}

// Reports returns a copy of everything recorded so far.
func (c *Collector) Reports() []Report {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Report, len(c.reports))
	copy(out, c.reports)
	return out
}

// ClassifyErr maps a transport-level error (a failed http.Client.Do call)
// to a Status. A nil error classifies as Success.
func ClassifyErr(err error) Status {
	if err == nil {
		return Success
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return TimedOut
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return TimedOut
	}
	return Unavailable
}

// ClassifyHTTPStatus maps a completed HTTP response's status code to a
// Status. A 404 classifies as Unavailable here: for a source where "not
// found" is itself a meaningful answer (a specific advisory or package that
// legitimately doesn't exist), the caller must recognize that status code
// itself before falling back to this — see e.g. fetchGHSAByID.
func ClassifyHTTPStatus(code int) Status {
	switch {
	case code == http.StatusTooManyRequests:
		return RateLimited
	case code >= 200 && code < 300:
		return Success
	default:
		return Unavailable
	}
}
