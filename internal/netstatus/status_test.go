package netstatus

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestClassifyErr(t *testing.T) {
	if got := ClassifyErr(nil); got != Success {
		t.Errorf("nil error: got %v, want %v", got, Success)
	}
	if got := ClassifyErr(context.DeadlineExceeded); got != TimedOut {
		t.Errorf("deadline exceeded: got %v, want %v", got, TimedOut)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	if got := ClassifyErr(ctx.Err()); got != TimedOut {
		t.Errorf("expired context: got %v, want %v", got, TimedOut)
	}
}

func TestClassifyHTTPStatus(t *testing.T) {
	tests := []struct {
		code int
		want Status
	}{
		{http.StatusOK, Success},
		{http.StatusNotFound, Unavailable},
		{http.StatusTooManyRequests, RateLimited},
		{http.StatusInternalServerError, Unavailable},
		{http.StatusForbidden, Unavailable},
	}
	for _, tt := range tests {
		if got := ClassifyHTTPStatus(tt.code); got != tt.want {
			t.Errorf("ClassifyHTTPStatus(%d) = %v, want %v", tt.code, got, tt.want)
		}
	}
}

func TestWorse(t *testing.T) {
	if got := Worse(Success, RateLimited); got != RateLimited {
		t.Errorf("Worse(Success, RateLimited) = %v, want %v", got, RateLimited)
	}
	if got := Worse(Unavailable, TimedOut); got != Unavailable {
		t.Errorf("Worse(Unavailable, TimedOut) = %v, want %v", got, Unavailable)
	}
	if got := Worse(Skipped, Success); got != Skipped {
		t.Errorf("Worse(Skipped, Success) = %v, want %v", got, Skipped)
	}
}

func TestCollector(t *testing.T) {
	var c Collector
	c.Add(Report{Source: "epss", Status: Success})
	c.Add(Report{Source: "kev", Status: TimedOut, Detail: "context deadline exceeded"})

	reports := c.Reports()
	if len(reports) != 2 {
		t.Fatalf("expected 2 reports, got %d", len(reports))
	}
	if reports[1].Status != TimedOut || reports[1].Detail == "" {
		t.Errorf("expected kev report to carry TimedOut status and a detail, got %+v", reports[1])
	}
}

func TestClassifyResponse(t *testing.T) {
	resp := func(code int, headers map[string]string) *http.Response {
		r := &http.Response{StatusCode: code, Header: http.Header{}}
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return r
	}
	tests := []struct {
		name string
		resp *http.Response
		want Status
	}{
		{"github quota exhausted", resp(403, map[string]string{"X-RateLimit-Remaining": "0"}), RateLimited},
		{"github secondary limit", resp(403, map[string]string{"Retry-After": "60"}), RateLimited},
		{"plain forbidden", resp(403, map[string]string{"X-RateLimit-Remaining": "4999"}), Unavailable},
		{"429", resp(429, nil), RateLimited},
		{"ok", resp(200, nil), Success},
	}
	for _, tt := range tests {
		if got := ClassifyResponse(tt.resp); got != tt.want {
			t.Errorf("%s: ClassifyResponse = %v, want %v", tt.name, got, tt.want)
		}
	}
}
