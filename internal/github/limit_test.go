package github

import (
	"bytes"
	"strings"
	"testing"
)

func TestReadLimitedBody(t *testing.T) {
	small := strings.Repeat("a", 1024)
	got, err := readLimitedBody(strings.NewReader(small))
	if err != nil || string(got) != small {
		t.Fatalf("small body: got %d bytes, err %v", len(got), err)
	}

	exact := bytes.Repeat([]byte("a"), maxResponseBodyBytes)
	if got, err := readLimitedBody(bytes.NewReader(exact)); err != nil || len(got) != maxResponseBodyBytes {
		t.Fatalf("body at the limit: got %d bytes, err %v", len(got), err)
	}

	over := bytes.Repeat([]byte("a"), maxResponseBodyBytes+1)
	if _, err := readLimitedBody(bytes.NewReader(over)); err == nil {
		t.Fatal("body over the limit: want an error")
	}
}
