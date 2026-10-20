package health

import (
	"bytes"
	"testing"
)

func TestReadLimited(t *testing.T) {
	exact := bytes.Repeat([]byte("a"), maxBodyBytes)
	if got, err := readLimited(bytes.NewReader(exact)); err != nil || len(got) != maxBodyBytes {
		t.Fatalf("body at the limit: got %d bytes, err %v", len(got), err)
	}
	over := bytes.Repeat([]byte("a"), maxBodyBytes+1)
	if _, err := readLimited(bytes.NewReader(over)); err == nil {
		t.Fatal("body over the limit: want an error")
	}
}
