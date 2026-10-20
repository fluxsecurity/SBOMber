// Package reproducible gives every output the same clock. With
// SOURCE_DATE_EPOCH set (the reproducible-builds convention), every
// timestamp SBOMber writes is that time, so two runs over the same inputs
// write identical files.
package reproducible

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// SourceDateEpoch returns the time SOURCE_DATE_EPOCH names, and whether it
// is set. A value that is not a non-negative number of seconds is an error.
func SourceDateEpoch() (time.Time, bool, error) {
	value, set := os.LookupEnv("SOURCE_DATE_EPOCH")
	if !set || value == "" {
		return time.Time{}, false, nil
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds < 0 {
		return time.Time{}, false, fmt.Errorf("SOURCE_DATE_EPOCH must be a non-negative number of seconds, got %q", value)
	}
	return time.Unix(seconds, 0).UTC(), true, nil
}

// Now is SOURCE_DATE_EPOCH when it is set and valid, otherwise the current
// time. Commands check SourceDateEpoch first and reject a bad value; Now is
// for code that only needs a timestamp.
func Now() time.Time {
	if t, set, err := SourceDateEpoch(); err == nil && set {
		return t
	}
	return time.Now().UTC()
}
