package usagegraph

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

func stableID(prefix string, parts ...string) string {
	hash := sha256.New()
	values := append([]string{prefix}, parts...)

	for _, value := range values {
		_, _ = hash.Write([]byte(strconv.Itoa(len(value))))
		_, _ = hash.Write([]byte{':'})
		_, _ = hash.Write([]byte(value))
	}

	digest := hash.Sum(nil)
	return prefix + "-" + hex.EncodeToString(digest[:16])
}
