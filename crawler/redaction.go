package crawler

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
)

func shortRequestHash(value string) string {
	s := sha256.Sum256([]byte(value))
	return hex.EncodeToString(s[:8])
}

func redactLogURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<redacted-url>"
	}
	q := u.Query()
	for k := range q {
		if sensitiveName(k) {
			q.Set(k, "<redacted>")
		}
	}
	u.RawQuery = q.Encode()
	if strings.Contains(u.Path, "/devtools/browser/") {
		return "<redacted-browser-url>"
	}
	return u.String()
}
