// crawler/fingerprint.go
package crawler

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
)

// CalculateFingerprint generates a unique fingerprint for a request
func CalculateFingerprint(method, urlStr, body, contentType string) string {
	parsedURL, _ := url.Parse(urlStr)
	path := parsedURL.Path
	if path == "" {
		path = "/"
	}

	query := parsedURL.Query()
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var queryStr strings.Builder
	for _, k := range keys {
		if queryStr.Len() > 0 {
			queryStr.WriteString("&")
		}
		queryStr.WriteString(k)
		queryStr.WriteString("=")
		queryStr.WriteString(query.Get(k))
	}

	fingerprint := strings.ToUpper(method) + "|" + path + "|" + queryStr.String()

	if method == "POST" || method == "PUT" || method == "PATCH" {
		if len(body) > 1024 {
			hash := sha256.Sum256([]byte(body))
			fingerprint += "|" + hex.EncodeToString(hash[:])
		} else {
			fingerprint += "|" + body
		}
	}

	fingerprint += "|" + contentType
	hash := sha256.Sum256([]byte(fingerprint))
	return hex.EncodeToString(hash[:])
}

// NormalizeURL normalizes a URL for deduplication
func NormalizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	path := u.Path
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		u.Path = path[:len(path)-1]
	}
	u.Fragment = ""
	return u.String()
}

// ExtractParameters extracts parameters from URL, body, and content type
func ExtractParameters(urlStr, body, contentType string) map[string]interface{} {
	params := make(map[string]interface{})

	parsedURL, _ := url.Parse(urlStr)
	if parsedURL != nil {
		for k, v := range parsedURL.Query() {
			if len(v) == 1 {
				params[k] = v[0]
			} else {
				params[k] = v
			}
		}
	}

	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		values, err := url.ParseQuery(body)
		if err == nil {
			for k, v := range values {
				if len(v) == 1 {
					params[k] = v[0]
				} else {
					params[k] = v
				}
			}
		}
	}

	return params
}