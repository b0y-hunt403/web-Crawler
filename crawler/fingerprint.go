// crawler/fingerprint.go
package crawler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

// CalculateFingerprint generates a unique fingerprint for a request
func CalculateFingerprint(method, urlStr, body, contentType string) string {
	fingerprint := strings.ToUpper(strings.TrimSpace(method)) + "|" +
		NormalizeURL(urlStr) + "|" + NormalizeRequestBody(body, contentType) + "|" +
		NormalizeContentType(contentType)
	hash := sha256.Sum256([]byte(fingerprint))
	return hex.EncodeToString(hash[:])
}

// NormalizeURL normalizes a URL for deduplication
func NormalizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if u.Scheme == "http" && strings.HasSuffix(u.Host, ":80") {
		u.Host = strings.TrimSuffix(u.Host, ":80")
	}
	if u.Scheme == "https" && strings.HasSuffix(u.Host, ":443") {
		u.Host = strings.TrimSuffix(u.Host, ":443")
	}
	path := u.Path
	if path == "" {
		u.Path = "/"
	}
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		u.Path = path[:len(path)-1]
	}
	u.RawQuery = u.Query().Encode()
	u.Fragment = ""
	return u.String()
}

func NormalizeContentType(contentType string) string {
	if i := strings.IndexByte(contentType, ';'); i >= 0 {
		contentType = contentType[:i]
	}
	return strings.ToLower(strings.TrimSpace(contentType))
}

// NormalizeRequestBody canonicalizes structured bodies for deduplication while
// callers retain the exact wire body in DiscoveredRequest.Body.
func NormalizeRequestBody(body, contentType string) string {
	if body == "" {
		return ""
	}
	switch NormalizeContentType(contentType) {
	case "application/json", "application/graphql+json":
		var value interface{}
		if json.Unmarshal([]byte(body), &value) == nil {
			if canonical, err := json.Marshal(value); err == nil {
				return string(canonical)
			}
		}
	case "application/x-www-form-urlencoded":
		if values, err := url.ParseQuery(body); err == nil {
			return values.Encode()
		}
	}
	return body
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

// GenerateResponseFingerprint creates a fingerprint from response
func GenerateResponseFingerprint(statusCode int, contentType string,
	contentLength int64, body string, headers map[string]string) ResponseFingerprint {

	fp := ResponseFingerprint{
		StatusCode:    statusCode,
		ContentType:   contentType,
		ContentLength: contentLength,
		Headers:       headers,
	}

	// Generate hash of body
	if body != "" {
		hash := sha256.Sum256([]byte(body))
		fp.Hash = hex.EncodeToString(hash[:])
	}

	// Extract mime type from content-type
	if contentType != "" {
		parts := strings.Split(contentType, ";")
		fp.MimeType = strings.TrimSpace(parts[0])
	}

	// Extract HTML title if present
	if strings.Contains(contentType, "text/html") {
		fp.Title = extractHTMLTitle(body)
	}

	// Extract server header
	if server, ok := headers["server"]; ok {
		fp.Server = server
	}

	// Extract ETag
	if etag, ok := headers["etag"]; ok {
		fp.Etag = etag
	}

	// Extract Last-Modified
	if lm, ok := headers["last-modified"]; ok {
		fp.LastModified = lm
	}

	return fp
}

// extractHTMLTitle extracts title from HTML
func extractHTMLTitle(html string) string {
	// Simple regex to extract title
	titleRegex := regexp.MustCompile(`<title[^>]*>([^<]*)</title>`)
	matches := titleRegex.FindStringSubmatch(html)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}
