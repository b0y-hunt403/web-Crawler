package crawler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeURLAndFingerprint(t *testing.T) {
	first := "HTTPS://Example.COM:443/api/?b=2&a=1#fragment"
	second := "https://example.com/api?a=1&b=2"
	if got, want := NormalizeURL(first), NormalizeURL(second); got != want {
		t.Fatalf("normalized URLs differ: %q != %q", got, want)
	}
	a := CalculateFingerprint("post", first, `{"b":2,"a":1}`, "Application/JSON; charset=utf-8")
	b := CalculateFingerprint("POST", second, `{ "a": 1, "b": 2 }`, "application/json")
	if a != b {
		t.Fatal("semantically equivalent JSON requests must deduplicate")
	}
}

func TestDetectContentTypes(t *testing.T) {
	tests := []struct {
		contentType string
		check       func(ContentTypeInfo) bool
	}{
		{"application/json", func(v ContentTypeInfo) bool { return v.IsJSON }},
		{"application/x-www-form-urlencoded", func(v ContentTypeInfo) bool { return v.IsURLEncoded }},
		{"multipart/form-data; boundary=raptor", func(v ContentTypeInfo) bool { return v.IsMultipart && v.Boundary == "raptor" }},
		{"application/graphql", func(v ContentTypeInfo) bool { return v.IsGraphQL }},
		{"application/xml", func(v ContentTypeInfo) bool { return v.IsXML }},
		{"text/plain; charset=utf-8", func(v ContentTypeInfo) bool { return v.IsText && v.Charset == "utf-8" }},
	}
	for _, test := range tests {
		if !test.check(DetectContentType(test.contentType)) {
			t.Errorf("classification failed for %s", test.contentType)
		}
	}
}

func TestAuthSessionPersistenceAndExport(t *testing.T) {
	store, err := NewRequestStore(filepath.Join(t.TempDir(), "raptor.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Second)
	session := &AuthSession{
		ID: "auth-1", LoginURL: "https://example.com/login", FinalURL: "https://example.com/dashboard",
		LoginMethod: "form", SuccessReason: "url_change", CookieHeader: "session=secret",
		CSRFField: "_csrf", CSRFToken: "token", AuthenticatedAt: now,
		Cookies: []CookieInfo{{Name: "session", Value: "secret", Domain: "example.com", Path: "/", HttpOnly: true, Secure: true}},
		Storage: []BrowserOriginStorage{{Origin: "https://example.com", LocalStorage: []BrowserStorageValue{{Name: "access_token", Value: "abc"}}}},
	}
	if err := store.SaveAuthSession(session); err != nil {
		t.Fatal(err)
	}
	for table := range map[string]struct{}{"auth_sessions": {}, "cookies": {}, "csrf_tokens": {}} {
		var count int
		if err := store.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s count = %d, err=%v", table, count, err)
		}
	}

	path := filepath.Join(t.TempDir(), "cookies.json")
	if err := exportAuthSession(path, session); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var exported authExport
	if err := json.Unmarshal(data, &exported); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(exported.ToolHints["sqlmap"], "session=secret") {
		t.Fatal("SQLMap export does not contain the authenticated cookie")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("cookie export permissions = %v, err=%v", info.Mode().Perm(), err)
	}
}
