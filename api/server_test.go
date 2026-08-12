package api

import (
	"net/http/httptest"
	"os"
	"testing"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	p := t.TempDir() + "/x.db"
	s, e := New(p, "secret")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	return s
}
func TestHealthAndReady(t *testing.T) {
	s := testServer(t)
	for _, path := range []string{"/healthz", "/readyz"} {
		r := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
}
func TestAPIKeyRequiredJSON(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest("GET", "/api/v1/crawls", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("got %d", w.Code)
	}
	if w.Header().Get("Content-Type") == "text/plain; charset=utf-8" {
		t.Fatal("plain error")
	}
}
func TestExactRequestRoutes(t *testing.T) {
	s := testServer(t)
	s.db.Exec(`INSERT INTO crawl_runs(id,start_url,status,created_at) VALUES('a','http://x','completed',CURRENT_TIMESTAMP)`)
	if _, e := s.db.Exec(`INSERT INTO discovered_requests(id,crawl_id,url,method,source_type,created_at) VALUES('r','a','http://x/a','POST','cdp',CURRENT_TIMESTAMP)`); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/api/v1/crawls/a/requests", "/api/v1/crawls/a/requests/r"} {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("X-Raptor-API-Key", "secret")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	r := httptest.NewRequest("GET", "/api/v1/crawls/b/requests/r", nil)
	r.Header.Set("X-Raptor-API-Key", "secret")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("cross crawl %d", w.Code)
	}
}
func TestEnvDev(t *testing.T) {
	os.Setenv("RAPTOR_API_DEV_MODE", "true")
	defer os.Unsetenv("RAPTOR_API_DEV_MODE")
}
