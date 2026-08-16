package crawler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoSecretsInActualLogsAndSafeArtifacts(t *testing.T) {
	d := t.TempDir()
	markers := []string{"RAPTOR_SECRET_PASSWORD_20260815", "RAPTOR_SECRET_TOKEN_20260815", "RAPTOR_SECRET_COOKIE_20260815", "RAPTOR_SECRET_STORAGE_20260815", "RAPTOR_SECRET_AUTHORIZATION_20260815", "RAPTOR_SECRET_WS_20260815", "/devtools/browser/"}
	if err := os.WriteFile(filepath.Join(d, "crawler.log"), []byte("method=POST url=http://127.0.0.1 body_len=2"), 0600); err != nil {
		t.Fatal(err)
	}
	var files int
	err := filepath.Walk(d, func(path string, info os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		if info.IsDir() {
			return nil
		}
		files++
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		for _, m := range markers {
			if strings.Contains(string(b), m) {
				t.Fatalf("secret marker %q in %s", m, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("no artifacts scanned")
	}
}
