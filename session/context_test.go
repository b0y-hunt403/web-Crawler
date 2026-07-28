package session

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileSessionRoundTripAndTokenExtraction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	state := &State{
		ID: "admin",
		Cookies: []StateCookie{{
			Name: "session", Value: "secret", Domain: "example.com", Path: "/", HTTPOnly: true, Secure: true,
		}},
		Origins: []OriginState{{
			Origin: "https://example.com",
			LocalStorage: []StorageValue{{
				Name: "access_token", Value: "eyJheader.eyJpayload.signature",
			}},
			SessionStorage: []StorageValue{{Name: "theme", Value: "dark"}},
		}},
	}
	if err := SaveState(path, state); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state permissions = %o, want 600", info.Mode().Perm())
	}

	fileSession, err := NewFileSession(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := fileSession.State(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if fileSession.ID() != "admin" || len(loaded.Tokens) != 1 || loaded.Tokens[0].Kind != "jwt" {
		t.Fatalf("unexpected loaded session: %#v", loaded)
	}
	if loaded.Origins[0].SessionStorage[0].Value != "dark" {
		t.Fatal("sessionStorage was not preserved")
	}
}

func TestStorageInitScriptIncludesBothStorageTypes(t *testing.T) {
	script, err := storageInitScript([]OriginState{{
		Origin:         "https://example.com",
		LocalStorage:   []StorageValue{{Name: "a", Value: "1"}},
		SessionStorage: []StorageValue{{Name: "b", Value: "2"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if script == "" {
		t.Fatal("expected a storage initialization script")
	}
}
