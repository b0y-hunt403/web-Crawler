// crawler/store.go
package crawler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// RequestStore persists DiscoveredRequest records to SQLite
type RequestStore struct {
	db *sql.DB
}

func NewRequestStore(dbPath string) (*RequestStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;`); err != nil {
		db.Close()
		return nil, err
	}

	schema := `
CREATE TABLE IF NOT EXISTS discovered_requests (
	id TEXT PRIMARY KEY,
	auth_session_id TEXT,
	url TEXT NOT NULL,
	method TEXT NOT NULL,
	headers TEXT,
	body TEXT,
	source_type TEXT,
	depth INTEGER,
	normalized_url TEXT,
	created_at TIMESTAMP,
	form_fields TEXT,
	form TEXT,
	spa_route TEXT,
	shadow_dom_elements TEXT,
	parameters TEXT,
	cookies TEXT,
	response TEXT,
	body_type TEXT,
	json_format TEXT
);
CREATE INDEX IF NOT EXISTS idx_normalized_url ON discovered_requests(normalized_url);
CREATE INDEX IF NOT EXISTS idx_source_type ON discovered_requests(source_type);
CREATE TABLE IF NOT EXISTS auth_sessions (
	id TEXT PRIMARY KEY,
	login_url TEXT NOT NULL,
	final_url TEXT,
	login_method TEXT NOT NULL,
	success_reason TEXT,
	cookie_header TEXT,
	storage TEXT,
	authenticated_at TIMESTAMP NOT NULL,
	expires_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS login_requests (
	request_id TEXT PRIMARY KEY,
	auth_session_id TEXT,
	url TEXT NOT NULL,
	method TEXT NOT NULL,
	headers TEXT,
	body TEXT,
	created_at TIMESTAMP NOT NULL,
	FOREIGN KEY(request_id) REFERENCES discovered_requests(id) ON DELETE CASCADE,
	FOREIGN KEY(auth_session_id) REFERENCES auth_sessions(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS cookies (
	auth_session_id TEXT NOT NULL,
	name TEXT NOT NULL,
	value TEXT,
	domain TEXT NOT NULL DEFAULT '',
	path TEXT NOT NULL DEFAULT '/',
	expires_at TIMESTAMP,
	http_only INTEGER NOT NULL DEFAULT 0,
	secure INTEGER NOT NULL DEFAULT 0,
	same_site TEXT,
	is_session INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY(auth_session_id, name, domain, path),
	FOREIGN KEY(auth_session_id) REFERENCES auth_sessions(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS csrf_tokens (
	auth_session_id TEXT NOT NULL,
	field_name TEXT NOT NULL,
	token_value TEXT NOT NULL,
	source_url TEXT,
	discovered_at TIMESTAMP NOT NULL,
	PRIMARY KEY(auth_session_id, field_name),
	FOREIGN KEY(auth_session_id) REFERENCES auth_sessions(id) ON DELETE CASCADE
);
`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}

	for _, col := range []string{"auth_session_id", "parameters", "cookies", "response", "body_type", "json_format"} {
		_, _ = db.Exec("ALTER TABLE discovered_requests ADD COLUMN " + col + " TEXT")
	}

	return &RequestStore{db: db}, nil
}

func (s *RequestStore) Close() error {
	return s.db.Close()
}

// SaveRequest upserts a discovered request
func (s *RequestStore) SaveRequest(req *DiscoveredRequest) error {
	headersJSON, _ := json.Marshal(req.Headers)
	fieldsJSON, _ := json.Marshal(req.FormFields)
	formJSON, _ := json.Marshal(req.Form)
	spaJSON, _ := json.Marshal(req.SPARoute)
	shadowJSON, _ := json.Marshal(req.ShadowDOMElements)
	paramsJSON, _ := json.Marshal(req.Parameters)
	cookiesJSON, _ := json.Marshal(req.Cookies)
	responseJSON, _ := json.Marshal(req.Response)
	jsonFormatJSON, _ := json.Marshal(req.JSONFormat)

	if req.CreatedAt.IsZero() {
		req.CreatedAt = time.Now().UTC()
	}

	_, err := s.db.Exec(`
INSERT INTO discovered_requests
	(id, auth_session_id, url, method, headers, body, source_type, depth, normalized_url, created_at,
	 form_fields, form, spa_route, shadow_dom_elements, parameters, cookies, response, body_type, json_format)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	auth_session_id=COALESCE(excluded.auth_session_id, discovered_requests.auth_session_id),
	url=excluded.url, method=excluded.method, headers=excluded.headers, body=excluded.body,
	source_type=excluded.source_type, depth=MIN(discovered_requests.depth, excluded.depth),
	normalized_url=excluded.normalized_url, form_fields=excluded.form_fields, form=excluded.form,
	spa_route=excluded.spa_route, shadow_dom_elements=excluded.shadow_dom_elements,
	parameters=excluded.parameters, cookies=excluded.cookies, response=excluded.response,
	body_type=excluded.body_type, json_format=excluded.json_format
`,
		req.ID, req.AuthSessionID, req.URL, req.Method, string(headersJSON), req.Body, req.SourceType,
		req.Depth, req.NormalizedURL, req.CreatedAt, string(fieldsJSON), string(formJSON),
		string(spaJSON), string(shadowJSON), string(paramsJSON), string(cookiesJSON), string(responseJSON),
		req.BodyType, string(jsonFormatJSON),
	)
	if err == nil && req.SourceType == "login_request" {
		_, err = s.db.Exec(`INSERT INTO login_requests
			(request_id, url, method, headers, body, created_at) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(request_id) DO UPDATE SET headers=excluded.headers, body=excluded.body`,
			req.ID, req.URL, req.Method, string(headersJSON), req.Body, req.CreatedAt)
	}
	return err
}

func (s *RequestStore) SaveAuthSession(session *AuthSession) error {
	if session == nil {
		return nil
	}
	storageJSON, err := json.Marshal(session.Storage)
	if err != nil {
		return fmt.Errorf("marshal auth storage: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO auth_sessions
		(id, login_url, final_url, login_method, success_reason, cookie_header, storage, authenticated_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET final_url=excluded.final_url, success_reason=excluded.success_reason,
		cookie_header=excluded.cookie_header, storage=excluded.storage, authenticated_at=excluded.authenticated_at,
		expires_at=excluded.expires_at`,
		session.ID, session.LoginURL, session.FinalURL, session.LoginMethod, session.SuccessReason,
		session.CookieHeader, string(storageJSON), session.AuthenticatedAt, session.ExpiresAt)
	if err != nil {
		return err
	}
	for _, cookie := range session.Cookies {
		_, err = tx.Exec(`INSERT INTO cookies
			(auth_session_id, name, value, domain, path, expires_at, http_only, secure, same_site, is_session)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(auth_session_id, name, domain, path) DO UPDATE SET value=excluded.value,
			expires_at=excluded.expires_at, http_only=excluded.http_only, secure=excluded.secure,
			same_site=excluded.same_site, is_session=excluded.is_session`,
			session.ID, cookie.Name, cookie.Value, cookie.Domain, cookie.Path, nullableTime(cookie.Expires),
			cookie.HttpOnly, cookie.Secure, cookie.SameSite, cookie.Session)
		if err != nil {
			return err
		}
	}
	if session.CSRFField != "" && session.CSRFToken != "" {
		_, err = tx.Exec(`INSERT INTO csrf_tokens
			(auth_session_id, field_name, token_value, source_url, discovered_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(auth_session_id, field_name) DO UPDATE SET token_value=excluded.token_value,
			source_url=excluded.source_url, discovered_at=excluded.discovered_at`,
			session.ID, session.CSRFField, session.CSRFToken, session.LoginURL, session.AuthenticatedAt)
		if err != nil {
			return err
		}
	}
	_, err = tx.Exec(`UPDATE login_requests SET auth_session_id = ?
		WHERE request_id = (SELECT request_id FROM login_requests
		ORDER BY created_at DESC LIMIT 1)`, session.ID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func nullableTime(value time.Time) interface{} {
	if value.IsZero() {
		return nil
	}
	return value
}

// DeleteRequestByURL removes a stale record
func (s *RequestStore) DeleteRequestByURL(url string) error {
	_, err := s.db.Exec(`DELETE FROM discovered_requests WHERE url = ?`, url)
	return err
}

func (s *RequestStore) Count() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM discovered_requests`).Scan(&n)
	return n, err
}
