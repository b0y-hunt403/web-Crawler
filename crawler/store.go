// crawler/store.go
package crawler

import (
	"database/sql"
	"encoding/json"
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

	schema := `
CREATE TABLE IF NOT EXISTS discovered_requests (
	id TEXT PRIMARY KEY,
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
`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}

	for _, col := range []string{"parameters", "cookies", "response", "body_type", "json_format"} {
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
	(id, url, method, headers, body, source_type, depth, normalized_url, created_at,
	 form_fields, form, spa_route, shadow_dom_elements, parameters, cookies, response, body_type, json_format)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	url=excluded.url, method=excluded.method, headers=excluded.headers, body=excluded.body,
	source_type=excluded.source_type, depth=MIN(discovered_requests.depth, excluded.depth),
	normalized_url=excluded.normalized_url, form_fields=excluded.form_fields, form=excluded.form,
	spa_route=excluded.spa_route, shadow_dom_elements=excluded.shadow_dom_elements,
	parameters=excluded.parameters, cookies=excluded.cookies, response=excluded.response,
	body_type=excluded.body_type, json_format=excluded.json_format
`,
		req.ID, req.URL, req.Method, string(headersJSON), req.Body, req.SourceType,
		req.Depth, req.NormalizedURL, req.CreatedAt, string(fieldsJSON), string(formJSON),
		string(spaJSON), string(shadowJSON), string(paramsJSON), string(cookiesJSON), string(responseJSON),
		req.BodyType, string(jsonFormatJSON),
	)
	return err
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