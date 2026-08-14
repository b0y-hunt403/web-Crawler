package api

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/Anduamlk/web-Crawler/crawler"
	"github.com/Anduamlk/web-Crawler/session"
	"github.com/google/uuid"
	"log"
	_ "modernc.org/sqlite"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Server struct {
	db     *sql.DB
	dbPath string
	key    string
	dev    bool
	jobs   chan struct{}
	mu     sync.RWMutex
}
type FeedRequest struct {
	StartURL       string    `json:"start_url"`
	AllowedOrigins []string  `json:"allowed_origins"`
	Auth           *FeedAuth `json:"auth"`
	Options        struct {
		Depth                   int  `json:"depth"`
		MaxPages                int  `json:"max_pages"`
		TimeoutSeconds          int  `json:"timeout_seconds"`
		Dynamic                 bool `json:"dynamic"`
		AllowDestructiveActions bool `json:"allow_destructive_actions"`
		AllowAccountCreation    bool `json:"allow_account_creation"`
		AllowFileUploads        bool `json:"allow_file_uploads"`
	} `json:"options"`
}

type FeedAuth struct {
	Type     string `json:"type"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	RoleID   string `json:"role_id,omitempty"`
}

func New(dbPath, key string) (*Server, error) {
	base, e := crawler.NewRequestStore(dbPath)
	if e != nil {
		return nil, e
	}
	base.Close()
	db, e := sql.Open("sqlite", dbPath)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	if _, e = db.Exec(`CREATE TABLE IF NOT EXISTS crawl_runs(id TEXT PRIMARY KEY,start_url TEXT NOT NULL,status TEXT NOT NULL,created_at DATETIME NOT NULL,started_at DATETIME,completed_at DATETIME,error_message TEXT,pages_visited INTEGER NOT NULL DEFAULT 0,requests_captured INTEGER NOT NULL DEFAULT 0,options_json TEXT);`); e != nil {
		db.Close()
		return nil, e
	}
	_, _ = db.Exec(`ALTER TABLE discovered_requests ADD COLUMN crawl_id TEXT`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_dr_crawl ON discovered_requests(crawl_id)`)
	s := &Server{db: db, dbPath: dbPath, key: key, dev: os.Getenv("RAPTOR_API_DEV_MODE") == "true", jobs: make(chan struct{}, 1)}
	return s, nil
}
func (s *Server) Close() { s.db.Close() }
func (s *Server) auth(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
		return true
	}
	got := r.Header.Get("X-Raptor-API-Key")
	if s.key == "" && !s.dev {
		writeError(w, "API_DISABLED", "API key is not configured", 503)
		return false
	}
	if s.key != "" && (len(got) != len(s.key) || subtle.ConstantTimeCompare([]byte(got), []byte(s.key)) != 1) {
		writeError(w, "UNAUTHORIZED", "invalid API key", 401)
		return false
	}
	return true
}
func writeError(w http.ResponseWriter, code, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"success": false, "error": map[string]string{"code": code, "message": message}})
}
func write(w http.ResponseWriter, v any, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"success": code < 400, "data": v})
}
func redactBody(raw string) string {
	var v any
	if json.Unmarshal([]byte(raw), &v) != nil {
		return raw
	}
	var walk func(any) any
	walk = func(x any) any {
		switch z := x.(type) {
		case map[string]any:
			for k, v := range z {
				l := strings.ToLower(k)
				if strings.Contains(l, "password") || strings.Contains(l, "token") || strings.Contains(l, "secret") || strings.Contains(l, "authorization") || strings.Contains(l, "cookie") {
					z[k] = "[REDACTED]"
				} else {
					z[k] = walk(v)
				}
			}
			return z
		case []any:
			for i := range z {
				z[i] = walk(z[i])
			}
			return z
		default:
			return x
		}
	}
	b, _ := json.Marshal(walk(v))
	return string(b)
}
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.auth(w, r) {
			return
		}
		if r.URL.Path == "/healthz" {
			write(w, map[string]any{"status": "ok"}, 200)
			return
		}
		if r.URL.Path == "/readyz" {
			if e := s.db.Ping(); e != nil {
				write(w, map[string]string{"error": "database unavailable"}, 503)
			} else {
				write(w, map[string]string{"status": "ready"}, 200)
			}
			return
		}
		if r.Method == "POST" && r.URL.Path == "/api/v1/feed-url" {
			s.feed(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/crawls/") {
			s.crawl(w, r)
			return
		}
		http.NotFound(w, r)
	})
}
func (s *Server) feed(w http.ResponseWriter, r *http.Request) {
	var q FeedRequest
	if json.NewDecoder(r.Body).Decode(&q) != nil {
		write(w, map[string]string{"error": "INVALID_REQUEST"}, 400)
		return
	}
	if q.Auth != nil {
		t := strings.ToLower(strings.TrimSpace(q.Auth.Type))
		switch t {
		case "none":
			if q.Auth.Username != "" || q.Auth.Password != "" || q.Auth.RoleID != "" {
				write(w, map[string]string{"error": "AUTH_MODE_CONFLICT"}, 400)
				return
			}
		case "form":
			if q.Auth.Username == "" || q.Auth.Password == "" || q.Auth.RoleID != "" {
				write(w, map[string]string{"error": "AUTH_MODE_INVALID"}, 400)
				return
			}
		case "session_manager_cdp":
			if q.Auth.RoleID == "" || q.Auth.Username != "" || q.Auth.Password != "" {
				write(w, map[string]string{"error": "AUTH_MODE_INVALID"}, 400)
				return
			}
		default:
			write(w, map[string]string{"error": "AUTH_MODE_INVALID"}, 400)
			return
		}
	}
	u, e := url.Parse(q.StartURL)
	if e != nil || u.Scheme != "http" && u.Scheme != "https" || u.User != nil {
		write(w, map[string]string{"error": "INVALID_URL"}, 400)
		return
	}
	startOrigin := u.Scheme + "://" + u.Host
	if len(q.AllowedOrigins) == 0 {
		q.AllowedOrigins = []string{startOrigin}
	}
	seen := map[string]bool{}
	for _, raw := range q.AllowedOrigins {
		ou, er := url.Parse(raw)
		if er != nil || ou.Scheme != "http" && ou.Scheme != "https" || ou.Host == "" || ou.User != nil || ou.Path != "" || ou.RawQuery != "" || ou.Fragment != "" {
			write(w, map[string]string{"code": "INVALID_ORIGIN", "message": "allowed_origins contains an invalid origin"}, 400)
			return
		}
		o := ou.Scheme + "://" + ou.Host
		if seen[o] {
			write(w, map[string]string{"code": "INVALID_ORIGIN", "message": "duplicate allowed origin"}, 400)
			return
		}
		seen[o] = true
	}
	if !seen[startOrigin] {
		write(w, map[string]string{"code": "INVALID_ORIGIN", "message": "start_url origin is not allowed"}, 400)
		return
	}
	id := "crawl_" + uuid.NewString()
	now := time.Now().UTC()
	_, e = s.db.Exec(`INSERT INTO crawl_runs(id,start_url,status,created_at,options_json) VALUES(?,?,?,?,?)`, id, q.StartURL, "queued", now, `{"dynamic":true}`)
	if e != nil {
		write(w, map[string]string{"error": "DATABASE_ERROR"}, 500)
		return
	}
	go s.run(id, q)
	write(w, map[string]string{"crawl_id": id, "status": "queued", "start_url": q.StartURL}, 202)
}
func (s *Server) run(id string, q FeedRequest) {
	s.jobs <- struct{}{}
	defer func() { <-s.jobs }()
	s.db.Exec(`UPDATE crawl_runs SET status='running',started_at=? WHERE id=?`, time.Now().UTC(), id)
	ctx := context.Background()
	cfg := crawler.DefaultCrawlerConfig()
	cfg.SeedURL = q.StartURL
	if q.Options.Depth > 0 {
		cfg.MaxDepth = q.Options.Depth
	}
	if q.Options.MaxPages > 0 {
		cfg.MaxPages = q.Options.MaxPages
	}
	cfg.AllowedOrigins = append([]string(nil), q.AllowedOrigins...)
	cfg.DynamicCrawl = q.Options.Dynamic
	cfg.DBPath = ""
	cfg.BrowserSource = "local"
	if q.Auth != nil {
		cfg.Auth = &crawler.AuthConfig{Type: q.Auth.Type, Username: q.Auth.Username, Password: q.Auth.Password, RoleID: q.Auth.RoleID}
		if strings.EqualFold(q.Auth.Type, "session_manager_cdp") {
			cfg.BrowserSource = "session_manager_cdp"
			cfg.SessionManagerURL = os.Getenv("PLAYSCAN_SESSION_MANAGER_URL")
			cfg.SessionManagerRoleID = q.Auth.RoleID
		}
	}
	var prov session.BrowserContextProvider = session.NewChromiumProvider(session.ChromiumOptions{Headless: true})
	var release func()
	if q.Auth != nil && strings.EqualFold(q.Auth.Type, "session_manager_cdp") {
		client, ce := session.NewSessionManagerHTTPClient(os.Getenv("PLAYSCAN_SESSION_MANAGER_URL"), os.Getenv("PLAYSCAN_SESSION_MANAGER_TOKEN"), session.AllowedWebSocketHosts(os.Getenv("PLAYSCAN_SESSION_MANAGER_WS_HOSTS")))
		if ce != nil {
			s.db.Exec(`UPDATE crawl_runs SET status='failed',completed_at=?,error_message=? WHERE id=?`, time.Now().UTC(), ce.Error(), id)
			return
		}
		acq, cancel := context.WithTimeout(ctx, 15*time.Second)
		lease, ce := client.AcquireContext(acq, q.StartURL, q.Auth.RoleID)
		cancel()
		if ce != nil {
			s.db.Exec(`UPDATE crawl_runs SET status='failed',completed_at=?,error_message=? WHERE id=?`, time.Now().UTC(), ce.Error(), id)
			return
		}
		log.Printf("SESSION_MANAGER_CONTEXT_ACQUIRED context_id_hash=%s session_id_hash=%s", session.RedactedSessionIdentifier(lease.ContextID), session.RedactedSessionIdentifier(lease.SessionID))
		release = func() {
			cc, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = client.ReleaseContext(cc, lease.ContextID)
			log.Printf("SESSION_MANAGER_CONTEXT_RELEASED context_id_hash=%s", session.RedactedSessionIdentifier(lease.ContextID))
		}
		remote, ce := session.NewRemoteCDPProvider(lease)
		if ce != nil {
			s.db.Exec(`UPDATE crawl_runs SET status='failed',completed_at=?,error_message=? WHERE id=?`, time.Now().UTC(), ce.Error(), id)
			return
		}
		prov = remote
		defer func() {
			if release != nil {
				release()
			}
		}()
	}
	store, se := crawler.NewRequestStore(s.dbPath)
	if se != nil {
		s.db.Exec(`UPDATE crawl_runs SET status='failed',completed_at=?,error_message=? WHERE id=?`, time.Now().UTC(), "request store unavailable", id)
		return
	}
	defer store.Close()
	c, e := crawler.NewDynamicCrawler(cfg, func(req *crawler.DiscoveredRequest, err error) {
		if err == nil {
			req.CrawlID = id
			_ = store.SaveRequest(req)
		}
	}, prov, nil)
	if e == nil {
		e = c.Start(ctx)
		if e == nil {
			e = c.Crawl(ctx)
		}
		c.Close()
	}
	status := "completed"
	if e != nil {
		status = "failed"
	}
	s.db.Exec(`UPDATE crawl_runs SET status=?,completed_at=?,error_message=? WHERE id=?`, status, time.Now().UTC(), fmt.Sprint(e), id)
}
func (s *Server) crawl(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 {
		http.NotFound(w, r)
		return
	}
	id := parts[3]
	if r.Method == "GET" && len(parts) == 4 {
		var status, start string
		var created time.Time
		e := s.db.QueryRow(`SELECT status,start_url,created_at FROM crawl_runs WHERE id=?`, id).Scan(&status, &start, &created)
		if e != nil {
			http.NotFound(w, r)
			return
		}
		write(w, map[string]any{"crawl_id": id, "status": status, "start_url": start, "created_at": created}, 200)
		return
	}
	if r.Method == "GET" && len(parts) == 5 && (parts[4] == "requests" || parts[4] == "getall" || parts[4] == "getonly" || parts[4] == "postonly" || parts[4] == "putonly" || parts[4] == "patchonly" || parts[4] == "deleteonly") {
		method := strings.ToUpper(r.URL.Query().Get("method"))
		if parts[4] != "requests" {
			method = map[string]string{"getonly": "GET", "postonly": "POST", "putonly": "PUT", "patchonly": "PATCH", "deleteonly": "DELETE"}[parts[4]]
		}
		q := `SELECT id,method,url,body_type,response,page_url,created_at FROM discovered_requests WHERE `
		args := []any{id}
		q += "crawl_id=?"
		if method != "" {
			q += " AND UPPER(method)=?"
			args = append(args, method)
		}
		q += " ORDER BY created_at,id"
		rows, e := s.db.Query(q, args...)
		if e != nil {
			write(w, map[string]string{"error": "QUERY_ERROR"}, 500)
			return
		}
		defer rows.Close()
		items := []any{}
		for rows.Next() {
			var id, m, u, bt, resp, page string
			var at time.Time
			rows.Scan(&id, &m, &u, &bt, &resp, &page, &at)
			items = append(items, map[string]any{"id": id, "method": m, "url": u, "body_type": bt, "response": resp, "page_url": page, "captured_at": at})
		}
		write(w, map[string]any{"crawl_id": id, "items": items}, 200)
		return
	}
	if r.Method == "GET" && len(parts) == 6 && parts[4] == "requests" {
		var m, u string
		var body sql.NullString
		e := s.db.QueryRow(`SELECT method,url,body FROM discovered_requests WHERE crawl_id=? AND id=?`, id, parts[5]).Scan(&m, &u, &body)
		if e != nil {
			http.NotFound(w, r)
			return
		}
		write(w, map[string]any{"id": parts[5], "method": m, "url": u, "body": redactBody(body.String)}, 200)
		return
	}
	http.NotFound(w, r)
}
