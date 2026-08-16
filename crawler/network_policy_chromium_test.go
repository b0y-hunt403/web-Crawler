package crawler

import (
	"context"
	"encoding/json"
	sessionmgr "github.com/Anduamlk/web-Crawler/session"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
)

func TestChromiumNetworkPolicyBlocksMutationsBeforeWire(t *testing.T) {
	var mu sync.Mutex
	counts := map[string]int{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		counts[r.URL.Path]++
		mu.Unlock()
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<script>fetch('/read');fetch('/background-post',{method:'POST',body:'{"kind":"post"}',headers:{'Content-Type':'application/json'}});fetch('/background-put',{method:'PUT',body:'{}'});fetch('/background-patch',{method:'PATCH',body:'{}'});fetch('/background-delete',{method:'DELETE'});fetch('/auth/preferences',{method:'POST',body:'{}'});fetch('/graphql-query',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:'query ReadOnly { read }',operationName:'ReadOnly'})});fetch('/graphql-mutation',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:'mutation Change { change }',operationName:'Change'})});</script>`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Skip(e)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	db, e := os.CreateTemp(t.TempDir(), "raptor-policy-*.db")
	if e != nil {
		t.Fatal(e)
	}
	db.Close()
	store, e := NewRequestStore(db.Name())
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	cfg := DefaultCrawlerConfig()
	cfg.SeedURL = srv.URL
	cfg.MaxDepth = 0
	cfg.MaxPages = 1
	cfg.UsePlaywright = true
	cfg.NetworkPolicy = NetworkPolicyConfig{ReadOnlyGraphQLRules: []GraphQLReadOnlyRule{{Endpoint: "/graphql-query", OperationName: "ReadOnly"}}}
	var callbackErr error
	c, e := NewDynamicCrawler(cfg, func(r *DiscoveredRequest, err error) {
		if err != nil {
			callbackErr = err
			return
		}
		if r != nil {
			if err := store.SaveRequest(r); err != nil {
				callbackErr = err
			}
		}
	}, sessionmgr.NewChromiumProvider(sessionmgr.ChromiumOptions{Headless: true}), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if e = c.Start(ctx); e != nil {
		if isChromeUnavailable(e) {
			t.Skip(e)
		}
		t.Fatal(e)
	}
	c.CrawlURL(ctx, srv.URL, 0)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if callbackErr != nil {
			t.Fatal(callbackErr)
		}
		rows, err := dbQueryPolicyEvidence(db.Name())
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		read, q := counts["/read"], counts["/graphql-query"]
		mu.Unlock()
		if read > 0 && q == 1 && len(rows) == 6 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	rows, err := dbQueryPolicyEvidence(db.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 6 {
		mu.Lock()
		snap := map[string]int{}
		for k, v := range counts {
			snap[k] = v
		}
		mu.Unlock()
		t.Fatalf("blocked rows=%d details=%v counters=%v", len(rows), rows, snap)
	}
	mu.Lock()
	snapshot := map[string]int{}
	for k, v := range counts {
		snapshot[k] = v
	}
	mu.Unlock()
	if snapshot["/read"] == 0 || snapshot["/graphql-query"] != 1 || snapshot["/auth/preferences"] != 0 || snapshot["/background-post"] != 0 || snapshot["/background-put"] != 0 || snapshot["/background-patch"] != 0 || snapshot["/background-delete"] != 0 || snapshot["/graphql-mutation"] != 0 {
		t.Fatalf("counters=%v", snapshot)
	}
	if os.Getenv("RAPTOR_WRITE_ACCEPTANCE_ARTIFACTS") == "true" {
		artifactDir := "assessment/enterprise-hardening/sprint-1/final"
		if err := os.MkdirAll(artifactDir, 0o755); err != nil {
			t.Fatal(err)
		}
		b, err := json.MarshalIndent(snapshot, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(artifactDir+"/fixture-server-counters.json", b, 0o644); err != nil {
			t.Fatal(err)
		}
		b, err = json.MarshalIndent(rows, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(artifactDir+"/blocked-request-evidence.json", b, 0o644); err != nil {
			t.Fatal(err)
		}
		n, err := dbScannerExclusion(db.Name(), rows)
		if err != nil {
			t.Fatal(err)
		}
		b, err = json.MarshalIndent(n, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(artifactDir+"/scanner-exclusion-evidence.json", b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func dbQueryPolicyEvidence(path string) ([]map[string]interface{}, error) {
	store, err := NewRequestStore(path)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	rows, err := store.db.Query(`SELECT id,source_type,lifecycle_state,failure_reason,response,page_url,frame_id FROM discovered_requests WHERE source_type='cdp_policy_blocked'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var id, src, life, reason, response, page, frame string
		if err := rows.Scan(&id, &src, &life, &reason, &response, &page, &frame); err != nil {
			return nil, err
		}
		out = append(out, map[string]interface{}{"id": id, "source_type": src, "lifecycle_state": life, "failure_reason": reason, "response": response, "page_url": page, "frame_id": frame})
	}
	return out, rows.Err()
}

func dbScannerExclusion(path string, rows []map[string]interface{}) (map[string]interface{}, error) {
	s, e := NewRequestStore(path)
	if e != nil {
		return nil, e
	}
	defer s.Close()
	var n int
	e = s.db.QueryRow(`SELECT COUNT(*) FROM scanner_candidates sc JOIN discovered_requests dr ON dr.id=sc.request_id WHERE dr.source_type='cdp_policy_blocked' OR dr.lifecycle_state='blocked_by_policy'`).Scan(&n)
	if e != nil {
		return nil, e
	}
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		if id, ok := r["id"].(string); ok {
			ids = append(ids, id)
		}
	}
	return map[string]interface{}{"blocked_request_scanner_candidates": n, "blocked_request_ids": ids}, nil
}
