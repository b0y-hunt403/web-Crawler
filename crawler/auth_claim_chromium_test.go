package crawler

import (
	"context"
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

func TestChromiumExactAuthenticationClaimAllowsOnce(t *testing.T) {
	var mu sync.Mutex
	counts := map[string]int{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		counts[r.URL.Path]++
		mu.Unlock()
		if r.URL.Path == "/login" {
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<form action="/login" method="post"><input name="email" autocomplete="username"><input name="password" type="password" autocomplete="current-password"><button>Sign in</button></form><script>document.querySelector('form').onsubmit=e=>{e.preventDefault();fetch('/auth/preferences',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:'fixture@example.test',password:'not-the-login'})}).catch(()=>{});Promise.all([fetch('/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:'fixture@example.test',password:'fixture-password'})}),fetch('/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:'fixture@example.test',password:'fixture-password'})})]).finally(()=>fetch('/auth/logout',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:'fixture@example.test',password:'fixture-password'})}).catch(()=>{}))}</script>`)
			return
		}
		if r.URL.Path == "/auth/login" {
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		if os.Getenv("RAPTOR_REQUIRE_BROWSER_FIXTURES") == "true" {
			t.Fatalf("browser fixture required: %v", err)
		}
		t.Skip(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	db, err := os.CreateTemp(t.TempDir(), "auth-*.db")
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	store, err := NewRequestStore(db.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := DefaultCrawlerConfig()
	cfg.SeedURL = srv.URL + "/login"
	cfg.MaxPages = 1
	cfg.MaxDepth = 0
	cfg.NetworkPolicy = NetworkPolicyConfig{}
	c, err := NewDynamicCrawler(cfg, func(r *DiscoveredRequest, e error) {
		if e != nil {
			t.Error(e)
		}
		if r != nil {
			if e := store.SaveRequest(r); e != nil {
				t.Error(e)
			}
		}
	}, sessionmgr.NewChromiumProvider(sessionmgr.ChromiumOptions{Headless: true}), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.Start(ctx); err != nil {
		if isChromeUnavailable(err) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	c.CrawlURL(ctx, cfg.SeedURL, 0)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := counts["/auth/login"]
		mu.Unlock()
		if n >= 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	mu.Lock()
	got := map[string]int{}
	for k, v := range counts {
		got[k] = v
	}
	mu.Unlock()
	if got["/auth/login"] != 1 || got["/auth/preferences"] != 0 || got["/auth/logout"] != 0 {
		t.Fatalf("counters=%v", got)
	}
}
