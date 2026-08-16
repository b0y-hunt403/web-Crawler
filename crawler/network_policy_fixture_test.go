package crawler

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestNetworkPolicyFixtureBlocksBackgroundMutationsBeforeWire(t *testing.T) {
	t.Setenv("RAPTOR_ALLOW_MUTATIONS", "false")
	t.Setenv("RAPTOR_ALLOW_DESTRUCTIVE_ACTIONS", "false")
	var total atomic.Int64
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("localhost unavailable: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { total.Add(1); w.WriteHeader(http.StatusNoContent) }))
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	methods := []string{"POST", "PUT", "PATCH", "DELETE"}
	for _, method := range methods {
		d := DecideNetworkPolicy(NetworkPolicyConfig{}, NetworkPolicyInput{Method: method, URL: srv.URL + "/background-" + method})
		if d.Action != NetworkPolicyBlock {
			t.Fatalf("%s was not blocked: %+v", method, d)
		}
	}
	if d := DecideNetworkPolicy(NetworkPolicyConfig{}, NetworkPolicyInput{Method: "POST", URL: srv.URL + "/login", IsActiveAuth: true, AuthExactMatch: true}); d.Action != NetworkPolicyAllow {
		t.Fatalf("auth was not allowed: %+v", d)
	}
	resp, err := http.Post(srv.URL+"/login", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := total.Load(); got != 1 {
		t.Fatalf("fixture received %d requests; expected only approved auth request", got)
	}
}
