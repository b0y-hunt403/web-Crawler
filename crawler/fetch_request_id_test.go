package crawler

import (
	"os"
	"testing"
)

func TestFetchRequestIDPersistsSeparatelyFromCDPRequestID(t *testing.T) {
	p := t.TempDir() + "/x.db"
	s, e := NewRequestStore(p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	r := &DiscoveredRequest{ID: "rid", URL: "http://x", Method: "POST", CDPRequestID: "network-fixture-2", FetchRequestID: "fetch-fixture-1", SourceType: "cdp_policy_blocked", LifecycleState: "blocked_by_policy"}
	if e = s.SaveRequest(r); e != nil {
		t.Fatal(e)
	}
	var f, c string
	if e = s.db.QueryRow("SELECT fetch_request_id,cdp_request_id FROM discovered_requests WHERE id=?", "rid").Scan(&f, &c); e != nil {
		t.Fatal(e)
	}
	if f != "fetch-fixture-1" || c != "network-fixture-2" {
		t.Fatalf("%q %q", f, c)
	}
	_ = os.Remove(p)
}
