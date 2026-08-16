package crawler

import (
	"context"
	"errors"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"sync/atomic"
	"testing"
	"time"
)

type failingFetchEnforcer struct {
	failCalls     atomic.Int64
	continueCalls atomic.Int64
	failErr       error
}

func (f *failingFetchEnforcer) Fail(context.Context, fetch.RequestID, network.ErrorReason) error {
	f.failCalls.Add(1)
	return f.failErr
}
func (f *failingFetchEnforcer) Continue(context.Context, fetch.RequestID) error {
	f.continueCalls.Add(1)
	return nil
}

func TestPolicyEnforcementFailureFailsClosed(t *testing.T) {
	f := &failingFetchEnforcer{failErr: errors.New("fixture enforcement failure")}
	store, err := NewRequestStore(t.TempDir() + "/failure.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var got []*DiscoveredRequest
	runStarted := make(chan struct{})
	runHold := make(chan struct{})
	var later atomic.Int64
	c := &DynamicCrawler{browserCtx: context.Background(), fetchEnforcer: f, runStarted: runStarted, runHold: runHold, callback: func(r *DiscoveredRequest, e error) {
		if r != nil {
			got = append(got, r)
			if err := store.SaveRequest(r); err != nil {
				t.Errorf("save evidence: %v", err)
			}
		}
	}, seenFingerprints: map[string]struct{}{}, seenURLs: map[string]struct{}{}}
	runErr := make(chan error, 1)
	go func() { runErr <- c.Crawl(context.Background()) }()
	select {
	case <-runStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("crawl did not start")
	}
	// Queue a later task; cancellation must prevent its execution.
	c.dispatchPausedBlock(PausedRequestBlock{FetchRequestID: "fetch-failure", NetworkRequestID: "network-failure", URL: "http://127.0.0.1/mutate", Method: "POST", Decision: NetworkPolicyDecision{RuleID: "MUTATION_BLOCKED"}})
	var returned error
	select {
	case returned = <-runErr:
	case <-time.After(5 * time.Second):
		t.Fatal("active crawl did not terminate")
	}
	if later.Load() != 0 {
		t.Fatalf("later workflow executions=%d", later.Load())
	}
	if f.failCalls.Load() != 1 || f.continueCalls.Load() != 0 {
		t.Fatalf("calls=%d/%d", f.failCalls.Load(), f.continueCalls.Load())
	}
	if len(got) != 1 || got[0].LifecycleState != "policy_enforcement_failed" {
		t.Fatalf("evidence=%v", got)
	}
	if !errors.Is(returned, ErrNetworkPolicyEnforcement) {
		t.Fatalf("crawl error=%v", returned)
	}
	var failed, blocked, completed, candidates int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM discovered_requests WHERE fetch_request_id='fetch-failure' AND lifecycle_state='policy_enforcement_failed'").Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT COUNT(*) FROM discovered_requests WHERE fetch_request_id='fetch-failure' AND lifecycle_state='blocked_by_policy'").Scan(&blocked); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT COUNT(*) FROM discovered_requests WHERE fetch_request_id='fetch-failure' AND lifecycle_state='completed'").Scan(&completed); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT COUNT(*) FROM scanner_candidates sc JOIN discovered_requests dr ON dr.id=sc.request_id WHERE dr.fetch_request_id='fetch-failure'").Scan(&candidates); err != nil {
		t.Fatal(err)
	}
	if failed != 1 || blocked != 0 || completed != 0 || candidates != 0 {
		t.Fatalf("counts=%d,%d,%d,%d", failed, blocked, completed, candidates)
	}
}

func TestMalformedPostDataEnforcementFailureFailsClosed(t *testing.T) {
	f := &failingFetchEnforcer{failErr: errors.New("decode enforcement failure")}
	store, err := NewRequestStore(t.TempDir() + "/malformed.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runStarted := make(chan struct{})
	runHold := make(chan struct{})
	c := &DynamicCrawler{browserCtx: context.Background(), fetchEnforcer: f, runStarted: runStarted, runHold: runHold, callback: func(r *DiscoveredRequest, e error) {
		if r != nil {
			if err := store.SaveRequest(r); err != nil {
				t.Errorf("save evidence: %v", err)
			}
		}
	}, seenFingerprints: map[string]struct{}{}, seenURLs: map[string]struct{}{}}
	runErr := make(chan error, 1)
	go func() { runErr <- c.Crawl(context.Background()) }()
	select {
	case <-runStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("crawl did not start")
	}
	c.dispatchPausedBlock(PausedRequestBlock{FetchRequestID: "malformed", URL: "http://127.0.0.1/graphql", Method: "POST", ContentType: "application/json", Decision: NetworkPolicyDecision{RuleID: "REQUEST_BODY_DECODE_FAILED"}})
	select {
	case err = <-runErr:
	case <-time.After(5 * time.Second):
		t.Fatal("active crawl did not terminate")
	}
	if !errors.Is(err, ErrNetworkPolicyEnforcement) {
		t.Fatal(err)
	}
	if f.failCalls.Load() != 1 || f.continueCalls.Load() != 0 {
		t.Fatal("wrong calls")
	}
	var failed, blocked, completed, candidates int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM discovered_requests WHERE fetch_request_id='malformed' AND lifecycle_state='policy_enforcement_failed'").Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT COUNT(*) FROM discovered_requests WHERE fetch_request_id='malformed' AND lifecycle_state='blocked_by_policy'").Scan(&blocked); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT COUNT(*) FROM discovered_requests WHERE fetch_request_id='malformed' AND lifecycle_state='completed'").Scan(&completed); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT COUNT(*) FROM scanner_candidates sc JOIN discovered_requests dr ON dr.id=sc.request_id WHERE dr.fetch_request_id='malformed'").Scan(&candidates); err != nil {
		t.Fatal(err)
	}
	if failed != 1 || blocked != 0 || completed != 0 || candidates != 0 {
		t.Fatalf("counts=%d,%d,%d,%d", failed, blocked, completed, candidates)
	}
}

func TestTerminalPolicyCorrelationPreventsLifecycleUpgrade(t *testing.T) {
	f := &failingFetchEnforcer{failErr: errors.New("blocked")}
	store, err := NewRequestStore(t.TempDir() + "/terminal.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	c := &DynamicCrawler{browserCtx: context.Background(), fetchEnforcer: f, callback: func(r *DiscoveredRequest, e error) {
		if r != nil {
			if err := store.SaveRequest(r); err != nil {
				t.Error(err)
			}
		}
	}, seenFingerprints: map[string]struct{}{}, seenURLs: map[string]struct{}{}}
	c.dispatchPausedBlock(PausedRequestBlock{FetchRequestID: "fetch-terminal", NetworkRequestID: "network-terminal", URL: "http://127.0.0.1/x", Method: "POST", Decision: NetworkPolicyDecision{RuleID: "MUTATION_BLOCKED"}})
	c.policyWG.Wait()
	c.updateLifecycle("network-terminal", "completed", "")
	var completed, observed int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM discovered_requests WHERE fetch_request_id='fetch-terminal' AND lifecycle_state='completed'").Scan(&completed); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT COUNT(*) FROM discovered_requests WHERE cdp_request_id='network-terminal' AND source_type='cdp_observed'").Scan(&observed); err != nil {
		t.Fatal(err)
	}
	if completed != 0 || observed != 0 {
		t.Fatalf("completed=%d observed=%d", completed, observed)
	}
}
