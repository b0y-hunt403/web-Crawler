package crawler

import (
	"sync"
	"testing"
	"time"
)

func authFixture() *DynamicCrawler {
	c := &DynamicCrawler{authState: authAuthenticating}
	c.beginAuthenticationCandidate("POST", "http://x/login", "", "", "", time.Minute)
	c.markAuthenticationSubmitStarted(c.authAttempt.ID, time.Now(), time.Minute)
	return c
}

func TestExactAuthRequestClaimedOnce(t *testing.T) {
	c := authFixture()
	if !c.claimAuthenticationRequest("POST", "http://x/login") || c.claimAuthenticationRequest("POST", "http://x/login") {
		t.Fatal("claim lifecycle incorrect")
	}
}
func TestDuplicateExactAuthRequestBlocked(t *testing.T) {
	c := authFixture()
	if !c.claimAuthenticationRequest("POST", "http://x/login") {
		t.Fatal("first claim rejected")
	}
	if c.claimAuthenticationRequest("POST", "http://x/login") {
		t.Fatal("duplicate accepted")
	}
}
func TestAuthRequestOutsideAttemptBlocked(t *testing.T) {
	c := &DynamicCrawler{authState: authAuthenticating}
	if c.claimAuthenticationRequest("POST", "http://x/login") {
		t.Fatal("outside attempt allowed")
	}
}
func TestExpiredAuthAttemptBlocked(t *testing.T) {
	c := authFixture()
	c.mu.Lock()
	c.authAttempt.ExpiresAt = time.Now().Add(-time.Second)
	c.mu.Unlock()
	if c.claimAuthenticationRequest("POST", "http://x/login") {
		t.Fatal("expired attempt allowed")
	}
}
func TestWrongAuthMethodBlocked(t *testing.T) {
	c := authFixture()
	if c.claimAuthenticationRequest("GET", "http://x/login") {
		t.Fatal("wrong method allowed")
	}
}
func TestWrongAuthURLBlocked(t *testing.T) {
	c := authFixture()
	if c.claimAuthenticationRequest("POST", "http://x/other") {
		t.Fatal("wrong URL allowed")
	}
}
func TestAuthCandidateClearedAfterSuccess(t *testing.T) {
	c := authFixture()
	c.completeAuthenticationAttempt()
	if c.authAttempt != nil || (c.authAttempt != nil && c.authAttempt.Candidate != nil) {
		t.Fatal("candidate not cleared")
	}
}
func TestAuthCandidateClearedAfterFailure(t *testing.T) {
	c := authFixture()
	c.failAuthenticationAttempt()
	if c.authAttempt != nil || (c.authAttempt != nil && c.authAttempt.Candidate != nil) {
		t.Fatal("candidate not cleared")
	}
}
func TestAuthCandidateClearedAfterTimeout(t *testing.T) {
	c := authFixture()
	c.expireAuthenticationAttempt()
	if c.authAttempt != nil || (c.authAttempt != nil && c.authAttempt.Candidate != nil) {
		t.Fatal("candidate not cleared")
	}
}
func TestNewAuthAttemptResetsClaim(t *testing.T) {
	c := authFixture()
	if !c.claimAuthenticationRequest("POST", "http://x/login") {
		t.Fatal("first claim rejected")
	}
	c.beginAuthenticationCandidate("POST", "http://x/login", "", "", "", time.Minute)
	if !c.claimAuthenticationRequest("POST", "http://x/login") {
		t.Fatal("new attempt did not reset claim")
	}
}
func TestUnrelatedAuthRequestsBlockedDuringLogin(t *testing.T) {
	c := authFixture()
	for _, u := range []string{"http://x/auth/preferences", "http://x/auth/logout"} {
		if c.claimAuthenticationRequest("POST", u) {
			t.Fatal("unrelated auth allowed")
		}
	}
}
func TestRuntimeCandidateReplacesFormActionHint(t *testing.T) {
	c := &DynamicCrawler{authState: authAuthenticating}
	c.beginAuthenticationAttempt("", "", "", time.Minute)
	if !c.bindAuthenticationCandidate("POST", "http://x/auth/login", "", "", "") || c.authAttempt.Candidate.URL != NormalizeURL("http://x/auth/login") {
		t.Fatal("runtime candidate not bound")
	}
}
func TestAuthCandidateBindsExactlyOnce(t *testing.T) {
	c := &DynamicCrawler{authState: authAuthenticating}
	c.beginAuthenticationAttempt("", "", "", time.Minute)
	if !c.bindAuthenticationCandidate("POST", "http://x/auth/login", "", "", "") || c.bindAuthenticationCandidate("POST", "http://x/other", "", "", "") {
		t.Fatal("candidate rebinding allowed")
	}
}
func TestMissingExpectedAuthMetadataBlocked(t *testing.T) {
	c := &DynamicCrawler{authState: authAuthenticating}
	c.beginAuthenticationAttempt("/login", "frame-1", "task-1", time.Minute)
	if c.bindAuthenticationCandidate("POST", "http://x/auth/login", "", "", "") {
		t.Fatal("missing metadata accepted")
	}
}
func TestWrongAuthFrameBlocked(t *testing.T) {
	c := &DynamicCrawler{authState: authAuthenticating}
	c.beginAuthenticationAttempt("", "frame-1", "", time.Minute)
	if c.bindAuthenticationCandidate("POST", "http://x/auth/login", "", "frame-2", "") {
		t.Fatal("wrong frame accepted")
	}
}
func TestWrongAuthTaskBlocked(t *testing.T) {
	c := &DynamicCrawler{authState: authAuthenticating}
	c.beginAuthenticationAttempt("", "", "task-1", time.Minute)
	if c.bindAuthenticationCandidate("POST", "http://x/auth/login", "", "", "task-2") {
		t.Fatal("wrong task accepted")
	}
}
func TestExpiredClaimClearsAttempt(t *testing.T) {
	c := authFixture()
	c.mu.Lock()
	c.authAttempt.ExpiresAt = time.Now().Add(-time.Second)
	c.mu.Unlock()
	if c.claimAuthenticationRequest("POST", "http://x/login") || c.authAttempt != nil || (c.authAttempt != nil && c.authAttempt.Candidate != nil) {
		t.Fatal("expired attempt was not cleared")
	}
}
func TestNewAttemptCannotBeOverwrittenByUnrelatedPOST(t *testing.T) {
	c := &DynamicCrawler{authState: authAuthenticating}
	c.beginAuthenticationAttempt("", "", "", time.Minute)
	if !c.bindAuthenticationCandidate("POST", "http://x/auth/login", "", "", "") {
		t.Fatal("candidate not bound")
	}
	if c.claimAuthenticationRequest("POST", "http://x/other") {
		t.Fatal("unrelated request accepted")
	}
}
func TestConcurrentExactAuthClaimsAllowOnlyOne(t *testing.T) {
	c := authFixture()
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.claimAuthenticationRequest("POST", "http://x/login") {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("wins=%d", wins)
	}
}
func TestAuthCandidateCannotBindBeforeSubmit(t *testing.T) {
	c := &DynamicCrawler{authState: authAuthenticating}
	id := c.beginAuthenticationAttempt("", "", "", time.Minute)
	if c.decideAuthenticationRequest(AuthenticationRequestInput{Method: "POST", URL: "http://x/auth/login", Body: "username=a&password=b", ContentType: "application/x-www-form-urlencoded"}).Allowed || c.authAttempt == nil {
		t.Fatal("bound before submit")
	}
	_ = id
}
func TestAuthCandidateBindsInsideSubmitWindow(t *testing.T) {
	c := &DynamicCrawler{authState: authAuthenticating}
	id := c.beginAuthenticationAttempt("", "", "", time.Minute)
	now := time.Now()
	c.markAuthenticationSubmitStarted(id, now, time.Minute)
	if !c.decideAuthenticationRequest(AuthenticationRequestInput{Method: "POST", URL: "http://x/auth/login", Body: "username=a&password=b", ContentType: "application/x-www-form-urlencoded", ObservedAt: now}).Allowed {
		t.Fatal("bind rejected")
	}
}
func TestAuthCandidateRejectedAfterSubmitWindow(t *testing.T) {
	c := &DynamicCrawler{authState: authAuthenticating}
	id := c.beginAuthenticationAttempt("", "", "", time.Minute)
	now := time.Now()
	c.markAuthenticationSubmitStarted(id, now, time.Millisecond)
	if c.decideAuthenticationRequest(AuthenticationRequestInput{Method: "POST", URL: "http://x/auth/login", Body: "username=a&password=b", ContentType: "application/x-www-form-urlencoded", ObservedAt: now.Add(time.Second)}).Allowed {
		t.Fatal("late bind accepted")
	}
}
