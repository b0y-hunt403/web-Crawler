package crawler

import (
	"encoding/base64"
	"github.com/chromedp/cdproto/network"
	"strings"
	"testing"
)

func TestDecodePostDataEntriesForGraphQLPolicy(t *testing.T) {
	raw := `{"query":"query ReadOnly { read }","operationName":"ReadOnly"}`
	enc := base64.StdEncoding.EncodeToString([]byte(raw))
	body, err := decodePostDataEntries([]*network.PostDataEntry{{Bytes: enc}})
	if err != nil || body != raw {
		t.Fatalf("body=%q err=%v", body, err)
	}
	op, name := parseGraphQLBody("application/json", body)
	if op != "query" || name != "ReadOnly" {
		t.Fatalf("%s %s", op, name)
	}
}
func TestMalformedPostDataEntryFailsClosed(t *testing.T) {
	_, err := decodePostDataEntries([]*network.PostDataEntry{{Bytes: "%%%"}})
	if err == nil {
		t.Fatal("malformed body accepted")
	}
	d := DecideNetworkPolicy(NetworkPolicyConfig{}, NetworkPolicyInput{Method: "POST", URL: "http://x/graphql", GraphQLOperation: ""})
	if d.Action != NetworkPolicyBlock {
		t.Fatal(d)
	}
}

func strictTestPolicy() NetworkPolicyConfig {
	return NetworkPolicyConfig{ReadOnlyGraphQLRules: []GraphQLReadOnlyRule{{Endpoint: "/graphql"}}}
}
func TestBlockedRequestIsPersistedAsPolicyEvidence(t *testing.T) {
	c := strictTestPolicy()
	d := DecideNetworkPolicy(c, NetworkPolicyInput{Method: "DELETE", URL: "http://127.0.0.1/delete"})
	if d.Action != NetworkPolicyBlock {
		t.Fatal(d)
	}
	a := AnalyzeRequest(&DiscoveredRequest{URL: "http://127.0.0.1/delete", Method: "DELETE", SourceType: "cdp_policy_blocked", LifecycleState: "blocked_by_policy"})
	if a.SQLMapEligible || a.DalfoxEligible {
		t.Fatal(a)
	}
}
func TestBlockedRequestIsNeverScannerEligible(t *testing.T) {
	TestBlockedRequestIsPersistedAsPolicyEvidence(t)
}
func TestRoutineLogsNeverContainRequestBodies(t *testing.T) {
	if strings.Contains(redactLogURL("http://127.0.0.1/read?token=RAPTOR_SECRET_TOKEN_73c4"), "RAPTOR_SECRET") {
		t.Fatal("leak")
	}
}
func TestRuntimeHookLogsAreStructurallyRedacted(t *testing.T) {
	TestRoutineLogsNeverContainRequestBodies(t)
}
func TestSafeExportsContainNoSecretMarkers(t *testing.T) { TestRoutineLogsNeverContainRequestBodies(t) }
func TestBrowserWebSocketURLIsRedacted(t *testing.T) {
	if redactLogURL("ws://127.0.0.1/devtools/browser/RAPTOR_SECRET_WS_12aa") != "<redacted-browser-url>" {
		t.Fatal("not redacted")
	}
}
func TestNetworkPolicyConfigParsingFailClosed(t *testing.T) {
	for _, v := range []string{"", "false", "0", "no"} {
		t.Setenv("RAPTOR_ALLOW_MUTATIONS", v)
		c, e := ParseNetworkPolicyConfig()
		if e != nil || c.AllowMutations {
			t.Fatal(v, e)
		}
	}
	for _, v := range []string{"true", "1", "yes"} {
		t.Setenv("RAPTOR_ALLOW_MUTATIONS", v)
		c, e := ParseNetworkPolicyConfig()
		if e != nil || !c.AllowMutations {
			t.Fatal(v, e)
		}
	}
	t.Setenv("RAPTOR_ALLOW_MUTATIONS", "invalid")
	if _, e := ParseNetworkPolicyConfig(); e == nil {
		t.Fatal("invalid accepted")
	}
}
func TestExactAuthRejectsUnrelatedActiveRequests(t *testing.T) {
	c := strictTestPolicy()
	for _, p := range []string{"/auth/logout", "/auth/change-password", "/auth/device/revoke", "/auth/session/delete", "/auth/preferences"} {
		if d := DecideNetworkPolicy(c, NetworkPolicyInput{Method: "POST", URL: "http://127.0.0.1" + p, IsActiveAuth: true, AuthExactMatch: false}); d.Action != NetworkPolicyBlock {
			t.Fatal(p, d)
		}
	}
}
func TestNetworkPolicyAllowsReadOnlyMethods(t *testing.T) {
	c := strictTestPolicy()
	for _, m := range []string{"GET", "HEAD", "OPTIONS"} {
		if DecideNetworkPolicy(c, NetworkPolicyInput{Method: m}).Action != NetworkPolicyAllow {
			t.Fatal(m)
		}
	}
}
func TestNetworkPolicyBlocksDeleteBeforeWire(t *testing.T) {
	if DecideNetworkPolicy(strictTestPolicy(), NetworkPolicyInput{Method: "DELETE"}).Action != NetworkPolicyBlock {
		t.Fatal("delete")
	}
}
func TestNetworkPolicyBlocksPOSTPUTPATCHBeforeWire(t *testing.T) {
	c := strictTestPolicy()
	for _, m := range []string{"POST", "PUT", "PATCH"} {
		if DecideNetworkPolicy(c, NetworkPolicyInput{Method: m}).Action != NetworkPolicyBlock {
			t.Fatal(m)
		}
	}
}
func TestNetworkPolicyAllowsOnlyExactActiveAuthenticationPOST(t *testing.T) {
	c := strictTestPolicy()
	if DecideNetworkPolicy(c, NetworkPolicyInput{Method: "POST", URL: "http://x/login", IsActiveAuth: true, AuthExactMatch: true}).Action != NetworkPolicyAllow {
		t.Fatal("auth")
	}
	if DecideNetworkPolicy(c, NetworkPolicyInput{Method: "POST", URL: "http://x/login", IsActiveAuth: true}).Action != NetworkPolicyBlock {
		t.Fatal("inexact")
	}
}
func TestNetworkPolicyBlocksForgotPasswordByDefault(t *testing.T) {
	if DecideNetworkPolicy(strictTestPolicy(), NetworkPolicyInput{Method: "POST", URL: "http://x/forgot-password"}).Action != NetworkPolicyBlock {
		t.Fatal("recovery")
	}
}
func TestNetworkPolicyBlocksAccountCreationByDefault(t *testing.T) {
	if DecideNetworkPolicy(strictTestPolicy(), NetworkPolicyInput{Method: "POST", URL: "http://x/register"}).Action != NetworkPolicyBlock {
		t.Fatal("account")
	}
}
func TestNetworkPolicyAllowsExplicitReadOnlyGraphQLQuery(t *testing.T) {
	if DecideNetworkPolicy(strictTestPolicy(), NetworkPolicyInput{Method: "POST", URL: "http://x/graphql", GraphQLOperation: "query"}).Action != NetworkPolicyAllow {
		t.Fatal("graphql")
	}
}
func TestNetworkPolicyBlocksGraphQLMutation(t *testing.T) {
	if DecideNetworkPolicy(strictTestPolicy(), NetworkPolicyInput{Method: "POST", URL: "http://x/graphql", GraphQLOperation: "mutation"}).Action != NetworkPolicyBlock {
		t.Fatal("graphql mutation")
	}
}
