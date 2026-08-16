package crawler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/chromedp/cdproto/network"
	"net/url"
	"os"
	"strings"
)

func decodePostDataEntries(entries []*network.PostDataEntry) (string, error) {
	var out []byte
	for _, entry := range entries {
		if entry == nil || entry.Bytes == "" {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(entry.Bytes)
		if err != nil {
			return "", err
		}
		out = append(out, b...)
	}
	return string(out), nil
}

type NetworkPolicyAction string

const (
	NetworkPolicyAllow NetworkPolicyAction = "ALLOW"
	NetworkPolicyBlock NetworkPolicyAction = "BLOCK"
)

type GraphQLReadOnlyRule struct{ Endpoint, OperationName string }
type NetworkPolicyConfig struct {
	AllowMutations, AllowDestructiveActions, AllowAccountCreation bool
	AllowRecovery, AllowLogout, AllowFileUploads                  bool
	ReadOnlyGraphQLRules                                          []GraphQLReadOnlyRule
}
type NetworkPolicyDecision struct {
	Action         NetworkPolicyAction
	RuleID, Reason string
}
type NetworkPolicyInput struct {
	Method, URL, ContentType, Body, GraphQLOperation, GraphQLOperationName string
	IsActiveAuth, AuthExactMatch, AuthClaimed                              bool
}

func isMutationMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

func ParseNetworkPolicyConfig() (NetworkPolicyConfig, error) {
	get := func(name string) (bool, error) {
		v, ok := os.LookupEnv(name)
		if !ok || strings.TrimSpace(v) == "" {
			return false, nil
		}
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "yes":
			return true, nil
		case "false", "0", "no":
			return false, nil
		default:
			return false, fmt.Errorf("invalid %s", name)
		}
	}
	var c NetworkPolicyConfig
	var err error
	if c.AllowMutations, err = get("RAPTOR_ALLOW_MUTATIONS"); err != nil {
		return c, err
	}
	if c.AllowDestructiveActions, err = get("RAPTOR_ALLOW_DESTRUCTIVE_ACTIONS"); err != nil {
		return c, err
	}
	if c.AllowAccountCreation, err = get("RAPTOR_ALLOW_ACCOUNT_CREATION"); err != nil {
		return c, err
	}
	if c.AllowRecovery, err = get("RAPTOR_ALLOW_RECOVERY"); err != nil {
		return c, err
	}
	if c.AllowLogout, err = get("RAPTOR_ALLOW_LOGOUT"); err != nil {
		return c, err
	}
	if c.AllowFileUploads, err = get("RAPTOR_ALLOW_FILE_UPLOADS"); err != nil {
		return c, err
	}
	return c, nil
}

func DecideNetworkPolicy(c NetworkPolicyConfig, in NetworkPolicyInput) NetworkPolicyDecision {
	m := strings.ToUpper(in.Method)
	p := pathOf(in.URL)
	if m == "GET" || m == "HEAD" || m == "OPTIONS" {
		return NetworkPolicyDecision{NetworkPolicyAllow, "READ_ONLY", "read-only method"}
	}
	if isLogoutPath(p) && !c.AllowLogout {
		return NetworkPolicyDecision{NetworkPolicyBlock, "LOGOUT_BLOCKED", "logout disabled"}
	}
	if isRecoveryPath(p) && !c.AllowRecovery {
		return NetworkPolicyDecision{NetworkPolicyBlock, "RECOVERY_BLOCKED", "recovery disabled"}
	}
	if isAccountPath(p) && !c.AllowAccountCreation {
		return NetworkPolicyDecision{NetworkPolicyBlock, "ACCOUNT_CREATION_BLOCKED", "account creation disabled"}
	}
	if strings.Contains(strings.ToLower(in.ContentType), "multipart") && !c.AllowFileUploads {
		return NetworkPolicyDecision{NetworkPolicyBlock, "FILE_UPLOAD_BLOCKED", "file uploads disabled"}
	}
	if m == "DELETE" && !c.AllowDestructiveActions {
		return NetworkPolicyDecision{NetworkPolicyBlock, "DELETE_BLOCKED", "destructive actions disabled"}
	}
	if m == "POST" && strings.EqualFold(in.GraphQLOperation, "query") && graphqlRule(c, in) {
		return NetworkPolicyDecision{NetworkPolicyAllow, "GRAPHQL_QUERY", "explicit read-only GraphQL rule"}
	}
	if m == "POST" && in.IsActiveAuth && in.AuthExactMatch && !in.AuthClaimed {
		return NetworkPolicyDecision{NetworkPolicyAllow, "AUTH_EXACT", "exact active authentication request"}
	}
	if !c.AllowMutations && (m == "POST" || m == "PUT" || m == "PATCH" || m == "DELETE") {
		return NetworkPolicyDecision{NetworkPolicyBlock, "MUTATION_BLOCKED", "mutations disabled"}
	}
	if m != "POST" && m != "PUT" && m != "PATCH" && m != "DELETE" {
		return NetworkPolicyDecision{NetworkPolicyBlock, "UNKNOWN_METHOD", "unknown non-read-only method"}
	}
	return NetworkPolicyDecision{NetworkPolicyAllow, "MUTATIONS_ENABLED", "mutations explicitly enabled"}
}
func pathOf(raw string) string { u, _ := url.Parse(raw); return strings.ToLower(u.Path) }
func isRecoveryPath(p string) bool {
	return strings.Contains(p, "forgot") || strings.Contains(p, "reset") || strings.Contains(p, "password/change")
}
func isAccountPath(p string) bool {
	return strings.Contains(p, "register") || strings.Contains(p, "signup") || strings.Contains(p, "account/create")
}
func isLogoutPath(p string) bool {
	return strings.Contains(p, "logout") || strings.Contains(p, "session/delete") || strings.Contains(p, "device/revoke")
}
func graphqlRule(c NetworkPolicyConfig, in NetworkPolicyInput) bool {
	u, _ := url.Parse(in.URL)
	for _, r := range c.ReadOnlyGraphQLRules {
		if (r.Endpoint == "" || r.Endpoint == u.Path) && (r.OperationName == "" || r.OperationName == in.GraphQLOperationName) {
			return true
		}
	}
	return false
}
func parseGraphQLBody(contentType, body string) (string, string) {
	if !strings.Contains(strings.ToLower(contentType), "json") {
		return "", ""
	}
	var v struct {
		Query         string                 `json:"query"`
		OperationName string                 `json:"operationName"`
		Variables     map[string]interface{} `json:"variables"`
	}
	if json.Unmarshal([]byte(body), &v) != nil {
		return "", ""
	}
	q := strings.ToLower(strings.TrimSpace(v.Query))
	for _, op := range []string{"query", "mutation", "subscription"} {
		if strings.HasPrefix(q, op) {
			return op, v.OperationName
		}
	}
	return "", ""
}
