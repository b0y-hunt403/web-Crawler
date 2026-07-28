// crawler/jsparser.go
package crawler

import (
	"net/url"
	"regexp"
	"strings"
)

// =============================================================================
// CONSTANTS & PATTERNS
// =============================================================================

// endpointPatterns finds relative-path endpoints, mirroring js_parser.py's
// original regex set.
var endpointPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)["'](/api/[a-zA-Z0-9/_-]+)["']`),
	regexp.MustCompile(`(?i)["'](/v[0-9]+/[a-zA-Z0-9/_-]+)["']`),
	regexp.MustCompile(`(?i)["'](/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)["']`),
	regexp.MustCompile(`(?i)["'](/[a-zA-Z0-9_-]+)["']`),
	regexp.MustCompile(`(?i)path:\s*["'](/[a-zA-Z0-9/_-]+)["']`),
	regexp.MustCompile(`(?i)to:\s*["'](/[a-zA-Z0-9/_-]+)["']`),
	regexp.MustCompile(`(?i)page:\s*["'](/[a-zA-Z0-9/_-]+)["']`),
	regexp.MustCompile(`(?i)route["']?\s*:\s*["'](/[a-zA-Z0-9/_-]+)["']`),
	regexp.MustCompile(`(?i)path["']?\s*:\s*["'](/[a-zA-Z0-9/_-]+)["']`),
}

// networkCallPatterns catch relative *or* absolute URLs passed to actual
// network-issuing calls — fetch/axios/XHR/dynamic import/new URL — which is
// where most real API endpoints live, as opposed to plain string literals.
var networkCallPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)fetch\(\s*["']([^"'()]+)["']`),
	regexp.MustCompile(`(?i)axios\.(?:get|post|put|delete|patch)\(\s*["']([^"'()]+)["']`),
	regexp.MustCompile(`(?i)axios\(\s*\{[^}]*url\s*:\s*["']([^"'()]+)["']`),
	regexp.MustCompile(`(?i)\.(?:get|post|put|delete|patch)\(\s*["']([^"'()]+)["']`),
	regexp.MustCompile(`(?i)\.open\(\s*["'](?:GET|POST|PUT|DELETE|PATCH|HEAD)["']\s*,\s*["']([^"'()]+)["']`),
	regexp.MustCompile(`(?i)new\s+URL\(\s*["']([^"'()]+)["']`),
	regexp.MustCompile(`(?i)import\(\s*["']([^"'()]+)["']\s*\)`),
}

// hardcodedURLPattern catches any fully-qualified URL sitting in a string
// literal, regardless of what function (if any) it's passed to.
var hardcodedURLPattern = regexp.MustCompile(`(?i)["'](https?://[a-zA-Z0-9.\-]+(?::[0-9]+)?(?:/[a-zA-Z0-9/_\-.%]*)?(?:\?[^"'\s]*)?)["']`)

// graphqlHintPattern flags likely GraphQL endpoints/operations.
var graphqlHintPattern = regexp.MustCompile(`(?i)["']([^"']*graphql[^"']*)["']`)

// reactRoutePatterns for React router configs.
var reactRoutePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)path\s*:\s*["'](/[a-zA-Z0-9/_-]+)["']`),
	regexp.MustCompile(`(?i)to\s*:\s*["'](/[a-zA-Z0-9/_-]+)["']`),
	regexp.MustCompile(`(?i)route\s*:\s*["'](/[a-zA-Z0-9/_-]+)["']`),
}

// Vue patterns for Vue router configs.
var vuePathPattern = regexp.MustCompile(`(?i)path\s*:\s*["'](/[a-zA-Z0-9/_-]+)["']`)
var vueImportPattern = regexp.MustCompile(`(?i)component\s*:\s*\(\)\s*=>\s*import\(["']([^"'()]+)["']\)`)

// requestPatterns for all JS request types (comprehensive mining).
var requestPatterns = []struct {
	Pattern *regexp.Regexp
	Type    RequestType
}{
	{regexp.MustCompile(`fetch\s*\(\s*['"]([^'"]+)['"]`), RequestTypeFetch},
	{regexp.MustCompile(`axios\.(?:get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]`), RequestTypeAxios},
	{regexp.MustCompile(`axios\s*\(\s*\{[^}]*url\s*:\s*['"]([^'"]+)['"]`), RequestTypeAxios},
	{regexp.MustCompile(`\.(?:get|post|put|delete|patch|request)\s*\(\s*['"]([^'"]+)['"]`), RequestTypeXHR},
	{regexp.MustCompile(`\.open\s*\(\s*['"](?:GET|POST|PUT|DELETE|PATCH)['"]\s*,\s*['"]([^'"]+)['"]`), RequestTypeXHR},
	{regexp.MustCompile(`new\s+WebSocket\s*\(\s*['"]([^'"]+)['"]`), RequestTypeWebSocket},
	{regexp.MustCompile(`new\s+EventSource\s*\(\s*['"]([^'"]+)['"]`), RequestTypeSSE},
	{regexp.MustCompile(`navigator\.sendBeacon\s*\(\s*['"]([^'"]+)['"]`), RequestTypeBeacon},
	{regexp.MustCompile(`new\s+URL\s*\(\s*['"]([^'"]+)['"]`), RequestTypeXHR},
	{regexp.MustCompile(`import\s*\(\s*['"]([^'"]+)['"]\s*\)`), RequestTypeFetch},
}

// graphQLPatterns for GraphQL detection.
var graphQLPatterns = []*regexp.Regexp{
	regexp.MustCompile(`query\s*\{[^}]*\}`),
	regexp.MustCompile(`mutation\s*\{[^}]*\}`),
	regexp.MustCompile(`subscription\s*\{[^}]*\}`),
	regexp.MustCompile(`gql\s*` + "`[^`]*`"),
	regexp.MustCompile(`graphql\s*` + "`[^`]*`"),
}

// axiosPatterns for Axios detection.
var axiosPatterns = []*regexp.Regexp{
	regexp.MustCompile(`axios\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]`),
	regexp.MustCompile(`axios\s*\(\s*\{[^}]*url\s*:\s*['"]([^'"]+)['"]`),
}

// fetchPattern for fetch() detection.
var fetchPattern = regexp.MustCompile(`fetch\s*\(\s*['"]([^'"]+)['"]\s*,\s*\{([^}]*)\}\s*\)`)

// =============================================================================
// MAIN EXPORT FUNCTIONS
// =============================================================================

// ExtractEndpointsFromJS extracts potential API endpoints, SPA routes, and
// hardcoded URLs from JavaScript source. Returns the raw endpoint string
// (relative or absolute) mapped to whether it looked GraphQL-flavored.
func ExtractEndpointsFromJS(jsContent string) map[string]bool {
	found := map[string]bool{} // endpoint -> isGraphQL

	collect := func(patterns []*regexp.Regexp) {
		for _, pattern := range patterns {
			for _, m := range pattern.FindAllStringSubmatch(jsContent, -1) {
				candidate := m[len(m)-1]
				isAbs := strings.HasPrefix(candidate, "http://") || strings.HasPrefix(candidate, "https://")
				if len(candidate) > 1 && (strings.HasPrefix(candidate, "/") || isAbs) {
					if _, exists := found[candidate]; !exists {
						found[candidate] = false
					}
				}
			}
		}
	}

	collect(endpointPatterns)
	collect(networkCallPatterns)

	for _, m := range hardcodedURLPattern.FindAllStringSubmatch(jsContent, -1) {
		if _, exists := found[m[1]]; !exists {
			found[m[1]] = false
		}
	}
	for _, m := range graphqlHintPattern.FindAllStringSubmatch(jsContent, -1) {
		found[m[1]] = true
	}

	cleaned := map[string]bool{}
	for ep, isGQL := range found {
		epClean := strings.SplitN(ep, "?", 2)[0]
		if strings.HasPrefix(epClean, "/") && len(epClean) > 1 && strings.HasSuffix(epClean, "/") {
			epClean = strings.TrimSuffix(epClean, "/")
		}
		if len(epClean) > 1 {
			cleaned[epClean] = cleaned[epClean] || isGQL
		}
	}
	return cleaned
}

// ExtractSPARoutesFromJS extracts SPA routes from React/Vue router configs.
func ExtractSPARoutesFromJS(jsContent string) []string {
	routeSet := map[string]struct{}{}

	for _, pattern := range reactRoutePatterns {
		for _, m := range pattern.FindAllStringSubmatch(jsContent, -1) {
			if route := m[1]; len(route) > 1 && strings.HasPrefix(route, "/") {
				routeSet[route] = struct{}{}
			}
		}
	}

	for _, m := range vuePathPattern.FindAllStringSubmatch(jsContent, -1) {
		routeSet[m[1]] = struct{}{}
	}
	for _, m := range vueImportPattern.FindAllStringSubmatch(jsContent, -1) {
		match := m[1]
		if strings.HasPrefix(match, "/") {
			routeSet[match] = struct{}{}
			continue
		}
		if strings.Contains(match, "/pages/") {
			parts := strings.SplitN(match, "/pages/", 2)
			route := strings.TrimSuffix(parts[len(parts)-1], ".js")
			if route == "index" {
				route = "/"
			} else {
				route = "/" + route
			}
			routeSet[route] = struct{}{}
		}
	}

	routes := make([]string, 0, len(routeSet))
	for r := range routeSet {
		routes = append(routes, r)
	}
	return routes
}

// ExtractAllRequestsFromJS extracts all request types from JS:
// fetch, axios, XHR, GraphQL, WebSocket, SSE, Beacon
func ExtractAllRequestsFromJS(jsContent string) []RequestSource {
	var requests []RequestSource
	seen := make(map[string]bool)

	// Fetch() detection
	for _, match := range fetchPattern.FindAllStringSubmatch(jsContent, -1) {
		key := match[0]
		if seen[key] {
			continue
		}
		seen[key] = true
		requests = append(requests, RequestSource{
			Type:       RequestTypeFetch,
			JavaScript: match[0],
		})
	}

	// Axios detection
	for _, pattern := range axiosPatterns {
		for _, match := range pattern.FindAllStringSubmatch(jsContent, -1) {
			key := match[0]
			if seen[key] {
				continue
			}
			seen[key] = true
			requests = append(requests, RequestSource{
				Type:       RequestTypeAxios,
				JavaScript: match[0],
			})
		}
	}

	// GraphQL detection
	for _, pattern := range graphQLPatterns {
		for _, match := range pattern.FindAllStringSubmatch(jsContent, -1) {
			key := match[0]
			if seen[key] {
				continue
			}
			seen[key] = true
			requests = append(requests, RequestSource{
				Type:       RequestTypeGraphQL,
				JavaScript: match[0],
			})
		}
	}

	// WebSocket detection
	wsPattern := regexp.MustCompile(`new\s+WebSocket\s*\(\s*['"]([^'"]+)['"]`)
	for _, match := range wsPattern.FindAllStringSubmatch(jsContent, -1) {
		key := match[0]
		if seen[key] {
			continue
		}
		seen[key] = true
		requests = append(requests, RequestSource{
			Type:       RequestTypeWebSocket,
			JavaScript: match[0],
		})
	}

	// Server-Sent Events detection
	ssePattern := regexp.MustCompile(`new\s+EventSource\s*\(\s*['"]([^'"]+)['"]`)
	for _, match := range ssePattern.FindAllStringSubmatch(jsContent, -1) {
		key := match[0]
		if seen[key] {
			continue
		}
		seen[key] = true
		requests = append(requests, RequestSource{
			Type:       RequestTypeSSE,
			JavaScript: match[0],
		})
	}

	// Beacon API detection
	beaconPattern := regexp.MustCompile(`navigator\.sendBeacon\s*\(\s*['"]([^'"]+)['"]`)
	for _, match := range beaconPattern.FindAllStringSubmatch(jsContent, -1) {
		key := match[0]
		if seen[key] {
			continue
		}
		seen[key] = true
		requests = append(requests, RequestSource{
			Type:       RequestTypeBeacon,
			JavaScript: match[0],
		})
	}

	return requests
}

// ExtractGraphQLOperations extracts GraphQL queries, mutations, and subscriptions.
func ExtractGraphQLOperations(jsContent string) []GraphQLOperation {
	var operations []GraphQLOperation
	seen := make(map[string]bool)

	// GraphQL operation patterns
	queryPattern := regexp.MustCompile(`query\s+(\w+)?\s*(?:\([^)]*\))?\s*\{[^}]*\}`)
	mutationPattern := regexp.MustCompile(`mutation\s+(\w+)?\s*(?:\([^)]*\))?\s*\{[^}]*\}`)
	subscriptionPattern := regexp.MustCompile(`subscription\s+(\w+)?\s*(?:\([^)]*\))?\s*\{[^}]*\}`)

	// gql tagged template literals
	gqlPattern := regexp.MustCompile("gql\\s*`([^`]*)`")

	for _, match := range queryPattern.FindAllStringSubmatch(jsContent, -1) {
		key := match[0]
		if seen[key] {
			continue
		}
		seen[key] = true
		operations = append(operations, GraphQLOperation{
			Type:      "query",
			Operation: match[0],
		})
	}

	for _, match := range mutationPattern.FindAllStringSubmatch(jsContent, -1) {
		key := match[0]
		if seen[key] {
			continue
		}
		seen[key] = true
		operations = append(operations, GraphQLOperation{
			Type:      "mutation",
			Operation: match[0],
		})
	}

	for _, match := range subscriptionPattern.FindAllStringSubmatch(jsContent, -1) {
		key := match[0]
		if seen[key] {
			continue
		}
		seen[key] = true
		operations = append(operations, GraphQLOperation{
			Type:      "subscription",
			Operation: match[0],
		})
	}

	for _, match := range gqlPattern.FindAllStringSubmatch(jsContent, -1) {
		key := match[1]
		if seen[key] {
			continue
		}
		seen[key] = true
		// Check if it contains query, mutation, or subscription
		if strings.Contains(match[1], "query") {
			operations = append(operations, GraphQLOperation{
				Type:      "query",
				Operation: match[1],
			})
		}
		if strings.Contains(match[1], "mutation") {
			operations = append(operations, GraphQLOperation{
				Type:      "mutation",
				Operation: match[1],
			})
		}
		if strings.Contains(match[1], "subscription") {
			operations = append(operations, GraphQLOperation{
				Type:      "subscription",
				Operation: match[1],
			})
		}
	}

	return operations
}

// ExtractAllEndpointsFromJS extracts all endpoints from JS using all patterns.
// This is the most comprehensive endpoint miner.
func ExtractAllEndpointsFromJS(jsContent string) []JSEndpoint {
	var endpoints []JSEndpoint
	seen := make(map[string]bool)

	for _, pattern := range requestPatterns {
		for _, match := range pattern.Pattern.FindAllStringSubmatch(jsContent, -1) {
			if len(match) < 2 {
				continue
			}

			url := match[1]
			// Skip data URLs, blob URLs, etc.
			if strings.HasPrefix(url, "data:") ||
				strings.HasPrefix(url, "blob:") ||
				strings.HasPrefix(url, "javascript:") ||
				strings.HasPrefix(url, "ws://") ||
				strings.HasPrefix(url, "wss://") {
				continue
			}

			key := url + string(pattern.Type)
			if seen[key] {
				continue
			}
			seen[key] = true

			endpoints = append(endpoints, JSEndpoint{
				URL:        url,
				Type:       pattern.Type,
				Snippet:    match[0],
				LineNumber: 0, // Could be extracted with more advanced parsing
			})
		}
	}

	return endpoints
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// ResolveJSEndpoint resolves a relative endpoint found in JS to an absolute URL.
func ResolveJSEndpoint(endpoint, jsURL, baseURL string) string {
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return endpoint
	}
	if strings.HasPrefix(endpoint, "/") {
		if resolved, err := resolveRef(baseURL, endpoint); err == nil {
			return resolved
		}
		return endpoint
	}

	if jsBase, err := resolveRef(jsURL, "."); err == nil {
		if resolved, err := resolveRef(jsBase, endpoint); err == nil {
			if strings.HasPrefix(resolved, "http://") || strings.HasPrefix(resolved, "https://") {
				return resolved
			}
		}
	}
	if resolved, err := resolveRef(baseURL, endpoint); err == nil {
		return resolved
	}
	return endpoint
}

// resolveRef resolves a reference URL against a base URL.
func resolveRef(base, ref string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	r, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return b.ResolveReference(r).String(), nil
}

// =============================================================================
// TYPES (need to be defined in models.go)
// =============================================================================

// These types should be defined in models.go:
//
// type RequestType string
//
// const (
//     RequestTypeFetch      RequestType = "fetch"
//     RequestTypeAxios      RequestType = "axios"
//     RequestTypeXHR        RequestType = "xmlhttprequest"
//     RequestTypeGraphQL    RequestType = "graphql"
//     RequestTypeWebSocket  RequestType = "websocket"
//     RequestTypeSSE        RequestType = "sse"
//     RequestTypeBeacon     RequestType = "beacon"
//     RequestTypeForm       RequestType = "form_submit"
//     RequestTypeNavigation RequestType = "navigation"
// )
//
// type RequestSource struct {
//     Type        RequestType `json:"type"`
//     JavaScript  string      `json:"javascript,omitempty"`
//     LineNumber  int         `json:"line_number,omitempty"`
//     FileURL     string      `json:"file_url,omitempty"`
//     StackTrace  string      `json:"stack_trace,omitempty"`
// }
//
// type GraphQLOperation struct {
//     Type      string `json:"type"`
//     Operation string `json:"operation"`
// }
//
// type JSEndpoint struct {
//     URL        string      `json:"url"`
//     Type       RequestType `json:"type"`
//     Snippet    string      `json:"snippet"`
//     LineNumber int         `json:"line_number"`
//     FilePath   string      `json:"file_path,omitempty"`
// }

// ExtractWebSockets extracts WebSocket URLs from JS
func ExtractWebSockets(jsContent string) []string {
	var wsURLs []string
	seen := make(map[string]bool)

	// WebSocket patterns
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`new\s+WebSocket\s*\(\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`ws://[a-zA-Z0-9./?&=_-]+`),
		regexp.MustCompile(`wss://[a-zA-Z0-9./?&=_-]+`),
	}

	for _, pattern := range patterns {
		for _, match := range pattern.FindAllStringSubmatch(jsContent, -1) {
			url := match[len(match)-1]
			if !seen[url] {
				seen[url] = true
				wsURLs = append(wsURLs, url)
			}
		}
	}

	return wsURLs
}

// ExtractSecretsFromJS extracts secrets from JavaScript
func ExtractSecretsFromJS(jsContent string) []Secret {
	var secrets []Secret
	seen := make(map[string]bool)

	// Secret patterns
	patterns := []struct {
		Pattern *regexp.Regexp
		Type    string
	}{
		{regexp.MustCompile(`api[_-]?key\s*[:=]\s*['"]([^'"]+)['"]`), "api_key"},
		{regexp.MustCompile(`secret\s*[:=]\s*['"]([^'"]+)['"]`), "secret"},
		{regexp.MustCompile(`token\s*[:=]\s*['"]([^'"]+)['"]`), "token"},
		{regexp.MustCompile(`jwt\s*[:=]\s*['"]([^'"]+)['"]`), "jwt"},
		{regexp.MustCompile(`password\s*[:=]\s*['"]([^'"]+)['"]`), "password"},
		{regexp.MustCompile(`auth[_-]?token\s*[:=]\s*['"]([^'"]+)['"]`), "auth_token"},
		{regexp.MustCompile(`bearer\s*[:=]\s*['"]([^'"]+)['"]`), "bearer"},
		{regexp.MustCompile(`private[_-]?key\s*[:=]\s*['"]([^'"]+)['"]`), "private_key"},
		// JWT tokens
		{regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`), "jwt_token"},
		// AWS keys
		{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "aws_access_key"},
		// Firebase
		{regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), "firebase_key"},
	}

	for _, pattern := range patterns {
		for _, match := range pattern.Pattern.FindAllStringSubmatch(jsContent, -1) {
			if len(match) > 1 {
				value := match[1]
				if !seen[value] {
					seen[value] = true
					secrets = append(secrets, Secret{
						Type:    pattern.Type,
						Value:   value,
						Snippet: match[0],
					})
				}
			}
		}
	}

	return secrets
}

// Secret represents a discovered secret
type Secret struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Snippet string `json:"snippet"`
}

// ExtractHiddenEndpointsFromJS extracts hidden endpoints from JS
func ExtractHiddenEndpointsFromJS(jsContent string) []string {
	var endpoints []string
	seen := make(map[string]bool)

	// Hidden endpoint patterns
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`["'](/[a-zA-Z0-9/_-]{3,})["']`),
		regexp.MustCompile(`["'](/admin/[a-zA-Z0-9/_-]+)["']`),
		regexp.MustCompile(`["'](/internal/[a-zA-Z0-9/_-]+)["']`),
		regexp.MustCompile(`["'](/debug/[a-zA-Z0-9/_-]+)["']`),
		regexp.MustCompile(`["'](/hidden/[a-zA-Z0-9/_-]+)["']`),
		regexp.MustCompile(`["'](/private/[a-zA-Z0-9/_-]+)["']`),
		regexp.MustCompile(`["'](/secret/[a-zA-Z0-9/_-]+)["']`),
		regexp.MustCompile(`["'](/test/[a-zA-Z0-9/_-]+)["']`),
		regexp.MustCompile(`["'](/v[0-9]+/[a-zA-Z0-9/_-]+)["']`),
	}

	for _, pattern := range patterns {
		for _, match := range pattern.FindAllStringSubmatch(jsContent, -1) {
			endpoint := match[1]
			if !seen[endpoint] && len(endpoint) > 3 {
				seen[endpoint] = true
				endpoints = append(endpoints, endpoint)
			}
		}
	}

	return endpoints
}
