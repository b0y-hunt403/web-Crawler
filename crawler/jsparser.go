package crawler

import (
	"net/url"
	"regexp"
	"strings"
)

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
	regexp.MustCompile(`(?i)\.open\(\s*["'](?:GET|POST|PUT|DELETE|PATCH|HEAD)["']\s*,\s*["']([^"'()]+)["']`), // XMLHttpRequest.open(method, url)
	regexp.MustCompile(`(?i)new\s+URL\(\s*["']([^"'()]+)["']`),
	regexp.MustCompile(`(?i)import\(\s*["']([^"'()]+)["']\s*\)`), // dynamic import()
}

// hardcodedURLPattern catches any fully-qualified URL sitting in a string
// literal, regardless of what function (if any) it's passed to — Katana-style
// "just grep every URL-shaped string out of the JS" coverage.
var hardcodedURLPattern = regexp.MustCompile(`(?i)["'](https?://[a-zA-Z0-9.\-]+(?::[0-9]+)?(?:/[a-zA-Z0-9/_\-.%]*)?(?:\?[^"'\s]*)?)["']`)

// graphqlHintPattern flags likely GraphQL endpoints/operations so callers
// can tag them distinctly instead of lumping them in with plain REST calls.
var graphqlHintPattern = regexp.MustCompile(`(?i)["']([^"']*graphql[^"']*)["']`)

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

var reactRoutePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)path\s*:\s*["'](/[a-zA-Z0-9/_-]+)["']`),
	regexp.MustCompile(`(?i)to\s*:\s*["'](/[a-zA-Z0-9/_-]+)["']`),
	regexp.MustCompile(`(?i)route\s*:\s*["'](/[a-zA-Z0-9/_-]+)["']`),
}

var vuePathPattern = regexp.MustCompile(`(?i)path\s*:\s*["'](/[a-zA-Z0-9/_-]+)["']`)
var vueImportPattern = regexp.MustCompile(`(?i)component\s*:\s*\(\)\s*=>\s*import\(["']([^"'()]+)["']\)`)

// ExtractSPARoutesFromJS extracts SPA routes from React/Vue router configs,
// mirroring extract_spa_routes_from_js in js_parser.py.
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
