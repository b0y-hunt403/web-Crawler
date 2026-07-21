package crawler

import (
	"bufio"
	"context"
	"net/http"
	"net/url"
	"strings"
)

// robotsRules is a deliberately minimal robots.txt parser: prefix-based
// Disallow matching for User-agent: * only. No wildcards, no crawl-delay,
// no sitemap parsing. This is opt-in (CrawlerConfig.RespectRobotsTxt) and
// intended for "enterprise mode", not bug-bounty scanning.
type robotsRules struct {
	disallow []string
}

func fetchRobotsRules(ctx context.Context, seedURL, userAgent string) *robotsRules {
	u, err := url.Parse(seedURL)
	if err != nil {
		return nil
	}
	robotsURL := u.Scheme + "://" + u.Host + "/robots.txt"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, robotsURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	rules := &robotsRules{}
	applies := false
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "user-agent:"):
			agent := strings.TrimSpace(line[len("user-agent:"):])
			applies = agent == "*"
		case applies && strings.HasPrefix(lower, "disallow:"):
			path := strings.TrimSpace(line[len("disallow:"):])
			if path != "" {
				rules.disallow = append(rules.disallow, path)
			}
		}
	}
	return rules
}

func (r *robotsRules) allows(rawURL string) bool {
	if r == nil {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	for _, prefix := range r.disallow {
		if strings.HasPrefix(u.Path, prefix) {
			return false
		}
	}
	return true
}
