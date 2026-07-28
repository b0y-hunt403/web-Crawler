// crawler/config.go
package crawler

import "time"

// CrawlerConfig holds configuration for the crawler
type CrawlerConfig struct {
	SeedURL          string            `json:"seed_url"`
	MaxDepth         int               `json:"max_depth"`
	MaxPages         int               `json:"max_pages"`
	Concurrency      int               `json:"concurrency"`
	StayInDomain     bool              `json:"stay_in_domain"`
	DynamicCrawl     bool              `json:"dynamic_crawl"`
	UsePlaywright    bool              `json:"use_playwright"`
	SessionStatePath string            `json:"session_state_path"`
	ExtractShadowDOM bool              `json:"extract_shadow_dom"`
	AnalyzeHeavyJS   bool              `json:"analyze_heavy_js"`
	ExtractSPARoutes bool              `json:"extract_spa_routes"`
	RequestTimeout   time.Duration     `json:"request_timeout"`
	MaxJSSize        int               `json:"max_js_size"`
	UserAgent        string            `json:"user_agent"`
	Proxy            string            `json:"proxy"`
	DBPath           string            `json:"db_path"`
	RespectRobotsTxt bool              `json:"respect_robots_txt"`
	CustomHeaders    map[string]string `json:"custom_headers,omitempty"`

	// Katana pre-pass (see katana.go). Off by default — Raptor behaves
	// exactly as before unless UseKatana is explicitly enabled. When on,
	// Katana runs first as a fast breadth-first discovery pass; Raptor's
	// own static/dynamic crawler still visits every non-asset URL it
	// finds for form-aware, request-intelligence extraction.
	UseKatana         bool   `json:"use_katana"`
	KatanaHeadless    bool   `json:"katana_headless"`    // use katana's hybrid (browser) engine instead of standard net/http
	KatanaMaxDepth    int    `json:"katana_max_depth"`   // Katana's own crawl depth, independent of MaxDepth
	KatanaConcurrency int    `json:"katana_concurrency"` // Katana can safely run much higher concurrency than the browser-backed dynamic crawler
	KatanaFieldScope  string `json:"katana_field_scope"` // "rdn" (default), "fqdn", or "dn" — see katana -fs
}

// DefaultCrawlerConfig returns a default crawler configuration
func DefaultCrawlerConfig() CrawlerConfig {
	return CrawlerConfig{
		MaxDepth:          3,
		MaxPages:          100,
		Concurrency:       5,
		StayInDomain:      true,
		DynamicCrawl:      false,
		UsePlaywright:     false,
		ExtractShadowDOM:  true,
		AnalyzeHeavyJS:    true,
		ExtractSPARoutes:  true,
		RequestTimeout:    30 * time.Second,
		MaxJSSize:         1024 * 1024,
		UserAgent:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		RespectRobotsTxt:  false,
		CustomHeaders:     make(map[string]string),
		UseKatana:         false,
		KatanaHeadless:    false,
		KatanaMaxDepth:    2,
		KatanaConcurrency: 20,
		KatanaFieldScope:  "rdn",
	}
}
