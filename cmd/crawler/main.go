// cmd/crawler/main.go
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Anduamlk/web-Crawler/crawler"
)

func main() {
	var (
		seedURL       = flag.String("url", "", "Seed URL to start crawling (required)")
		maxDepth      = flag.Int("depth", 3, "Maximum crawl depth")
		maxPages      = flag.Int("pages", 100, "Maximum number of pages to crawl")
		concurrency   = flag.Int("concurrency", 5, "Number of concurrent workers")
		userAgent     = flag.String("ua", "", "Custom User-Agent string")
		stayInDomain  = flag.Bool("stay-in-domain", true, "Only crawl URLs within the same domain")
		proxy         = flag.String("proxy", "", "Proxy URL (e.g., http://proxy:8080)")
		useDynamic    = flag.Bool("dynamic", false, "Use dynamic (headless browser) crawler for SPAs")
		bothModes     = flag.Bool("both", false, "Run both static and dynamic crawlers")
		sessionFile   = flag.String("session", "", "Path to session state JSON file")
		dbPath        = flag.String("db", "scanner_discovery.db", "SQLite database path")
		timeout       = flag.Duration("timeout", 30*time.Second, "Request timeout")
		jsonOutput    = flag.String("output", "", "Output results to JSON file (optional)")
		username      = flag.String("username", "", "Username for authenticated crawling")
		password      = flag.String("password", "", "Password for authenticated crawling")
		loginURL      = flag.String("login-url", "", "Login page or JSON login endpoint")
		usernameField = flag.String("username-field", "", "Username field name or CSS selector (auto-detected when empty)")
		passwordField = flag.String("password-field", "", "Password field name or CSS selector (auto-detected when empty)")
		csrfField     = flag.String("csrf-field", "", "CSRF field name, selector, or JSON header (auto-detected when empty)")
		loginMethod   = flag.String("login-method", "form", "Login transport: form or json")
		sessionCookie = flag.String("session-cookie", "", "Cookie whose creation confirms login success")
		cookieFile    = flag.String("cookie-file", "", "Write reusable authenticated session metadata to this JSON file")
		successRegex  = flag.String("login-success-regex", "", "Regex matched against post-login URL and page text")

		useKatana         = flag.Bool("katana", false, "Run a Katana pre-pass for fast breadth-first discovery before Raptor's own crawl")
		katanaHeadless    = flag.Bool("katana-headless", false, "Use Katana's headless (browser) engine instead of its standard net/http engine")
		katanaDepth       = flag.Int("katana-depth", 2, "Katana's own crawl depth (independent of -depth)")
		katanaConcurrency = flag.Int("katana-concurrency", 20, "Katana concurrency (can safely run higher than -concurrency since it has no browser overhead in standard mode)")
		katanaFieldScope  = flag.String("katana-field-scope", "rdn", "Katana crawl scope field: rdn, fqdn, or dn")
	)
	flag.Parse()

	auth := crawler.AuthConfig{
		Username: *username, Password: *password, LoginURL: *loginURL,
		UsernameField: *usernameField, PasswordField: *passwordField, CSRFField: *csrfField,
		LoginMethod: *loginMethod, SessionCookie: *sessionCookie, CookieFile: *cookieFile,
		SuccessRegex: *successRegex,
	}

	if *seedURL == "" {
		log.Fatal("Error: -url flag is required")
	}
	if (*username != "" || *password != "" || *loginURL != "") && !auth.Enabled() {
		log.Fatal("Error: authenticated crawling requires --username, --password, and --login-url")
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	// Print banner ONCE at the very beginning
	banner := crawler.DefaultBanner()
	banner.PrintBanner()

	// If -both flag is set, run both modes
	if *bothModes {
		log.Println("🔄 Running BOTH static and dynamic crawlers...")
		log.Println("")

		// Run static crawler
		log.Println("🔍 Running static crawler...")
		if err := runCrawler(*seedURL, *dbPath, *maxDepth, *maxPages, *concurrency,
			*stayInDomain, *userAgent, *proxy, *sessionFile, *timeout, false, *jsonOutput,
			*useKatana, *katanaHeadless, *katanaDepth, *katanaConcurrency, *katanaFieldScope, auth); err != nil {
			log.Printf("❌ Static crawler failed: %v", err)
		} else {
			log.Println("✅ Static crawler completed successfully")
		}

		log.Println("")

		// Run dynamic crawler
		log.Println("🚀 Running dynamic crawler...")
		if err := runCrawler(*seedURL, *dbPath, *maxDepth, *maxPages, *concurrency,
			*stayInDomain, *userAgent, *proxy, *sessionFile, *timeout, true, *jsonOutput,
			// Katana pre-pass already ran during the static phase above and
			// persisted its results to the same DBPath — don't run it twice.
			false, *katanaHeadless, *katanaDepth, *katanaConcurrency, *katanaFieldScope, auth); err != nil {
			log.Printf("❌ Dynamic crawler failed: %v", err)
		} else {
			log.Println("✅ Dynamic crawler completed successfully")
		}

		log.Println("")
		log.Println("✅ Both crawls completed!")
		return
	}

	// Single mode run
	if err := runCrawler(*seedURL, *dbPath, *maxDepth, *maxPages, *concurrency,
		*stayInDomain, *userAgent, *proxy, *sessionFile, *timeout, *useDynamic, *jsonOutput,
		*useKatana, *katanaHeadless, *katanaDepth, *katanaConcurrency, *katanaFieldScope, auth); err != nil {
		log.Fatalf("❌ Crawl failed: %v", err)
	}
}

func runCrawler(seedURL, dbPath string, maxDepth, maxPages, concurrency int,
	stayInDomain bool, userAgent, proxy, sessionFile string,
	timeout time.Duration, dynamic bool, jsonOutput string,
	useKatana, katanaHeadless bool, katanaDepth, katanaConcurrency int, katanaFieldScope string,
	auth crawler.AuthConfig) error {

	config := crawler.DefaultCrawlerConfig()
	config.SeedURL = seedURL
	config.MaxDepth = maxDepth
	config.MaxPages = maxPages
	config.Concurrency = concurrency
	config.StayInDomain = stayInDomain
	config.Proxy = proxy
	config.UsePlaywright = dynamic
	config.DynamicCrawl = dynamic
	config.SessionStatePath = sessionFile
	config.DBPath = dbPath
	config.RequestTimeout = timeout
	config.UseKatana = useKatana
	config.KatanaHeadless = katanaHeadless
	config.KatanaMaxDepth = katanaDepth
	config.KatanaConcurrency = katanaConcurrency
	config.KatanaFieldScope = katanaFieldScope
	config.Auth = auth
	if auth.Enabled() {
		config.UsePlaywright = true
		config.DynamicCrawl = true
	}

	if userAgent != "" {
		config.UserAgent = userAgent
	}

	c, err := crawler.NewCrawler(config)
	if err != nil {
		return err
	}
	defer func() {
		if err := c.Close(); err != nil {
			log.Printf("Error closing crawler: %v", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("🛑 Received interrupt signal, shutting down gracefully...")
		cancel()
	}()

	startTime := time.Now()
	results, err := c.Run(ctx)
	if err != nil {
		if ctx.Err() == context.Canceled {
			log.Println("⏹️ Crawl cancelled by user")
			return nil
		}
		return err
	}

	elapsed := time.Since(startTime)
	log.Printf("✅ Crawl completed in %v, discovered %d requests", elapsed, len(results))

	printSummary(results)

	if jsonOutput != "" {
		if err := writeResultsToJSON(jsonOutput, results); err != nil {
			log.Printf("Error writing JSON output: %v", err)
		} else {
			log.Printf("📄 Results written to %s", jsonOutput)
		}
	}

	log.Printf("💾 Results persisted to database: %s", config.DBPath)
	return nil
}

func printSummary(results []*crawler.DiscoveredRequest) {
	if len(results) == 0 {
		log.Println("No results found.")
		return
	}

	sourceCounts := make(map[string]int)
	methodCounts := make(map[string]int)
	var formCount, spaRouteCount, jsonFormCount int

	for _, req := range results {
		sourceCounts[req.SourceType]++
		methodCounts[req.Method]++
		if req.Form != nil {
			formCount++
			if req.JSONFormat != nil && req.JSONFormat.IsJSON {
				jsonFormCount++
			}
		}
		if req.SPARoute != nil {
			spaRouteCount++
		}
	}

	log.Println("\n=== Crawl Summary ===")
	log.Printf("Total discovered requests: %d", len(results))
	log.Println("\nBy source type:")
	for source, count := range sourceCounts {
		log.Printf("  %-15s: %d", source, count)
	}
	log.Println("\nBy HTTP method:")
	for method, count := range methodCounts {
		log.Printf("  %-10s: %d", method, count)
	}
	if formCount > 0 {
		log.Printf("Forms found: %d (JSON forms: %d)", formCount, jsonFormCount)
	}
	if spaRouteCount > 0 {
		log.Printf("SPA routes found: %d", spaRouteCount)
	}

	// Show POST requests with bodies
	log.Println("\n=== POST Requests with Bodies ===")
	postCount := 0
	for _, req := range results {
		if req.Method == "POST" && req.Body != "" {
			postCount++
			if postCount <= 10 {
				bodyPreview := req.Body
				if len(bodyPreview) > 200 {
					bodyPreview = bodyPreview[:200] + "..."
				}
				log.Printf("  [%s] %s", req.URL, bodyPreview)
			}
		}
	}
	if postCount > 10 {
		log.Printf("  ... and %d more POST requests", postCount-10)
	}

	log.Println("\nTop discovered URLs:")
	count := 0
	for _, req := range results {
		if count >= 10 {
			break
		}
		log.Printf("  [%s] %s (depth: %d)", req.Method, req.URL, req.Depth)
		count++
	}
	if len(results) > 10 {
		log.Printf("  ... and %d more", len(results)-10)
	}
}

func writeResultsToJSON(path string, results []*crawler.DiscoveredRequest) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}
