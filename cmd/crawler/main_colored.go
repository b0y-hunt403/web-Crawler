package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"sessionmgr/crawler"
)

// ANSI color codes
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
	ColorDim    = "\033[2m"
)

// Custom callback with colored output
func coloredCallback(req *crawler.DiscoveredRequest, err error) {
	if err != nil {
		fmt.Printf("%s[ERROR]%s %v\n", ColorRed, ColorReset, err)
		return
	}
	if req == nil {
		return
	}

	// Filter out static assets and JS files
	if isStaticAsset(req.URL) {
		// Print in dim color for static assets
		fmt.Printf("%s  [STATIC] %s%s\n", ColorDim, req.URL, ColorReset)
		return
	}

	// Determine color based on source type
	var color string
	var icon string
	switch req.SourceType {
	case "anchor":
		color = ColorGreen
		icon = "📄"
	case "form_submit":
		color = ColorCyan
		icon = "📝"
	case "js_api_extract":
		color = ColorPurple
		icon = "🔗"
	case "js_spa_route":
		color = ColorBlue
		icon = "🔄"
	case "ajax_fetch":
		color = ColorYellow
		icon = "🌐"
	case "shadow_dom_form":
		color = ColorPurple
		icon = "👻"
	case "dom_input":
		color = ColorCyan
		icon = "⌨️"
	default:
		color = ColorWhite
		icon = "•"
	}

	// Format the output
	output := fmt.Sprintf("%s%s %s[%s]%s %s (depth: %d)",
		color,
		icon,
		ColorBold,
		req.Method,
		ColorReset,
		req.URL,
		req.Depth,
	)

	// Add form info if available
	if req.Form != nil {
		formType := req.Form.FormType
		if formType != "" {
			output += fmt.Sprintf(" %s[%s]%s", ColorYellow, formType, ColorReset)
		}
		// Show number of fields
		if len(req.Form.Fields) > 0 {
			output += fmt.Sprintf(" %s(%d fields)%s", ColorDim, len(req.Form.Fields), ColorReset)
		}
	}

	// Add SPA route info
	if req.SPARoute != nil {
		output += fmt.Sprintf(" %s[SPA Route]%s", ColorBlue, ColorReset)
	}

	fmt.Println(output)
}

// Check if URL is a static asset
func isStaticAsset(url string) bool {
	staticExtensions := []string{
		".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".gif",
		".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot",
		".mp4", ".mp3", ".pdf", ".doc", ".docx", ".zip",
		".tar", ".gz", ".rar",
	}
	urlLower := strings.ToLower(url)
	for _, ext := range staticExtensions {
		if strings.HasSuffix(urlLower, ext) {
			return true
		}
	}
	// Also filter Next.js chunks
	if strings.Contains(url, "/_next/") {
		return true
	}
	return false
}

func main() {
	// Command line flags
	var (
		seedURL      = flag.String("url", "", "Seed URL to start crawling (required)")
		maxDepth     = flag.Int("depth", 3, "Maximum crawl depth")
		maxPages     = flag.Int("pages", 100, "Maximum number of pages to crawl")
		concurrency  = flag.Int("concurrency", 5, "Number of concurrent workers")
		userAgent    = flag.String("ua", "", "Custom User-Agent string")
		stayInDomain = flag.Bool("stay-in-domain", true, "Only crawl URLs within the same domain")
		proxy        = flag.String("proxy", "", "Proxy URL (e.g., http://proxy:8080)")
		useDynamic   = flag.Bool("dynamic", false, "Use dynamic (headless browser) crawler for SPAs")
		sessionFile  = flag.String("session", "", "Path to session state JSON file (for authenticated crawling)")
		dbPath       = flag.String("db", "scanner_discovery.db", "SQLite database path")
		timeout      = flag.Duration("timeout", 30*time.Second, "Request timeout")
		jsonOutput   = flag.String("output", "", "Output results to JSON file (optional)")
		showStatic   = flag.Bool("show-static", false, "Show static assets in output")
	)
	flag.Parse()

	if *seedURL == "" {
		log.Fatal("Error: -url flag is required")
	}

	// Setup logging
	log.SetFlags(0) // Disable timestamp in log, we'll use our own formatting

	fmt.Printf("%s🚀 Starting Crawler%s\n", ColorBold, ColorReset)
	fmt.Printf("%s📍 Target:%s %s\n", ColorCyan, ColorReset, *seedURL)
	fmt.Printf("%s📊 Max Depth:%s %d, %sMax Pages:%s %d\n", 
		ColorCyan, ColorReset, *maxDepth, 
		ColorCyan, ColorReset, *maxPages)
	fmt.Printf("%s🔄 Dynamic Mode:%s %v\n", ColorCyan, ColorReset, *useDynamic)
	fmt.Println(strings.Repeat("=", 80))

	// Build configuration
	config := crawler.DefaultCrawlerConfig(*seedURL)
	config.MaxDepth = *maxDepth
	config.MaxPages = *maxPages
	config.Concurrency = *concurrency
	config.StayInDomain = *stayInDomain
	config.Proxy = *proxy
	config.UsePlaywright = *useDynamic
	config.SessionStatePath = *sessionFile
	config.DBPath = *dbPath
	config.RequestTimeout = *timeout

	if *userAgent != "" {
		config.UserAgent = *userAgent
	}

	// Create crawler with colored callback
	c, err := crawler.NewCrawlerWithCallback(config, coloredCallback)
	if err != nil {
		log.Fatalf("%sFailed to create crawler: %v%s", ColorRed, err, ColorReset)
	}
	defer func() {
		if err := c.Close(); err != nil {
			fmt.Printf("%sError closing crawler: %v%s\n", ColorRed, err, ColorReset)
		}
	}()

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupts gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Printf("\n%s⚠️  Received interrupt signal, shutting down gracefully...%s\n", ColorYellow, ColorReset)
		cancel()
	}()

	// Run the crawler
	fmt.Printf("\n%s🔍 Crawling...%s\n\n", ColorBold, ColorReset)

	startTime := time.Now()
	results, err := c.Run(ctx)
	if err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Printf("\n%s⏹️  Crawl cancelled by user%s\n", ColorYellow, ColorReset)
		} else {
			log.Fatalf("%sCrawl failed: %v%s", ColorRed, err, ColorReset)
		}
	}

	elapsed := time.Since(startTime)

	// Print summary
	printColoredSummary(results, elapsed, config.DBPath, *jsonOutput)

	// Output to JSON if requested
	if *jsonOutput != "" {
		if err := writeResultsToJSON(*jsonOutput, results); err != nil {
			fmt.Printf("%sError writing JSON output: %v%s\n", ColorRed, err, ColorReset)
		} else {
			fmt.Printf("%s✅ Results written to %s%s\n", ColorGreen, *jsonOutput, ColorReset)
		}
	}
}

func printColoredSummary(results []*crawler.DiscoveredRequest, elapsed time.Duration, dbPath, jsonOutput string) {
	fmt.Printf("\n%s" + strings.Repeat("=", 80) + "%s\n", ColorBold, ColorReset)
	fmt.Printf("%s📊 CRAWL SUMMARY%s\n", ColorBold, ColorReset)
	fmt.Printf("%s" + strings.Repeat("=", 80) + "%s\n", ColorBold, ColorReset)

	fmt.Printf("%s⏱️  Time elapsed:%s %v\n", ColorCyan, ColorReset, elapsed)
	fmt.Printf("%s📊 Total requests:%s %d\n", ColorCyan, ColorReset, len(results))

	// Count by source type (excluding static)
	sourceCounts := make(map[string]int)
	methodCounts := make(map[string]int)
	var formCount, spaRouteCount, pageCount, staticCount int

	for _, req := range results {
		methodCounts[req.Method]++
		if isStaticAsset(req.URL) {
			staticCount++
			continue
		}
		pageCount++
		sourceCounts[req.SourceType]++
		if req.Form != nil {
			formCount++
		}
		if req.SPARoute != nil {
			spaRouteCount++
		}
	}

	fmt.Printf("%s📄 Pages/Endpoints:%s %d\n", ColorGreen, ColorReset, pageCount)
	fmt.Printf("%s📁 Static assets:%s %d\n", ColorDim, ColorReset, staticCount)
	fmt.Printf("%s📝 Forms found:%s %d\n", ColorCyan, ColorReset, formCount)
	fmt.Printf("%s🔄 SPA Routes:%s %d\n", ColorBlue, ColorReset, spaRouteCount)

	fmt.Printf("\n%s📂 By source type (pages only):%s\n", ColorBold, ColorReset)
	for source, count := range sourceCounts {
		fmt.Printf("  %s•%s %s: %d\n", ColorGreen, ColorReset, source, count)
	}

	fmt.Printf("\n%s📊 By HTTP method:%s\n", ColorBold, ColorReset)
	for method, count := range methodCounts {
		fmt.Printf("  %s•%s %s: %d\n", ColorYellow, ColorReset, method, count)
	}

	// Show top discovered pages
	fmt.Printf("\n%s🔝 Top Discovered Pages:%s\n", ColorBold, ColorReset)
	count := 0
	for _, req := range results {
		if isStaticAsset(req.URL) {
			continue
		}
		if count >= 10 {
			break
		}
		color := ColorGreen
		if req.Form != nil {
			color = ColorCyan
		}
		if req.SPARoute != nil {
			color = ColorBlue
		}
		fmt.Printf("  %s[%s]%s %s (depth: %d)%s\n", 
			color, req.Method, ColorReset, req.URL, req.Depth, ColorReset)
		count++
	}
	if len(results)-staticCount > 10 {
		fmt.Printf("  %s... and %d more%s\n", ColorDim, len(results)-staticCount-10, ColorReset)
	}

	fmt.Printf("\n%s💾 Results persisted to database:%s %s\n", ColorCyan, ColorReset, dbPath)
	if jsonOutput != "" {
		fmt.Printf("%s💾 Results saved to JSON:%s %s\n", ColorCyan, ColorReset, jsonOutput)
	}
	fmt.Printf("%s" + strings.Repeat("=", 80) + "%s\n", ColorBold, ColorReset)
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
