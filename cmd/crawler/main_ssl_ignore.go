package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sessionmgr/crawler"
)

func main() {
	var (
		seedURL      = flag.String("url", "", "Seed URL to start crawling (required)")
		maxDepth     = flag.Int("depth", 3, "Maximum crawl depth")
		maxPages     = flag.Int("pages", 100, "Maximum number of pages to crawl")
		concurrency  = flag.Int("concurrency", 5, "Number of concurrent workers")
		userAgent    = flag.String("ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "Custom User-Agent string")
		stayInDomain = flag.Bool("stay-in-domain", true, "Only crawl URLs within the same domain")
		proxy        = flag.String("proxy", "", "Proxy URL")
		useDynamic   = flag.Bool("dynamic", false, "Use dynamic crawler")
		sessionFile  = flag.String("session", "", "Session state file")
		dbPath       = flag.String("db", "scanner_discovery.db", "SQLite database path")
		timeout      = flag.Duration("timeout", 30*time.Second, "Request timeout")
		outputFile   = flag.String("output", "", "Output JSON file")
	)
	flag.Parse()

	if *seedURL == "" {
		log.Fatal("Error: -url flag is required")
	}

	log.Printf("Starting crawler with seed URL: %s", *seedURL)

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
	config.UserAgent = *userAgent

	// Add custom headers to look more like a real browser
	config.CustomHeaders = map[string]string{
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"Accept-Language":           "en-US,en;q=0.5",
		"Accept-Encoding":           "gzip, deflate, br",
		"Connection":                "keep-alive",
		"Upgrade-Insecure-Requests": "1",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "none",
		"Sec-Fetch-User":            "?1",
		"Cache-Control":             "no-cache",
		"Pragma":                    "no-cache",
		"DNT":                       "1",
	}

	// Create custom HTTP client that ignores SSL errors
	customClient := &http.Client{
		Timeout: config.RequestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Ignore SSL certificate errors
			},
		},
	}

	c, err := crawler.NewCrawlerWithClient(config, customClient)
	if err != nil {
		log.Fatalf("Failed to create crawler: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Shutting down...")
		cancel()
	}()

	log.Printf("Starting crawl...")
	startTime := time.Now()
	results, err := c.Run(ctx)
	if err != nil {
		log.Fatalf("Crawl failed: %v", err)
	}

	log.Printf("Crawl completed in %v, discovered %d requests", time.Since(startTime), len(results))

	if *outputFile != "" {
		data, _ := json.MarshalIndent(results, "", "  ")
		os.WriteFile(*outputFile, data, 0644)
		log.Printf("Results saved to %s", *outputFile)
	}
}
