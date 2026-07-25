// crawler/crawler.go
package crawler

import (
	"container/heap"
	"context"
	"fmt"
	"log"
	"strings"
)

// queueItem is one pending URL to crawl.
type queueItem struct {
	url      string
	depth    int
	priority int // lower = crawled sooner
	seq      int // tie-breaker so equal-priority items stay roughly FIFO
}

// priorityQueue is a min-heap on (priority, seq)
type priorityQueue []*queueItem

func (pq priorityQueue) Len() int { return len(pq) }
func (pq priorityQueue) Less(i, j int) bool {
	if pq[i].priority != pq[j].priority {
		return pq[i].priority < pq[j].priority
	}
	return pq[i].seq < pq[j].seq
}
func (pq priorityQueue) Swap(i, j int) { pq[i], pq[j] = pq[j], pq[i] }
func (pq *priorityQueue) Push(x interface{}) {
	*pq = append(*pq, x.(*queueItem))
}
func (pq *priorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[:n-1]
	return item
}

// urlPriority scores a URL for crawl ordering
func urlPriority(rawURL string) int {
	lower := strings.ToLower(rawURL)
	switch {
	case strings.Contains(lower, "login"), strings.Contains(lower, "signin"), strings.Contains(lower, "admin"):
		return 0
	case strings.Contains(lower, "register"), strings.Contains(lower, "signup"),
		strings.Contains(lower, "/api/"), strings.Contains(lower, "graphql"):
		return 1
	default:
		return 5
	}
}

// Crawler ties the static and dynamic crawlers together
type Crawler struct {
	config           CrawlerConfig
	static           *StaticCrawler
	dynamic          *DynamicCrawler
	store            *RequestStore
	robots           *robotsRules
	externalCallback RequestCallback
	visited          map[string]struct{}
	seenFingerprints map[string]struct{}
	results          []*DiscoveredRequest
}

// NewCrawler wires up storage and crawlers
func NewCrawler(config CrawlerConfig) (*Crawler, error) {
	return NewCrawlerWithCallback(config, nil)
}

// NewCrawlerWithCallback creates a crawler with a callback
func NewCrawlerWithCallback(config CrawlerConfig, cb RequestCallback) (*Crawler, error) {
	store, err := NewRequestStore(config.DBPath)
	if err != nil {
		return nil, err
	}

	c := &Crawler{
		config:           config,
		store:            store,
		externalCallback: cb,
		visited:          map[string]struct{}{},
		seenFingerprints: map[string]struct{}{},
	}
	c.static = NewStaticCrawler(config, nil, store)

	if config.UsePlaywright {
		dyn, err := NewDynamicCrawler(config, c.handleDiscovered)
		if err != nil {
			store.Close()
			return nil, err
		}
		c.dynamic = dyn
	}

	return c, nil
}

// handleDiscovered is the single funnel every DiscoveredRequest passes through
func (c *Crawler) handleDiscovered(req *DiscoveredRequest, err error) {
	if c.externalCallback != nil {
		c.externalCallback(req, err)
	}
	if err != nil {
		log.Printf("crawler: %v", err)
		return
	}
	if req == nil {
		return
	}
	if _, seen := c.seenFingerprints[req.ID]; seen {
		return
	}
	c.seenFingerprints[req.ID] = struct{}{}

	if saveErr := c.store.SaveRequest(req); saveErr != nil {
		log.Printf("crawler: failed to persist %s: %v", req.URL, saveErr)
	}
	c.results = append(c.results, req)
}

// Run performs a priority-ordered crawl starting at config.SeedURL
func (c *Crawler) Run(ctx context.Context) ([]*DiscoveredRequest, error) {
	if c.config.RespectRobotsTxt {
		c.robots = fetchRobotsRules(ctx, c.config.SeedURL, c.config.UserAgent)
	}

	if c.dynamic != nil {
		if err := c.dynamic.Start(ctx); err != nil {
			return nil, err
		}
		defer c.dynamic.Close()
	}

	pq := &priorityQueue{}
	heap.Init(pq)
	seq := 0
	push := func(u string, depth int) {
		heap.Push(pq, &queueItem{url: u, depth: depth, priority: urlPriority(u), seq: seq})
		seq++
	}
	push(c.config.SeedURL, 0)

	queuedOrVisited := map[string]struct{}{c.config.SeedURL: {}}

	// Katana pre-pass: fast, browser-free breadth-first discovery
	if c.config.UseKatana {
		PrintInfo("Running Katana pre-pass for fast breadth-first discovery...")
		seeded := 0
		
		// Try library approach first
		katanaErr := RunKatanaPhase(ctx, c.config,
			func(req *DiscoveredRequest) {
				c.handleDiscovered(req, nil)
			},
			func(u string, depth int) {
				if _, seen := queuedOrVisited[u]; seen {
					return
				}
				queuedOrVisited[u] = struct{}{}
				push(u, depth)
				seeded++
			},
		)
		
		// If library approach fails, try binary approach
		if katanaErr != nil {
			PrintWarning(fmt.Sprintf("Katana library pre-pass failed: %v", katanaErr))
			PrintInfo("Attempting Katana binary pre-pass...")
			
			katanaErr = RunKatanaBinary(ctx, c.config,
				func(req *DiscoveredRequest) {
					c.handleDiscovered(req, nil)
				},
				func(u string, depth int) {
					if _, seen := queuedOrVisited[u]; seen {
						return
					}
					queuedOrVisited[u] = struct{}{}
					push(u, depth)
					seeded++
				},
			)
			
			if katanaErr != nil {
				PrintWarning(fmt.Sprintf("Katana binary pre-pass failed, continuing with Raptor-only discovery: %v", katanaErr))
			} else {
				PrintSuccess(fmt.Sprintf("Katana binary pre-pass seeded %d additional URL(s) for deep crawling", seeded))
			}
		} else {
			PrintSuccess(fmt.Sprintf("Katana pre-pass seeded %d additional URL(s) for deep crawling", seeded))
		}
	}

	for pq.Len() > 0 && len(c.visited) < c.config.MaxPages {
		item := heap.Pop(pq).(*queueItem)
		u := item.url

		if _, seen := c.visited[u]; seen {
			continue
		}
		if c.robots != nil && !c.robots.allows(u) {
			continue
		}
		c.visited[u] = struct{}{}

		if item.depth > c.config.MaxDepth {
			continue
		}

		var next []string
		if c.dynamic != nil {
			next = c.dynamic.CrawlURL(ctx, u, item.depth)
		} else {
			found, staticNext := c.static.CrawlURL(ctx, u, item.depth, nil)
			for _, req := range found {
				c.handleDiscovered(req, nil)
			}
			next = staticNext
		}

		for _, n := range next {
			if _, seen := queuedOrVisited[n]; seen {
				continue
			}
			queuedOrVisited[n] = struct{}{}
			push(n, item.depth+1)
		}
	}

	return c.results, nil
}

// Close closes the crawler and releases resources
func (c *Crawler) Close() error {
	if c.dynamic != nil {
		c.dynamic.Close()
	}
	return c.store.Close()
}

// Add to crawler.go
func (c *Crawler) BuildAuthFlow(ctx context.Context) (*AuthFlow, error) {
    // Find login endpoints
    loginURLs := []string{}
    for _, req := range c.results {
        if req.Form != nil && req.Form.FormType == FormLogin {
            loginURLs = append(loginURLs, req.URL)
        }
    }
    
    if len(loginURLs) == 0 {
        return nil, fmt.Errorf("no login forms found")
    }
    
    flow := &AuthFlow{
        StartURL: loginURLs[0],
        Steps:    []AuthStep{},
    }
    
    // Step 1: GET login page (CSRF extraction)
    step1 := AuthStep{
        Order:   0,
        URL:     loginURLs[0],
        Method:  "GET",
        IsLogin: false,
    }
    flow.Steps = append(flow.Steps, step1)
    
    // Step 2: POST login credentials
    // Find the login form submission
    for _, req := range c.results {
        if req.URL == loginURLs[0] && req.Method == "POST" {
            step2 := AuthStep{
                Order:    1,
                URL:      req.URL,
                Method:   req.Method,
                IsLogin:  true,
                Request:  extractRequestHeaders(req.Headers),
            }
            flow.Steps = append(flow.Steps, step2)
            break
        }
    }
    
    // Step 3: Check for redirect (dashboard)
    for _, req := range c.results {
        if req.Method == "GET" && strings.Contains(req.URL, "dashboard") ||
           strings.Contains(req.URL, "profile") ||
           strings.Contains(req.URL, "account") {
            step3 := AuthStep{
                Order:       2,
                URL:         req.URL,
                Method:      req.Method,
                IsRedirect:  true,
                IsLogin:     false,
            }
            flow.Steps = append(flow.Steps, step3)
            flow.FinalURL = req.URL
            break
        }
    }
    
    return flow, nil
}