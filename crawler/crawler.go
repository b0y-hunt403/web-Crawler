// Package crawler discovers everything a target web app exposes — pages,
// API endpoints, files, forms and their input fields, and SPA routes.
//
// It deliberately owns NO authentication or session logic. That is your
// Session_Manager's job. This package only ever *reads* an already-captured
// session via CrawlerConfig.SessionStatePath (a JSON file: cookies +
// per-origin localStorage). If that path is empty, it crawls unauthenticated.
package crawler

import (
	"container/heap"
	"context"
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

// priorityQueue is a min-heap on (priority, seq) — login/admin/api/graphql
// pages jump the queue instead of waiting behind hundreds of static assets
// discovered earlier, per the "adaptive priority" ask.
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

// urlPriority scores a URL for crawl ordering. Lower is crawled sooner.
// This is intentionally simple keyword matching, not learned/adaptive —
// good enough to make sure auth/admin/API surfaces get attention early
// instead of getting starved by max-pages on a large site.
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

// Crawler ties the static and dynamic crawlers together into a single
// priority-ordered BFS walk of the target, bounded by MaxDepth/MaxPages.
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

// NewCrawler wires up storage and, if config.UsePlaywright is true, the
// chromedp-backed dynamic crawler. Every DiscoveredRequest is persisted to
// DBPath and returned from Run(); nothing extra happens per-discovery.
func NewCrawler(config CrawlerConfig) (*Crawler, error) {
	return NewCrawlerWithCallback(config, nil)
}

// NewCrawlerWithCallback is NewCrawler plus a caller-supplied callback that
// fires for every DiscoveredRequest as it's found — e.g. for live colored
// terminal output. The callback runs in addition to (not instead of)
// persistence and dedup; it fires even for entries that turn out to be
// duplicates, so a live UI can still show every match it saw.
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

// handleDiscovered is the single funnel every DiscoveredRequest passes
// through: forward to the caller's callback (if any), dedup by fingerprint,
// persist, and keep for the final results slice.
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

// Run performs a priority-ordered crawl starting at config.SeedURL and
// returns every DiscoveredRequest found (also persisted to DBPath along
// the way). The seed URL itself is recorded at depth 0; its direct
// children at depth 1, and so on.
func (c *Crawler) Run(ctx context.Context) ([]*DiscoveredRequest, error) {
	// Banner removed - now printed once in main.go

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

func (c *Crawler) Close() error {
	if c.dynamic != nil {
		c.dynamic.Close()
	}
	return c.store.Close()
}