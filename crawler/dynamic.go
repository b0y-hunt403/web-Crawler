// crawler/dynamic.go
package crawler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	sessionmgr "github.com/Anduamlk/web-Crawler/session"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// RequestCallback receives every DiscoveredRequest as it's found.
type RequestCallback func(req *DiscoveredRequest, err error)

// pendingNetworkRequest tracks one in-flight browser network request.
// ENHANCED: Added fetch/XHR tracking fields
type pendingNetworkRequest struct {
	method      string
	url         string
	headers     map[string]string
	body        string
	depth       int
	isDocument  bool
	resourceTyp network.ResourceType
	startTime   time.Time
	isFetch     bool
	initiator   string
	fetchCode   string
	jsContext   string
	contentType string
	requestBody string
}

// urlQueueItem represents a URL in the crawling queue with its depth.
type urlQueueItem struct {
	url   string
	depth int
}

// noiseExtensions are file extensions to skip
var noiseExtensions = []string{
	".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg",
	".css", ".mp3", ".mp4", ".avi", ".mov", ".mkv",
	".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
	".zip", ".rar", ".7z", ".tar", ".gz",
}

// strOr returns string value or empty string
func strOr(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// mapToFormField converts a map to FormField
func mapToFormField(m map[string]interface{}) FormField {
	ff := FormField{
		Name:         strOr(m["name"]),
		Type:         FieldType(strOr(m["type"])),
		Value:        strOr(m["value"]),
		Placeholder:  strOr(m["placeholder"]),
		ID:           strOr(m["id"]),
		ClassName:    strOr(m["class_name"]),
		Autocomplete: strOr(m["autocomplete"]),
	}
	if req, ok := m["required"].(bool); ok {
		ff.Required = req
	}
	if ro, ok := m["readonly"].(bool); ok {
		ff.Readonly = ro
	}
	if dis, ok := m["disabled"].(bool); ok {
		ff.Disabled = dis
	}
	if chk, ok := m["checked"].(bool); ok {
		ff.Checked = chk
	}
	// Extract validation rules
	ff.Validation = ExtractValidationRules(m)
	return ff
}

// DynamicCrawler is the chromedp-backed dynamic crawler.
type DynamicCrawler struct {
	config           CrawlerConfig
	callback         RequestCallback
	session          sessionmgr.Session
	sessionState     *sessionmgr.State
	contextProvider  sessionmgr.BrowserContextProvider
	contextHandle    sessionmgr.BrowserContext
	allowedHost      string
	browserCtx       context.Context
	seenFingerprints map[string]struct{}
	seenURLs         map[string]struct{}
	pending          map[network.RequestID]*pendingNetworkRequest
	mu               sync.RWMutex
	queue            []urlQueueItem
	queueMu          sync.Mutex
	visitedCount     int
	maxPages         int
	maxDepth         int
	wg               sync.WaitGroup
	workerPool       chan struct{}
	sessionMu        sync.RWMutex
	sessionExpired   bool
}

func NewDynamicCrawler(config CrawlerConfig, callback RequestCallback, provider sessionmgr.BrowserContextProvider, activeSession sessionmgr.Session) (*DynamicCrawler, error) {
	host := ""
	if u, err := url.Parse(config.SeedURL); err == nil {
		host = u.Host
	}

	maxPages := config.MaxPages
	if maxPages == 0 {
		maxPages = 100
	}

	maxDepth := config.MaxDepth
	if maxDepth == 0 {
		maxDepth = 3
	}

	return &DynamicCrawler{
		config:           config,
		callback:         callback,
		session:          activeSession,
		contextProvider:  provider,
		allowedHost:      host,
		seenFingerprints: map[string]struct{}{},
		seenURLs:         map[string]struct{}{},
		pending:          map[network.RequestID]*pendingNetworkRequest{},
		maxPages:         maxPages,
		maxDepth:         maxDepth,
		workerPool:       make(chan struct{}, 5),
	}, nil
}

// Start launches the headless browser and initializes the crawler.
func (c *DynamicCrawler) Start(ctx context.Context) error {
	if c.contextProvider == nil {
		return fmt.Errorf("dynamic crawler requires a browser context provider")
	}
	var state *sessionmgr.State
	var err error
	if c.session != nil {
		state, err = c.session.State(ctx)
		if err != nil {
			return fmt.Errorf("load supplied session: %w", err)
		}
	}
	handle, err := c.contextProvider.NewContext(ctx, state)
	if err != nil {
		return err
	}
	c.contextHandle = handle
	c.browserCtx = handle.Context()
	c.sessionState = state
	return nil
}

// canonicalizeURL removes trailing slash for dedup purposes.
func (c *DynamicCrawler) canonicalizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	// Remove trailing slash
	path := u.Path
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		u.Path = path[:len(path)-1]
	}
	u.Fragment = ""
	return u.String()
}

// IsInScope checks if a URL should be crawled.
func (c *DynamicCrawler) IsInScope(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	pathNoQuery := strings.ToLower(strings.SplitN(u.Path, "?", 2)[0])
	for _, ext := range noiseExtensions {
		if strings.HasSuffix(pathNoQuery, ext) {
			return false
		}
	}
	if c.config.StayInDomain {
		return u.Host == c.allowedHost
	}
	return true
}

// normalizeCrawlURL normalizes a URL for crawling queue dedup.
func (c *DynamicCrawler) normalizeCrawlURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.RawQuery = ""
	u.Fragment = ""
	// Remove trailing slash
	path := u.Path
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		u.Path = path[:len(path)-1]
	}
	return u.String()
}

// domSnapshot represents the live DOM state.
type domSnapshot struct {
	Links []struct {
		Href string `json:"href"`
	} `json:"links"`
	Forms []struct {
		Action  string                   `json:"action"`
		Method  string                   `json:"method"`
		Enctype string                   `json:"enctype"`
		ID      string                   `json:"id"`
		Name    string                   `json:"name"`
		Class   string                   `json:"class"`
		Fields  []map[string]interface{} `json:"fields"`
	} `json:"forms"`
	JSONForms []struct {
		Action  string                   `json:"action"`
		Method  string                   `json:"method"`
		Enctype string                   `json:"enctype"`
		Fields  []map[string]interface{} `json:"fields"`
		IsJSON  bool                     `json:"isJSON"`
	} `json:"jsonForms"`
	JSONEndpoints []struct {
		URL    string `json:"url"`
		Method string `json:"method"`
		Format string `json:"format"`
		Body   string `json:"body"`
	} `json:"jsonEndpoints"`
	Standalone  []map[string]interface{} `json:"standalone"`
	ShadowHosts []struct {
		Selector string                   `json:"selector"`
		Elements []map[string]interface{} `json:"elements"`
	} `json:"shadowHosts"`
	Scripts  []string `json:"scripts"`
	APICalls []struct {
		URL    string `json:"url"`
		Method string `json:"method"`
	} `json:"apiCalls"`
}

// domExtractionJS extracts DOM information including JSON forms and API calls.
const domExtractionJS = `
(function() {
  function fieldsOf(root) {
    return Array.from(root.querySelectorAll('input, select, textarea')).map(function(el) {
      return {
        name: el.getAttribute('name') || '',
        type: (el.tagName === 'SELECT' ? 'select' : (el.tagName === 'TEXTAREA' ? 'textarea' : (el.getAttribute('type') || 'text'))),
        placeholder: el.getAttribute('placeholder') || '',
        required: el.hasAttribute('required'),
        value: el.value || '',
        id: el.getAttribute('id') || '',
        class_name: el.getAttribute('class') || '',
        autocomplete: el.getAttribute('autocomplete') || '',
        readonly: el.hasAttribute('readonly'),
        disabled: el.hasAttribute('disabled'),
        checked: !!el.checked,
        'data-json': el.dataset.json || false,
        min: el.hasAttribute('min') ? el.getAttribute('min') : null,
        max: el.hasAttribute('max') ? el.getAttribute('max') : null,
        minlength: el.hasAttribute('minlength') ? el.getAttribute('minlength') : null,
        maxlength: el.hasAttribute('maxlength') ? el.getAttribute('maxlength') : null,
        pattern: el.getAttribute('pattern') || '',
        step: el.hasAttribute('step') ? el.getAttribute('step') : null,
        accept: el.getAttribute('accept') || '',
        multiple: el.hasAttribute('multiple'),
        autofocus: el.hasAttribute('autofocus')
      };
    });
  }
  
  // Get all links
  var links = Array.from(document.querySelectorAll('a[href]')).map(function(a){
    return { href: a.getAttribute('href') ? a.href : '' };
  }).filter(function(l){ return l.href; });

  // Get all forms
  var forms = Array.from(document.querySelectorAll('form')).map(function(f){
    var actionAttr = f.getAttribute('action') || '';
    return {
      action: actionAttr ? new URL(actionAttr, location.href).href : location.href,
      method: (f.getAttribute('method') || 'get').toUpperCase(),
      enctype: f.getAttribute('enctype') || 'application/x-www-form-urlencoded',
      id: f.getAttribute('id') || '',
      name: f.getAttribute('name') || '',
      class: f.getAttribute('class') || '',
      fields: fieldsOf(f)
    };
  });

  // Detect JSON forms
  var jsonForms = [];
  document.querySelectorAll('form').forEach(function(f) {
    var enctype = f.getAttribute('enctype') || '';
    var isJSON = enctype === 'application/json' || 
                 f.dataset.json === 'true' ||
                 f.hasAttribute('data-json-payload') ||
                 f.getAttribute('data-submit-json') === 'true';
    
    if (isJSON) {
      jsonForms.push({
        action: f.action || location.href,
        method: f.method || 'POST',
        enctype: 'application/json',
        fields: fieldsOf(f),
        isJSON: true
      });
    }
  });

  // Get standalone inputs
  var formEls = new Set(Array.from(document.querySelectorAll('form input, form select, form textarea')));
  var standalone = Array.from(document.querySelectorAll('input, select, textarea'))
    .filter(function(el){ return !formEls.has(el); })
    .map(function(el){ return fieldsOf({querySelectorAll: function(){ return [el]; }})[0]; });

  // Get shadow DOM forms
  var shadowHosts = [];
  document.querySelectorAll('*').forEach(function(el){
    if (el.shadowRoot) {
      shadowHosts.push({
        selector: el.tagName.toLowerCase() + (el.getAttribute('id') ? '#' + el.getAttribute('id') : ''),
        elements: Array.from(el.shadowRoot.querySelectorAll('form')).map(function(f){
          var actionAttr = f.getAttribute('action') || '';
          return {
            tagName: 'form',
            action: actionAttr ? new URL(actionAttr, location.href).href : location.href,
            method: (f.getAttribute('method') || 'get').toUpperCase(),
            fields: fieldsOf(f)
          };
        })
      });
    }
  });

  // Get script sources
  var scripts = Array.from(document.querySelectorAll('script[src]')).map(function(s){ return s.src; });
  
  // Extract API calls from inline scripts
  var apiCalls = [];
  var jsonEndpoints = [];
  var allScripts = document.querySelectorAll('script:not([src])');
  allScripts.forEach(function(script) {
    var content = script.textContent || '';
    
    // Fetch with JSON detection
    var fetchMatches = content.match(/fetch\s*\(\s*['"]([^'"]+)['"]\s*,\s*\{[^}]*['"]Content-Type['"]\s*:\s*['"]application\/json['"]/g) || [];
    fetchMatches.forEach(function(match) {
      var urlMatch = match.match(/fetch\s*\(\s*['"]([^'"]+)['"]/);
      var bodyMatch = match.match(/body\s*:\s*(?:JSON\.stringify\()?({[^}]+})/);
      if (urlMatch) {
        jsonEndpoints.push({
          url: urlMatch[1],
          method: 'POST',
          format: 'json',
          body: bodyMatch ? bodyMatch[1] : null
        });
        apiCalls.push({ url: urlMatch[1], method: 'POST' });
      }
    });
    
    // Axios with JSON
    var axiosMatches = content.match(/axios\.(post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]\s*,\s*({[^}]+})/g) || [];
    axiosMatches.forEach(function(match) {
      var methodMatch = match.match(/axios\.(post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]/);
      var bodyMatch = match.match(/axios\.(post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]\s*,\s*({[^}]+})/);
      if (methodMatch && bodyMatch) {
        jsonEndpoints.push({
          url: methodMatch[2],
          method: methodMatch[1].toUpperCase(),
          format: 'json',
          body: bodyMatch[2]
        });
        apiCalls.push({ url: methodMatch[2], method: methodMatch[1].toUpperCase() });
      }
    });
    
    // Regular fetch calls
    var fetchAllMatches = content.match(/fetch\s*\(\s*['"]([^'"]+)['"]/g) || [];
    fetchAllMatches.forEach(function(match) {
      var urlMatch = match.match(/fetch\s*\(\s*['"]([^'"]+)['"]/);
      if (urlMatch) {
        apiCalls.push({ url: urlMatch[1], method: 'GET' });
      }
    });
    
    // XMLHttpRequest
    var xhrMatches = content.match(/new\s+XMLHttpRequest\s*\(\)/g) || [];
    xhrMatches.forEach(function() {
      var openMatch = content.match(/\.open\s*\(\s*['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]/);
      if (openMatch) {
        apiCalls.push({ url: openMatch[2], method: openMatch[1].toUpperCase() });
      }
    });
  });

  return JSON.stringify({ 
    links: links, 
    forms: forms,
    jsonForms: jsonForms,
    jsonEndpoints: jsonEndpoints,
    standalone: standalone, 
    shadowHosts: shadowHosts, 
    scripts: scripts,
    apiCalls: apiCalls
  });
})()
`

// buildJSONPayloadFromForm builds a JSON payload from form fields
func buildJSONPayloadFromForm(fields []map[string]interface{}) (string, map[string]interface{}) {
	payload := make(map[string]interface{})

	for _, field := range fields {
		name := strOr(field["name"])
		if name == "" {
			continue
		}

		fieldType := strOr(field["type"])
		value := GetSmartValue(field, nil)

		// Convert based on field type
		switch fieldType {
		case "number", "range":
			if val, err := strconv.ParseFloat(value, 64); err == nil {
				payload[name] = val
			} else {
				payload[name] = value
			}
		case "checkbox":
			payload[name] = strOr(field["checked"]) == "true"
		case "select":
			if strings.Contains(strOr(field["multiple"]), "multiple") {
				payload[name] = []string{value}
			} else {
				payload[name] = value
			}
		case "email":
			payload[name] = value
		default:
			payload[name] = value
		}
	}

	jsonBytes, _ := json.Marshal(payload)
	return string(jsonBytes), payload
}

// getDataFormat determines the data format of the form
func getDataFormat(isJSON bool, enctype string) string {
	if isJSON {
		return "json"
	}
	if strings.Contains(enctype, "multipart") {
		return "multipart"
	}
	return "urlencoded"
}

// encodeForm encodes form data as URL-encoded string
func encodeForm(data map[string]string) string {
	values := url.Values{}
	for k, v := range data {
		values.Set(k, v)
	}
	return values.Encode()
}

// CrawlURL crawls a single URL and returns discovered links.
func (c *DynamicCrawler) CrawlURL(ctx context.Context, targetURL string, depth int) []string {
	var next []string
	seenPaths := map[string]struct{}{}

	c.sessionMu.RLock()
	expired := c.sessionExpired
	c.sessionMu.RUnlock()
	if c.session != nil && expired {
		if err := c.refreshSession(ctx); err != nil {
			c.callback(nil, fmt.Errorf("refreshing supplied session: %w", err))
			return next
		}
	}

	// Use worker pool
	select {
	case c.workerPool <- struct{}{}:
		defer func() { <-c.workerPool }()
	default:
		return next
	}

	// Check limits
	c.mu.Lock()
	if c.visitedCount >= c.maxPages {
		c.mu.Unlock()
		return next
	}
	c.visitedCount++
	c.mu.Unlock()

	log.Printf("[%d/%d] Crawling depth %d: %s", c.visitedCount, c.maxPages, depth, targetURL)

	navCtx, cancel := context.WithTimeout(c.browserCtx, c.config.RequestTimeout)
	defer cancel()

	// Listen for network events
	chromedp.ListenTarget(navCtx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			c.trackRequest(navCtx, e, depth)
		case *network.EventRequestWillBeSentExtraInfo:
			c.mergeExtraRequestHeaders(e)
		case *network.EventResponseReceived:
			c.completeRequest(e, depth)
		case *network.EventLoadingFailed:
			c.mu.Lock()
			delete(c.pending, e.RequestID)
			c.mu.Unlock()
		}
	})

	var snapshotJSON string
	err := chromedp.Run(navCtx,
		network.Enable(),
		chromedp.Navigate(targetURL),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Evaluate(domExtractionJS, &snapshotJSON),
	)
	if err != nil {
		c.callback(nil, fmt.Errorf("navigating %s: %w", targetURL, err))
		return next
	}

	var snap domSnapshot
	if err := json.Unmarshal([]byte(snapshotJSON), &snap); err != nil {
		c.callback(nil, fmt.Errorf("parsing DOM snapshot for %s: %w", targetURL, err))
		return next
	}

	// Process JSON endpoints from scripts
	for _, jsonEndpoint := range snap.JSONEndpoints {
		if !c.IsInScope(jsonEndpoint.URL) {
			continue
		}

		var payload map[string]interface{}
		if jsonEndpoint.Body != "" {
			json.Unmarshal([]byte(jsonEndpoint.Body), &payload)
		}

		c.emit(&DiscoveredRequest{
			ID:            CalculateFingerprint(jsonEndpoint.Method, jsonEndpoint.URL, jsonEndpoint.Body, "application/json"),
			URL:           jsonEndpoint.URL,
			Method:        jsonEndpoint.Method,
			SourceType:    "json_api_extract",
			Depth:         depth + 1,
			NormalizedURL: NormalizeURL(jsonEndpoint.URL),
			Parameters:    ExtractParameters(jsonEndpoint.URL, jsonEndpoint.Body, "application/json"),
			JSONFormat: &JSONFormat{
				Payload: payload,
				Raw:     jsonEndpoint.Body,
				IsJSON:  true,
			},
		})
	}

	// Process API calls
	for _, apiCall := range snap.APICalls {
		if !c.IsInScope(apiCall.URL) {
			continue
		}
		c.emit(&DiscoveredRequest{
			ID:            CalculateFingerprint(apiCall.Method, apiCall.URL, "", ""),
			URL:           apiCall.URL,
			Method:        apiCall.Method,
			SourceType:    "js_api_call",
			Depth:         depth + 1,
			NormalizedURL: NormalizeURL(apiCall.URL),
			Parameters:    ExtractParameters(apiCall.URL, "", ""),
		})
	}

	// Process JSON forms (new)
	for _, jsonForm := range snap.JSONForms {
		if !c.IsInScope(jsonForm.Action) {
			continue
		}
		c.processJSONForm(jsonForm, targetURL, depth, seenPaths, &next)
	}

	// Process regular forms
	for _, f := range snap.Forms {
		c.processForm(f, targetURL, depth, seenPaths, &next)
	}

	// Process links
	for _, l := range snap.Links {
		if !c.IsInScope(l.Href) {
			continue
		}
		canonicalURL := c.canonicalizeURL(l.Href)

		c.mu.RLock()
		_, seen := c.seenURLs[canonicalURL]
		c.mu.RUnlock()

		if !seen {
			c.emit(&DiscoveredRequest{
				ID:            CalculateFingerprint("GET", l.Href, "", ""),
				URL:           l.Href,
				Method:        "GET",
				SourceType:    "anchor",
				Depth:         depth + 1,
				NormalizedURL: NormalizeURL(l.Href),
				Parameters:    ExtractParameters(l.Href, "", ""),
			})

			np := c.normalizeCrawlURL(l.Href)
			if _, seenPath := seenPaths[np]; !seenPath && depth+1 <= c.maxDepth {
				seenPaths[np] = struct{}{}
				next = append(next, l.Href)
			}
		}
	}

	// Process standalone inputs
	if len(snap.Standalone) > 0 && c.IsInScope(targetURL) {
		if u, err := url.Parse(targetURL); err == nil {
			q := u.Query()
			formFields := BuildFormFields(snap.Standalone)
			for _, raw := range snap.Standalone {
				if name := strOr(raw["name"]); name != "" {
					q.Set(name, strOr(raw["value"]))
				}
			}
			u.RawQuery = q.Encode()
			inputURL := u.String()
			c.emit(&DiscoveredRequest{
				ID:            CalculateFingerprint("GET", inputURL, "", ""),
				URL:           inputURL,
				Method:        "GET",
				SourceType:    "dom_input",
				Depth:         depth + 1,
				NormalizedURL: NormalizeURL(inputURL),
				FormFields:    formFields,
				Parameters:    ExtractParameters(inputURL, "", ""),
			})
		}
	}

	// Process shadow DOM
	if c.config.ExtractShadowDOM {
		c.processShadowForms(snap.ShadowHosts, targetURL, depth, seenPaths, &next)
	}

	// Analyze JavaScript
	if c.config.AnalyzeHeavyJS {
		c.analyzeScripts(navCtx, snap.Scripts, targetURL, depth)
	}

	return next
}

// processJSONForm processes a JSON form submission
func (c *DynamicCrawler) processJSONForm(f struct {
	Action  string                   `json:"action"`
	Method  string                   `json:"method"`
	Enctype string                   `json:"enctype"`
	Fields  []map[string]interface{} `json:"fields"`
	IsJSON  bool                     `json:"isJSON"`
}, targetURL string, depth int, seenPaths map[string]struct{}, next *[]string) {
	if !c.IsInScope(f.Action) {
		return
	}

	formFields := BuildFormFields(f.Fields)
	csrfField, requiredFields := FormMeta(formFields)

	// Detect form framework from targetURL and fields
	formFramework := DetectFormFramework("", "")

	method := strings.ToUpper(f.Method)
	if method == "" {
		method = "POST"
	}

	action := f.Action

	// Build JSON payload
	jsonBody, jsonPayload := buildJSONPayloadFromForm(f.Fields)

	// Handle nested JSON for registration/login
	if strings.Contains(action, "register") || strings.Contains(action, "signup") {
		wrapped := map[string]interface{}{
			"user":         jsonPayload,
			"organization": jsonPayload,
			"data":         jsonPayload,
		}
		for wrapperName, wrapperData := range wrapped {
			if strings.Contains(action, wrapperName) {
				if jsonBytes, err := json.Marshal(map[string]interface{}{
					wrapperName: wrapperData,
				}); err == nil {
					jsonBody = string(jsonBytes)
					break
				}
			}
		}
	}

	// Handle login forms
	if strings.Contains(action, "login") || strings.Contains(action, "signin") {
		loginPayload := map[string]interface{}{}
		for _, field := range f.Fields {
			name := strOr(field["name"])
			if name != "" {
				loginPayload[name] = GetSmartValue(field, nil)
			}
		}
		if jsonBytes, err := json.Marshal(loginPayload); err == nil {
			jsonBody = string(jsonBytes)
		}
	}

	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}

	params := ExtractParameters(action, jsonBody, "application/json")

	formType := ClassifyForm(f.Fields, targetURL)

	// Parse content type info
	contentTypeInfo := DetectContentType("application/json")

	c.emit(&DiscoveredRequest{
		ID:            CalculateFingerprint(method, action, jsonBody, "application/json"),
		URL:           action,
		Method:        method,
		Headers:       headers,
		Body:          jsonBody,
		SourceType:    "json_form_submit",
		Depth:         depth + 1,
		NormalizedURL: NormalizeURL(action),
		FormFields:    formFields,
		Parameters:    params,
		JSONFormat: &JSONFormat{
			Payload: jsonPayload,
			Raw:     jsonBody,
			IsJSON:  true,
		},
		Form: &Form{
			Action:         action,
			Method:         method,
			Fields:         formFields,
			SourceURL:      targetURL,
			FormType:       formType,
			CSRFTokenField: csrfField,
			RequiredFields: requiredFields,
			DataFormat:     "json",
			Framework:      formFramework,
			APIMapping: &APIMapping{
				PageURL:     targetURL,
				APIMethod:   method,
				APIEndpoint: action,
				BodyFormat:  "json",
			},
		},
		ContentTypeInfo: &contentTypeInfo,
	})
}

// processForm processes a regular form.
func (c *DynamicCrawler) processForm(f struct {
	Action  string                   `json:"action"`
	Method  string                   `json:"method"`
	Enctype string                   `json:"enctype"`
	ID      string                   `json:"id"`
	Name    string                   `json:"name"`
	Class   string                   `json:"class"`
	Fields  []map[string]interface{} `json:"fields"`
}, targetURL string, depth int, seenPaths map[string]struct{}, next *[]string) {
	if !c.IsInScope(f.Action) {
		return
	}

	formType := ClassifyForm(f.Fields, targetURL)
	formFields := BuildFormFields(f.Fields)
	csrfField, requiredFields := FormMeta(formFields)

	// Detect form framework
	formFramework := DetectFormFramework("", "")

	formData := map[string]string{}
	for _, raw := range f.Fields {
		if name := strOr(raw["name"]); name != "" {
			formData[name] = GetSmartValue(raw, nil)
		}
	}

	method := strings.ToUpper(f.Method)
	action := f.Action
	headers := map[string]string{}
	var body string

	if method == "POST" {
		headers["Content-Type"] = f.Enctype
		if strings.Contains(f.Enctype, "urlencoded") || f.Enctype == "" {
			body = encodeForm(formData)
		} else {
			body = "[Multipart Form Data]"
		}
	} else {
		method = "GET"
		if u, err := url.Parse(action); err == nil {
			q := u.Query()
			for k, v := range formData {
				q.Set(k, v)
			}
			u.RawQuery = q.Encode()
			action = u.String()
		}
	}
	contentType := headers["Content-Type"]

	params := ExtractParameters(action, body, contentType)

	// Parse content type info
	contentTypeInfo := DetectContentType(contentType)

	c.emit(&DiscoveredRequest{
		ID:            CalculateFingerprint(method, action, body, contentType),
		URL:           action,
		Method:        method,
		Headers:       headers,
		Body:          body,
		SourceType:    "form_submit",
		Depth:         depth + 1,
		NormalizedURL: NormalizeURL(action),
		FormFields:    formFields,
		Parameters:    params,
		Form: &Form{
			Action:         action,
			Method:         method,
			Fields:         formFields,
			SourceURL:      targetURL,
			FormType:       formType,
			ID:             f.ID,
			Name:           f.Name,
			ClassName:      f.Class,
			Enctype:        f.Enctype,
			CSRFTokenField: csrfField,
			RequiredFields: requiredFields,
			DataFormat:     getDataFormat(false, f.Enctype),
			Framework:      formFramework,
			APIMapping: &APIMapping{
				PageURL:     targetURL,
				APIMethod:   method,
				APIEndpoint: action,
				BodyFormat:  getDataFormat(false, f.Enctype),
			},
		},
		ContentTypeInfo: &contentTypeInfo,
	})

	if method == "GET" && SafeToRequeueAsGET[formType] {
		np := c.normalizeCrawlURL(action)
		if _, seen := seenPaths[np]; !seen && depth+1 <= c.maxDepth {
			seenPaths[np] = struct{}{}
			*next = append(*next, action)
		}
	}
}

// processShadowForms processes shadow DOM forms.
func (c *DynamicCrawler) processShadowForms(hosts []struct {
	Selector string                   `json:"selector"`
	Elements []map[string]interface{} `json:"elements"`
}, targetURL string, depth int, seenPaths map[string]struct{}, next *[]string) {
	for _, host := range hosts {
		for _, el := range host.Elements {
			action := strOr(el["action"])
			if action == "" {
				action = targetURL
			}
			if !c.IsInScope(action) {
				continue
			}
			method := strings.ToUpper(strOr(el["method"]))
			if method == "" {
				method = "GET"
			}
			var fields []map[string]interface{}
			if fieldsRaw, ok := el["fields"].([]interface{}); ok {
				for _, fr := range fieldsRaw {
					if m, ok := fr.(map[string]interface{}); ok {
						fields = append(fields, m)
					}
				}
			}

			shadowFormType := ClassifyForm(fields, targetURL)
			formFields := BuildFormFields(fields)
			csrfField, requiredFields := FormMeta(formFields)

			formData := map[string]string{}
			for _, f := range fields {
				if name := strOr(f["name"]); name != "" {
					formData[name] = GetSmartValue(f, nil)
				}
			}

			var headers map[string]string
			var body string
			if method == "POST" {
				headers = map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
				body = encodeForm(formData)
			} else if u, err := url.Parse(action); err == nil {
				q := u.Query()
				for k, v := range formData {
					q.Set(k, v)
				}
				u.RawQuery = q.Encode()
				action = u.String()
			}
			contentType := headers["Content-Type"]

			contentTypeInfo := DetectContentType(contentType)

			c.emit(&DiscoveredRequest{
				ID:            CalculateFingerprint(method, action, body, contentType),
				URL:           action,
				Method:        method,
				Headers:       headers,
				Body:          body,
				SourceType:    "shadow_dom_form",
				Depth:         depth + 1,
				NormalizedURL: NormalizeURL(action),
				FormFields:    formFields,
				Parameters:    ExtractParameters(action, body, contentType),
				Form: &Form{
					Action:         action,
					Method:         method,
					Fields:         formFields,
					SourceURL:      targetURL,
					FormType:       shadowFormType,
					CSRFTokenField: csrfField,
					RequiredFields: requiredFields,
					DataFormat:     getDataFormat(false, ""),
				},
				ContentTypeInfo: &contentTypeInfo,
			})

			if method == "GET" && SafeToRequeueAsGET[shadowFormType] {
				np := c.normalizeCrawlURL(action)
				if _, seen := seenPaths[np]; !seen && depth+1 <= c.maxDepth {
					seenPaths[np] = struct{}{}
					*next = append(*next, action)
				}
			}
		}
	}
}

// analyzeScripts extracts endpoints from JavaScript files.
func (c *DynamicCrawler) analyzeScripts(ctx context.Context, scriptURLs []string, baseURL string, depth int) {
	for _, jsURL := range scriptURLs {
		if !c.IsInScope(jsURL) {
			continue
		}
		var body string
		if err := chromedp.Run(ctx, chromedp.EvaluateAsDevTools(
			fmt.Sprintf("fetch(%q).then(r => r.text())", jsURL), &body,
		)); err != nil {
			continue
		}
		if len(body) > c.config.MaxJSSize {
			body = body[:c.config.MaxJSSize]
		}

		for ep, isGraphQL := range ExtractEndpointsFromJS(body) {
			resolved := ResolveJSEndpoint(ep, jsURL, baseURL)
			if !c.IsInScope(resolved) {
				continue
			}
			sourceType := "js_api_extract"
			if isGraphQL {
				sourceType = "js_graphql_endpoint"
			}

			canonical := c.canonicalizeURL(resolved)
			c.mu.RLock()
			_, seen := c.seenURLs[canonical]
			c.mu.RUnlock()

			if !seen {
				c.emit(&DiscoveredRequest{
					ID:            CalculateFingerprint("GET", resolved, "", ""),
					URL:           resolved,
					Method:        "GET",
					SourceType:    sourceType,
					Depth:         depth + 1,
					NormalizedURL: NormalizeURL(resolved),
					Parameters:    ExtractParameters(resolved, "", ""),
				})
			}
		}

		if c.config.ExtractSPARoutes {
			for _, route := range ExtractSPARoutesFromJS(body) {
				resolved := ResolveJSEndpoint(route, jsURL, baseURL)
				if !c.IsInScope(resolved) {
					continue
				}
				canonical := c.canonicalizeURL(resolved)
				c.mu.RLock()
				_, seen := c.seenURLs[canonical]
				c.mu.RUnlock()

				if !seen {
					c.emit(&DiscoveredRequest{
						ID:            CalculateFingerprint("GET", resolved, "", ""),
						URL:           resolved,
						Method:        "GET",
						SourceType:    "js_spa_route",
						Depth:         depth + 1,
						NormalizedURL: NormalizeURL(resolved),
						SPARoute: &SPARoute{
							Path:       route,
							SourceFile: jsURL,
							Depth:      depth + 1,
						},
					})
				}
			}
		}
	}
}

// trackRequest stashes an in-flight request with enhanced fetch/XHR detection.
func (c *DynamicCrawler) trackRequest(ctx context.Context, e *network.EventRequestWillBeSent, depth int) {
	if !c.IsInScope(e.Request.URL) {
		return
	}

	headers := map[string]string{}
	for k, v := range e.Request.Headers {
		if s, ok := v.(string); ok {
			headers[k] = s
		}
	}
	if HeaderValue(headers, "Referer") == "" && e.DocumentURL != "" {
		headers["Referer"] = e.DocumentURL
	}
	if HeaderValue(headers, "Origin") == "" && e.DocumentURL != "" {
		headers["Origin"] = originOf(e.DocumentURL)
	}
	c.enrichAuthenticatedHeaders(headers)

	reqDepth := depth + 1
	isDoc := e.Type == network.ResourceTypeDocument
	if isDoc {
		reqDepth = depth
	}

	var postData string
	if e.Request.HasPostData {
		var body strings.Builder
		for _, entry := range e.Request.PostDataEntries {
			if entry != nil {
				body.WriteString(entry.Bytes)
			}
		}
		postData = body.String()
	}

	// Detect content type
	contentType := ""
	if ct, ok := headers["Content-Type"]; ok {
		contentType = strings.ToLower(ct)
	}

	// Detect if this is a fetch/XHR request
	isFetch := strings.Contains(HeaderValue(headers, "X-Requested-With"), "XMLHttpRequest") ||
		strings.Contains(contentType, "application/json") ||
		strings.Contains(HeaderValue(headers, "Accept"), "application/json")

	// Detect initiator
	initiator := "other"
	if e.Initiator != nil {
		if e.Initiator.Type == "script" {
			initiator = "js_script"
		} else if e.Initiator.Type == "parser" {
			initiator = "html_parser"
		}
	}

	// Reconstruct fetch code for debugging/intelligence
	var fetchCode string
	if isFetch && postData != "" {
		var sb strings.Builder
		sb.WriteString("fetch(\"")
		sb.WriteString(e.Request.URL)
		sb.WriteString("\", {\n")
		sb.WriteString("  method: \"")
		sb.WriteString(e.Request.Method)
		sb.WriteString("\",\n")

		if len(headers) > 0 {
			sb.WriteString("  headers: {\n")
			for k, v := range headers {
				sb.WriteString(fmt.Sprintf("    \"%s\": \"%s\",\n", k, v))
			}
			sb.WriteString("  },\n")
		}

		if postData != "" {
			// Try to parse as JSON for pretty display
			var prettyBody string
			var jsonPayload map[string]interface{}
			if err := json.Unmarshal([]byte(postData), &jsonPayload); err == nil {
				pretty, _ := json.MarshalIndent(jsonPayload, "  ", "  ")
				prettyBody = string(pretty)
			} else {
				prettyBody = postData
			}
			sb.WriteString(fmt.Sprintf("  body: %s\n", prettyBody))
		}
		sb.WriteString("})")
		fetchCode = sb.String()
	}

	// Check if this is a JSON request for special handling
	isJSON := strings.Contains(contentType, "application/json") ||
		strings.Contains(contentType, "application/vnd.api+json") ||
		strings.Contains(contentType, "application/graphql")

	if isJSON && postData != "" {
		// Try to parse JSON payload
		var jsonPayload map[string]interface{}
		if err := json.Unmarshal([]byte(postData), &jsonPayload); err == nil {
			// Emit as JSON request
			c.emitJSONRequest(e.Request.URL, e.Request.Method, postData, jsonPayload, depth)
		}
	}

	c.mu.Lock()
	c.pending[e.RequestID] = &pendingNetworkRequest{
		method:      e.Request.Method,
		url:         e.Request.URL,
		headers:     headers,
		body:        postData,
		depth:       reqDepth,
		isDocument:  isDoc,
		resourceTyp: e.Type,
		startTime:   time.Now(),
		isFetch:     isFetch,
		initiator:   initiator,
		fetchCode:   fetchCode,
		contentType: contentType,
	}
	c.mu.Unlock()

	if e.Request.HasPostData && postData == "" {
		go func() {
			var body []byte
			err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
				var err error
				body, err = network.GetRequestPostData(e.RequestID).Do(ctx)
				return err
			}))
			if err != nil || len(body) == 0 {
				return
			}
			c.mu.Lock()
			if pending := c.pending[e.RequestID]; pending != nil {
				pending.body = string(body)
			}
			c.mu.Unlock()
		}()
	}
}

func (c *DynamicCrawler) mergeExtraRequestHeaders(e *network.EventRequestWillBeSentExtraInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pending := c.pending[e.RequestID]
	if pending == nil {
		return
	}
	for key, value := range e.Headers {
		if text, ok := value.(string); ok {
			pending.headers[key] = text
		}
	}
}

// emitJSONRequest emits a JSON API request
func (c *DynamicCrawler) emitJSONRequest(url, method, body string, payload map[string]interface{}, depth int) {
	fingerprint := CalculateFingerprint(method, url, body, "application/json")

	c.mu.RLock()
	_, seen := c.seenFingerprints[fingerprint]
	c.mu.RUnlock()

	if seen {
		return
	}

	contentTypeInfo := DetectContentType("application/json")

	c.emit(&DiscoveredRequest{
		ID:            fingerprint,
		URL:           url,
		Method:        method,
		Headers:       map[string]string{"Content-Type": "application/json"},
		Body:          body,
		SourceType:    "json_api",
		Depth:         depth + 1,
		NormalizedURL: NormalizeURL(url),
		Parameters:    ExtractParameters(url, body, "application/json"),
		JSONFormat: &JSONFormat{
			Payload: payload,
			Raw:     body,
			IsJSON:  true,
		},
		ContentTypeInfo: &contentTypeInfo,
	})
}

// completeRequest merges response information.
func (c *DynamicCrawler) completeRequest(e *network.EventResponseReceived, _ int) {
	c.mu.Lock()
	pendingPtr, ok := c.pending[e.RequestID]
	if !ok {
		c.mu.Unlock()
		return
	}
	pending := *pendingPtr
	delete(c.pending, e.RequestID)
	c.mu.Unlock()

	respHeaders := map[string]string{}
	for k, v := range e.Response.Headers {
		if s, ok := v.(string); ok {
			respHeaders[strings.ToLower(k)] = s
		}
	}

	var setCookies []string
	if sc, ok := respHeaders["set-cookie"]; ok && sc != "" {
		setCookies = strings.Split(sc, "\n")
	}

	contentLength := int64(0)
	if cl, ok := respHeaders["content-length"]; ok {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil {
			contentLength = n
		}
	}

	response := &ResponseMetadata{
		StatusCode:    int(e.Response.Status),
		ContentType:   respHeaders["content-type"],
		ContentLength: contentLength,
		Server:        respHeaders["server"],
		CacheControl:  respHeaders["cache-control"],
		Headers:       respHeaders,
		SetCookies:    setCookies,
	}
	if c.session != nil && (response.StatusCode == 401 || response.StatusCode == 403) {
		c.sessionMu.Lock()
		c.sessionExpired = true
		c.sessionMu.Unlock()
	}

	cookies := parseCookieHeader(HeaderValue(pending.headers, "Cookie"))
	contentType := HeaderValue(pending.headers, "Content-Type")

	sourceType := "ajax_fetch"
	switch {
	case pending.isDocument:
		sourceType = "page"
	case pending.resourceTyp == network.ResourceTypeScript:
		sourceType = "script_src"
	case pending.resourceTyp == network.ResourceTypeXHR, pending.resourceTyp == network.ResourceTypeFetch:
		sourceType = "ajax_fetch"
	case strings.Contains(pending.headers["Accept"], "graphql"):
		sourceType = "graphql"
	}

	fingerprint := CalculateFingerprint(pending.method, pending.url, pending.body, contentType)
	c.mu.RLock()
	_, seen := c.seenFingerprints[fingerprint]
	c.mu.RUnlock()

	if !seen {
		contentTypeInfo := DetectContentType(contentType)

		// Build fetch details if this was a fetch/XHR request
		var fetchDetails *FetchDetails
		if pending.isFetch {
			fetchDetails = &FetchDetails{
				Method:     pending.method,
				URL:        pending.url,
				Headers:    pending.headers,
				Body:       pending.body,
				BodyType:   contentType,
				RawSnippet: pending.fetchCode,
				Initiator:  pending.initiator,
			}
		}

		c.emit(&DiscoveredRequest{
			ID:              fingerprint,
			URL:             pending.url,
			Method:          pending.method,
			Headers:         pending.headers,
			Body:            pending.body,
			BodyType:        bodyTypeFromContentType(contentType),
			SourceType:      sourceType,
			Depth:           pending.depth,
			NormalizedURL:   NormalizeURL(pending.url),
			Parameters:      ExtractParameters(pending.url, pending.body, contentType),
			Cookies:         cookies,
			Response:        response,
			FetchDetails:    fetchDetails,
			ContentTypeInfo: &contentTypeInfo,
			JSONFormat:      ParseJSONFormat(pending.body, contentType),
		})
	}
}

func (c *DynamicCrawler) enrichAuthenticatedHeaders(headers map[string]string) {
	c.sessionMu.RLock()
	defer c.sessionMu.RUnlock()
	if c.sessionState == nil {
		return
	}
	if HeaderValue(headers, "Cookie") == "" {
		if cookieHeader := sessionCookieHeader(c.sessionState); cookieHeader != "" {
			headers["Cookie"] = cookieHeader
		}
	}
	for _, token := range c.sessionState.Tokens {
		if token.Kind == "csrf" && HeaderValue(headers, "X-CSRF-Token") == "" {
			headers["X-CSRF-Token"] = token.Value
			break
		}
	}
	if HeaderValue(headers, "Authorization") == "" {
		for _, token := range c.sessionState.Tokens {
			if token.Kind != "jwt" && token.Kind != "token" {
				continue
			}
			value := token.Value
			if !strings.HasPrefix(strings.ToLower(value), "bearer ") {
				value = "Bearer " + value
			}
			headers["Authorization"] = value
			return
		}
	}
}

func (c *DynamicCrawler) refreshSession(ctx context.Context) error {
	state, err := c.session.Refresh(ctx)
	if err != nil {
		return err
	}
	if err := c.contextHandle.ApplyState(ctx, state); err != nil {
		return err
	}
	c.sessionMu.Lock()
	c.sessionState = state
	c.sessionExpired = false
	c.sessionMu.Unlock()
	return nil
}

func sessionCookieHeader(state *sessionmgr.State) string {
	if state == nil {
		return ""
	}
	parts := make([]string, 0, len(state.Cookies))
	for _, cookie := range state.Cookies {
		if cookie.Name != "" {
			parts = append(parts, cookie.Name+"="+cookie.Value)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func parseCookieHeader(cookieHeader string) map[string]string {
	if cookieHeader == "" {
		return nil
	}
	cookies := map[string]string{}
	for _, pair := range strings.Split(cookieHeader, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		if idx := strings.Index(pair, "="); idx > 0 {
			cookies[pair[:idx]] = pair[idx+1:]
		}
	}
	if len(cookies) == 0 {
		return nil
	}
	return cookies
}

// emit sends a discovered request through the callback after deduplication.
func (c *DynamicCrawler) emit(req *DiscoveredRequest) {
	if c.session != nil {
		if req.Headers == nil {
			req.Headers = map[string]string{}
		}
		c.enrichAuthenticatedHeaders(req.Headers)
		if HeaderValue(req.Headers, "Referer") == "" {
			referer := c.config.SeedURL
			if req.Form != nil && req.Form.SourceURL != "" {
				referer = req.Form.SourceURL
			}
			req.Headers["Referer"] = referer
		}
		if HeaderValue(req.Headers, "Origin") == "" {
			req.Headers["Origin"] = originOf(req.Headers["Referer"])
		}
		if req.Cookies == nil {
			req.Cookies = parseCookieHeader(HeaderValue(req.Headers, "Cookie"))
		}
		req.AuthSessionID = c.session.ID()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, seen := c.seenFingerprints[req.ID]; seen {
		return
	}
	c.seenFingerprints[req.ID] = struct{}{}

	canonical := c.canonicalizeURL(req.URL)
	if _, seen := c.seenURLs[canonical]; !seen {
		c.seenURLs[canonical] = struct{}{}
	}

	req.CreatedAt = time.Now().UTC()
	c.callback(req, nil)
}

// Crawl starts the recursive crawling process from the seed URL.
func (c *DynamicCrawler) Crawl(ctx context.Context) error {
	seedURL := c.config.SeedURL

	// Initialize queue with seed URL at depth 0
	c.queueMu.Lock()
	c.queue = []urlQueueItem{{url: seedURL, depth: 0}}
	c.queueMu.Unlock()

	// Mark seed as seen
	c.mu.Lock()
	c.seenURLs[c.canonicalizeURL(seedURL)] = struct{}{}
	c.mu.Unlock()

	var wg sync.WaitGroup

	// Process queue until empty or max pages reached
	for {
		c.queueMu.Lock()
		if len(c.queue) == 0 {
			c.queueMu.Unlock()
			break
		}

		// Get next item from queue
		item := c.queue[0]
		c.queue = c.queue[1:]
		c.queueMu.Unlock()

		// Check limits
		c.mu.RLock()
		if c.visitedCount >= c.maxPages {
			c.mu.RUnlock()
			break
		}
		c.mu.RUnlock()

		// Check depth limit
		if item.depth > c.maxDepth {
			continue
		}

		wg.Add(1)
		go func(url string, depth int) {
			defer wg.Done()

			// Crawl the URL
			nextURLs := c.CrawlURL(ctx, url, depth)

			// Add discovered URLs to queue with incremented depth
			c.queueMu.Lock()
			for _, nextURL := range nextURLs {
				canonical := c.canonicalizeURL(nextURL)
				c.mu.RLock()
				_, seen := c.seenURLs[canonical]
				c.mu.RUnlock()

				if !seen {
					c.mu.Lock()
					c.seenURLs[canonical] = struct{}{}
					c.mu.Unlock()
					c.queue = append(c.queue, urlQueueItem{url: nextURL, depth: depth + 1})
				}
			}
			c.queueMu.Unlock()
		}(item.url, item.depth)

		// Small delay to prevent overwhelming
		time.Sleep(100 * time.Millisecond)
	}

	wg.Wait()
	return nil
}

func (c *DynamicCrawler) Close() {
	if c.contextHandle != nil {
		_ = c.contextHandle.Close()
		c.contextHandle = nil
	}
}

// Add to completeRequest function - extract all headers
func extractRequestHeaders(headers map[string]string) RequestHeaders {
	reqHeaders := RequestHeaders{
		Raw:    headers,
		Custom: make(map[string]string),
	}

	for k, v := range headers {
		lowerK := strings.ToLower(k)
		switch lowerK {
		case "authorization":
			reqHeaders.Authorization = v
		case "cookie":
			reqHeaders.Cookie = v
		case "x-csrf-token", "x-xsrf-token", "csrf-token":
			reqHeaders.CSRF = v
		case "x-requested-with":
			reqHeaders.XRequestedWith = v
		case "origin":
			reqHeaders.Origin = v
		case "referer":
			reqHeaders.Referer = v
		case "host":
			reqHeaders.Host = v
		case "user-agent":
			reqHeaders.UserAgent = v
		case "accept":
			reqHeaders.Accept = v
		case "accept-language":
			reqHeaders.AcceptLanguage = v
		case "accept-encoding":
			reqHeaders.AcceptEncoding = v
		case "content-type":
			reqHeaders.ContentType = v
		case "content-length":
			reqHeaders.ContentLength = v
		case "content-encoding":
			reqHeaders.ContentEncoding = v
		case "cache-control":
			reqHeaders.CacheControl = v
		case "pragma":
			reqHeaders.Pragma = v
		case "connection":
			reqHeaders.Connection = v
		case "upgrade":
			reqHeaders.Upgrade = v
		default:
			reqHeaders.Custom[lowerK] = v
		}
	}

	return reqHeaders
}

// Add to dynamic.go
func parseCookieHeaderWithAttributes(cookieHeader string) []CookieInfo {
	var cookies []CookieInfo

	// Parse Set-Cookie header with attributes
	parts := strings.Split(cookieHeader, ";")
	if len(parts) == 0 {
		return cookies
	}

	// First part is name=value
	nameValue := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
	if len(nameValue) != 2 {
		return cookies
	}

	cookie := CookieInfo{
		Name:  nameValue[0],
		Value: nameValue[1],
	}

	// Parse attributes
	for i := 1; i < len(parts); i++ {
		attr := strings.TrimSpace(parts[i])
		attrLower := strings.ToLower(attr)

		switch {
		case strings.HasPrefix(attrLower, "domain="):
			cookie.Domain = strings.TrimPrefix(attr, "Domain=")
		case strings.HasPrefix(attrLower, "path="):
			cookie.Path = strings.TrimPrefix(attr, "Path=")
		case strings.HasPrefix(attrLower, "expires="):
			expires, _ := time.Parse(time.RFC1123, strings.TrimPrefix(attr, "Expires="))
			cookie.Expires = expires
		case strings.HasPrefix(attrLower, "max-age="):
			maxAge, _ := strconv.Atoi(strings.TrimPrefix(attr, "Max-Age="))
			cookie.MaxAge = maxAge
		case attrLower == "httponly":
			cookie.HttpOnly = true
		case attrLower == "secure":
			cookie.Secure = true
		case strings.HasPrefix(attrLower, "samesite="):
			cookie.SameSite = strings.TrimPrefix(attr, "SameSite=")
		}
	}

	cookies = append(cookies, cookie)
	return cookies
}

// ExtractRequestHeaders extracts all headers from a request
func ExtractRequestHeaders(headers map[string]string) RequestHeaders {
	reqHeaders := RequestHeaders{
		Raw:    headers,
		Custom: make(map[string]string),
	}

	for k, v := range headers {
		lowerK := strings.ToLower(k)
		switch lowerK {
		case "authorization":
			reqHeaders.Authorization = v
		case "cookie":
			reqHeaders.Cookie = v
		case "x-csrf-token", "x-xsrf-token", "csrf-token":
			reqHeaders.CSRF = v
		case "x-xsrftoken", "xsrf-token":
			reqHeaders.XSRFToken = v
		case "x-requested-with":
			reqHeaders.XRequestedWith = v
		case "origin":
			reqHeaders.Origin = v
		case "referer":
			reqHeaders.Referer = v
		case "host":
			reqHeaders.Host = v
		case "user-agent":
			reqHeaders.UserAgent = v
		case "accept":
			reqHeaders.Accept = v
		case "accept-language":
			reqHeaders.AcceptLanguage = v
		case "accept-encoding":
			reqHeaders.AcceptEncoding = v
		case "content-type":
			reqHeaders.ContentType = v
		case "content-length":
			reqHeaders.ContentLength = v
		case "content-encoding":
			reqHeaders.ContentEncoding = v
		case "cache-control":
			reqHeaders.CacheControl = v
		case "pragma":
			reqHeaders.Pragma = v
		case "connection":
			reqHeaders.Connection = v
		case "upgrade":
			reqHeaders.Upgrade = v
		default:
			reqHeaders.Custom[lowerK] = v
		}
	}

	return reqHeaders
}

// ParseCookies parses cookie header with attributes
func ParseCookies(cookieHeader string) []CookieInfo {
	var cookies []CookieInfo

	if cookieHeader == "" {
		return cookies
	}

	parts := strings.Split(cookieHeader, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Parse name=value
		nv := strings.SplitN(part, "=", 2)
		if len(nv) != 2 {
			continue
		}

		cookie := CookieInfo{
			Name:  strings.TrimSpace(nv[0]),
			Value: strings.TrimSpace(nv[1]),
		}

		// Check for attributes (if this is a Set-Cookie header)
		if len(parts) > 1 {
			// Parse attributes
			for _, attr := range parts[1:] {
				attr = strings.TrimSpace(attr)
				attrLower := strings.ToLower(attr)

				switch {
				case strings.HasPrefix(attrLower, "domain="):
					cookie.Domain = strings.TrimPrefix(attr, "Domain=")
				case strings.HasPrefix(attrLower, "path="):
					cookie.Path = strings.TrimPrefix(attr, "Path=")
				case strings.HasPrefix(attrLower, "expires="):
					expires, _ := time.Parse(time.RFC1123, strings.TrimPrefix(attr, "Expires="))
					cookie.Expires = expires
				case strings.HasPrefix(attrLower, "max-age="):
					maxAge, _ := strconv.Atoi(strings.TrimPrefix(attr, "Max-Age="))
					cookie.MaxAge = maxAge
				case attrLower == "httponly":
					cookie.HttpOnly = true
				case attrLower == "secure":
					cookie.Secure = true
				case strings.HasPrefix(attrLower, "samesite="):
					cookie.SameSite = strings.TrimPrefix(attr, "SameSite=")
				}
			}
		}

		cookies = append(cookies, cookie)
	}

	return cookies
}

// DetectGraphQL detects GraphQL endpoints
func DetectGraphQL(response *ResponseMetadata, body string) bool {
	if response == nil {
		return false
	}

	// Check content type
	if strings.Contains(response.ContentType, "application/graphql") {
		return true
	}

	// Check for GraphQL keywords in body
	if strings.Contains(body, `"query"`) ||
		strings.Contains(body, `"mutation"`) ||
		strings.Contains(body, `"variables"`) ||
		strings.Contains(body, "graphql") {
		return true
	}

	return false
}

// ExtractGraphQLIntrospection extracts GraphQL schema via introspection
func ExtractGraphQLIntrospection(ctx context.Context, url string) (string, error) {
	query := `query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                kind
                name
                description
                fields {
                    name
                    type {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                            }
                        }
                    }
                }
            }
        }
    }`

	// Send introspection query
	req, _ := http.NewRequestWithContext(ctx, "POST", url,
		strings.NewReader(fmt.Sprintf(`{"query": "%s"}`, query)))
	req.Header.Set("Content-Type", "application/json")

	// Execute request...
	// Return schema
	return "", nil
}
