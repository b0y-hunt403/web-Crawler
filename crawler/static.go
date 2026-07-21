// crawler/static.go
package crawler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// StaticCrawler does fast, JS-free crawling via plain HTTP GET + HTML parsing
type StaticCrawler struct {
	config CrawlerConfig
	client *http.Client
	store  *RequestStore
}

func NewStaticCrawler(config CrawlerConfig, client *http.Client, store *RequestStore) *StaticCrawler {
	if client == nil {
		client = &http.Client{Timeout: config.RequestTimeout}
	}
	return &StaticCrawler{config: config, client: client, store: store}
}

func (c *StaticCrawler) allowedHost() string {
	u, err := url.Parse(c.config.SeedURL)
	if err != nil {
		return ""
	}
	return u.Host
}

var staticNoiseExtensions = []string{
	".css", ".png", ".jpg", ".jpeg", ".svg", ".gif",
	".woff", ".woff2", ".ico", ".webp", ".mp4", ".mp3",
	".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip",
	".tar", ".gz", ".rar", ".7z",
}

func (c *StaticCrawler) IsInScope(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	pathNoQuery := strings.ToLower(strings.SplitN(u.Path, "?", 2)[0])
	for _, ext := range staticNoiseExtensions {
		if strings.HasSuffix(pathNoQuery, ext) {
			return false
		}
	}
	if c.config.StayInDomain {
		return u.Host == c.allowedHost()
	}
	return true
}

func (c *StaticCrawler) normalizeCrawlURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

type fetchResult struct {
	html     string
	response *ResponseMetadata
}

func (c *StaticCrawler) fetch(ctx context.Context, rawURL string) (*fetchResult, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("User-Agent", c.config.UserAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()

	meta := responseMetadataFromHTTP(resp)

	if resp.StatusCode == http.StatusNotFound {
		if c.store != nil {
			_ = c.store.DeleteRequestByURL(rawURL)
		}
		return &fetchResult{response: meta}, false
	}

	isHTML := strings.Contains(resp.Header.Get("Content-Type"), "text/html")
	if resp.StatusCode != http.StatusOK || !isHTML {
		return &fetchResult{response: meta}, false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &fetchResult{response: meta}, false
	}
	return &fetchResult{html: string(body), response: meta}, true
}

func responseMetadataFromHTTP(resp *http.Response) *ResponseMetadata {
	headers := map[string]string{}
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}
	return &ResponseMetadata{
		StatusCode:    resp.StatusCode,
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: resp.ContentLength,
		Server:        resp.Header.Get("Server"),
		CacheControl:  resp.Header.Get("Cache-Control"),
		Headers:       headers,
		SetCookies:    resp.Header.Values("Set-Cookie"),
	}
}

type extractedLink struct {
	url        string
	sourceType string
}

func (c *StaticCrawler) ExtractLinks(html, baseURL string) []extractedLink {
	var links []extractedLink
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return links
	}
	base, _ := url.Parse(baseURL)

	doc.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
		href := strings.TrimSpace(getAttrOr(s, "href", ""))
		if href == "" || strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "mailto:") || strings.HasPrefix(href, "tel:") {
			return
		}
		if abs := resolveAgainst(base, href); abs != "" {
			links = append(links, extractedLink{abs, "anchor"})
		}
	})
	doc.Find("script[src]").Each(func(_ int, s *goquery.Selection) {
		if src := strings.TrimSpace(getAttrOr(s, "src", "")); src != "" {
			if abs := resolveAgainst(base, src); abs != "" {
				links = append(links, extractedLink{abs, "script_src"})
			}
		}
	})
	doc.Find("iframe[src]").Each(func(_ int, s *goquery.Selection) {
		if src := strings.TrimSpace(getAttrOr(s, "src", "")); src != "" {
			if abs := resolveAgainst(base, src); abs != "" {
				links = append(links, extractedLink{abs, "iframe_src"})
			}
		}
	})
	return links
}

func resolveAgainst(base *url.URL, ref string) string {
	if base == nil {
		return ref
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return base.ResolveReference(r).String()
}

type extractedForm struct {
	actionURL          string
	hasExplicitMethod  bool
	explicitMethod     string
	hasExplicitEnctype bool
	explicitEnctype    string
	fields             []map[string]interface{}
	meta               map[string]interface{}
}

func (c *StaticCrawler) ExtractForms(html, baseURL string) []extractedForm {
	var forms []extractedForm
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return forms
	}
	base, _ := url.Parse(baseURL)

	doc.Find("form").Each(func(_ int, form *goquery.Selection) {
		action := getAttrOr(form, "action", "")
		actionURL := baseURL
		if strings.TrimSpace(action) != "" {
			actionURL = resolveAgainst(base, action)
		}
		methodAttr, hasMethod := form.Attr("method")
		enctypeAttr, hasEnctype := form.Attr("enctype")
		formID := getAttrOr(form, "id", "")
		formName := getAttrOr(form, "name", "")
		formClass := getAttrOr(form, "class", "")

		var rawFields []map[string]interface{}
		form.Find("input, select, textarea").Each(func(_ int, el *goquery.Selection) {
			rawFields = append(rawFields, fieldToMap(el))
		})

		formType := ClassifyForm(rawFields, baseURL)

		forms = append(forms, extractedForm{
			actionURL:          actionURL,
			hasExplicitMethod:  hasMethod,
			explicitMethod:     strings.ToUpper(strings.TrimSpace(methodAttr)),
			hasExplicitEnctype: hasEnctype,
			explicitEnctype:    enctypeAttr,
			fields:             rawFields,
			meta: map[string]interface{}{
				"id": formID, "name": formName, "class": formClass, "form_type": formType,
				"isJSON": strings.Contains(enctypeAttr, "application/json"),
			},
		})
	})

	return forms
}

func getAttrOr(s *goquery.Selection, attr, def string) string {
	if v, ok := s.Attr(attr); ok {
		return v
	}
	return def
}

func fieldToMap(el *goquery.Selection) map[string]interface{} {
	tag := goquery.NodeName(el)
	fieldType := getAttrOr(el, "type", "text")
	if tag == "select" {
		fieldType = "select"
	} else if tag == "textarea" {
		fieldType = "textarea"
	}
	_, required := el.Attr("required")
	_, readonly := el.Attr("readonly")
	_, disabled := el.Attr("disabled")
	_, checked := el.Attr("checked")

	minLen, hasMin := el.Attr("minlength")
	maxLen, hasMax := el.Attr("maxlength")

	value := getAttrOr(el, "value", "")
	if tag == "textarea" {
		value = strings.TrimSpace(el.Text())
	}

	var options []string
	if tag == "select" {
		el.Find("option").Each(func(_ int, opt *goquery.Selection) {
			if v, ok := opt.Attr("value"); ok {
				options = append(options, v)
			} else {
				options = append(options, strings.TrimSpace(opt.Text()))
			}
		})
	}

	m := map[string]interface{}{
		"name":         getAttrOr(el, "name", ""),
		"type":         fieldType,
		"placeholder":  getAttrOr(el, "placeholder", ""),
		"required":     required,
		"value":        value,
		"id":           getAttrOr(el, "id", ""),
		"class_name":   getAttrOr(el, "class", ""),
		"autocomplete": getAttrOr(el, "autocomplete", ""),
		"pattern":      getAttrOr(el, "pattern", ""),
		"readonly":     readonly,
		"disabled":     disabled,
		"checked":      checked,
		"options":      options,
	}
	if hasMin {
		if n, err := strconv.Atoi(minLen); err == nil {
			m["min_length"] = n
		}
	}
	if hasMax {
		if n, err := strconv.Atoi(maxLen); err == nil {
			m["max_length"] = n
		}
	}
	return m
}

func encodeFormData(data map[string]string) string {
	v := url.Values{}
	for k, val := range data {
		v.Set(k, val)
	}
	return v.Encode()
}

func mustPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Path
}

func stringOrEmpty(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func mapToFormFieldStatic(raw map[string]interface{}) FormField {
	ftypeStr := stringOrEmpty(raw["type"])
	ftype := FieldType(ftypeStr)
	if ftypeStr == "" {
		ftype = FieldText
	}
	var options []string
	if opts, ok := raw["options"].([]string); ok {
		options = opts
	}
	required, _ := raw["required"].(bool)
	readonly, _ := raw["readonly"].(bool)
	disabled, _ := raw["disabled"].(bool)

	var minLen, maxLen *int
	if n, ok := raw["min_length"].(int); ok {
		minLen = &n
	}
	if n, ok := raw["max_length"].(int); ok {
		maxLen = &n
	}

	return FormField{
		Name:         stringOrEmpty(raw["name"]),
		Type:         ftype,
		Placeholder:  stringOrEmpty(raw["placeholder"]),
		Required:     required,
		Value:        stringOrEmpty(raw["value"]),
		Options:      options,
		ID:           stringOrEmpty(raw["id"]),
		ClassName:    stringOrEmpty(raw["class_name"]),
		Autocomplete: stringOrEmpty(raw["autocomplete"]),
		Pattern:      stringOrEmpty(raw["pattern"]),
		ReadOnly:     readonly,
		Disabled:     disabled,
		MinLength:    minLen,
		MaxLength:    maxLen,
	}
}

// CrawlURL fetches a single page and extracts every link/form on it
func (c *StaticCrawler) CrawlURL(ctx context.Context, rawURL string, depth int, credentials map[string]string) ([]*DiscoveredRequest, []string) {
	var found []*DiscoveredRequest
	var next []string

	if strings.HasSuffix(strings.ToLower(strings.SplitN(mustPath(rawURL), "?", 2)[0]), ".js") {
		return found, next
	}

	result, ok := c.fetch(ctx, rawURL)

	if result != nil {
		contentType := ""
		if result.response != nil {
			contentType = result.response.ContentType
		}
		found = append(found, &DiscoveredRequest{
			ID:            CalculateFingerprint("GET", rawURL, "", contentType),
			URL:           rawURL,
			Method:        "GET",
			SourceType:    "page",
			Depth:         depth,
			NormalizedURL: NormalizeURL(rawURL),
			Parameters:    ExtractParameters(rawURL, "", ""),
			Response:      result.response,
			CreatedAt:     time.Now().UTC(),
		})
	}

	if !ok {
		return found, next
	}
	html := result.html

	seenPaths := map[string]struct{}{}

	for _, link := range c.ExtractLinks(html, rawURL) {
		if !c.IsInScope(link.url) {
			continue
		}
		found = append(found, &DiscoveredRequest{
			ID:            CalculateFingerprint("GET", link.url, "", ""),
			URL:           link.url,
			Method:        "GET",
			SourceType:    link.sourceType,
			Depth:         depth + 1,
			NormalizedURL: NormalizeURL(link.url),
			Parameters:    ExtractParameters(link.url, "", ""),
			CreatedAt:     time.Now().UTC(),
		})

		if link.sourceType == "anchor" || link.sourceType == "iframe_src" {
			np := c.normalizeCrawlURL(link.url)
			lp := strings.ToLower(strings.SplitN(mustPath(link.url), "?", 2)[0])
			if !strings.HasSuffix(lp, ".js") {
				if _, seen := seenPaths[np]; !seen {
					seenPaths[np] = struct{}{}
					next = append(next, link.url)
				}
			}
		}
	}

	for _, f := range c.ExtractForms(html, rawURL) {
		if !c.IsInScope(f.actionURL) {
			continue
		}

		formType, _ := f.meta["form_type"].(FormType)
		formFields := BuildFormFields(f.fields)
		csrfField, requiredFields := FormMeta(formFields)
		containsPassword := hasPasswordField(formFields)

		formData := map[string]string{}
		for _, raw := range f.fields {
			name, _ := raw["name"].(string)
			if name == "" {
				continue
			}
			ftype, _ := raw["type"].(string)
			checked, _ := raw["checked"].(bool)
			if (ftype == "checkbox" || ftype == "radio") && !checked {
				continue
			}
			formData[name] = GetSmartValue(raw, credentials)
		}

		isJSONForm := strings.Contains(f.explicitEnctype, "application/json") || f.meta["isJSON"] == true

		submissions := BuildFormSubmissions(
			f.actionURL, f.hasExplicitMethod, f.hasExplicitEnctype,
			f.explicitMethod, f.explicitEnctype, formData, containsPassword,
		)

		form := &Form{
			Action:         f.actionURL,
			Method:         submissions[0].Method,
			Fields:         formFields,
			SourceURL:      rawURL,
			FormType:       formType,
			Enctype:        f.explicitEnctype,
			ID:             stringOrEmpty(f.meta["id"]),
			Name:           stringOrEmpty(f.meta["name"]),
			ClassName:      stringOrEmpty(f.meta["class"]),
			CSRFTokenField: csrfField,
			RequiredFields: requiredFields,
			DataFormat:     getDataFormat(isJSONForm, f.explicitEnctype), // Uses getDataFormat from dynamic.go
		}

		for _, sub := range submissions {
			contentType := sub.Headers["Content-Type"]

			var jsonPayload map[string]interface{}
			var jsonFormat *JSONFormat
			if sub.BodyType == "json" && sub.Body != "" {
				json.Unmarshal([]byte(sub.Body), &jsonPayload)
				jsonFormat = &JSONFormat{
					Payload: jsonPayload,
					Raw:     sub.Body,
					IsJSON:  true,
				}
			}

			req := &DiscoveredRequest{
				ID:            CalculateFingerprint(sub.Method, sub.URL, sub.Body, contentType),
				URL:           sub.URL,
				Method:        sub.Method,
				Headers:       sub.Headers,
				Body:          sub.Body,
				BodyType:      sub.BodyType,
				SourceType:    "form_submit",
				Depth:         depth + 1,
				NormalizedURL: NormalizeURL(sub.URL),
				FormFields:    formFields,
				Form:          form,
				Parameters:    ExtractParameters(sub.URL, sub.Body, contentType),
				JSONFormat:    jsonFormat,
				CreatedAt:     time.Now().UTC(),
			}
			found = append(found, req)

			if sub.Method == "GET" && SafeToRequeueAsGET[formType] {
				np := c.normalizeCrawlURL(sub.URL)
				if _, seen := seenPaths[np]; !seen {
					seenPaths[np] = struct{}{}
					next = append(next, sub.URL)
				}
			}
		}
	}

	return found, next
}