// crawler/dynamic.go
package crawler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	sessionmgr "github.com/Anduamlk/web-Crawler/session"
	fetchproto "github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/kb"
)

// RequestCallback receives every DiscoveredRequest as it's found.
type RequestCallback func(req *DiscoveredRequest, err error)

// decodeJSONBodyIfBase64 normalizes the representation returned by CDP for
// textual JSON payloads. It only decodes when the original value is not JSON
// and the decoded bytes are valid JSON, avoiding heuristic conversion of
// ordinary request bodies.
func decodeJSONBodyIfBase64(body string) string {
	var payload map[string]interface{}
	if json.Unmarshal([]byte(body), &payload) == nil {
		return body
	}
	decoded, err := base64.StdEncoding.DecodeString(body)
	if err != nil || json.Unmarshal(decoded, &payload) != nil {
		return body
	}
	return string(decoded)
}

// pendingNetworkRequest tracks one in-flight browser network request.
// ENHANCED: Added fetch/XHR tracking fields
type pendingNetworkRequest struct {
	requestID             network.RequestID
	method                string
	url                   string
	headers               map[string]string
	body                  string
	depth                 int
	isDocument            bool
	resourceTyp           network.ResourceType
	startTime             time.Time
	isFetch               bool
	initiator             string
	fetchCode             string
	jsContext             string
	contentType           string
	requestBody           string
	lifecycleState        string
	requestTimestamp      float64
	responseTimestamp     float64
	failureReason         string
	response              *ResponseMetadata
	pageURL               string
	taskID                string
	taskSelector          string
	interactionType       string
	parentWorkflowID      string
	bodyComplete          bool
	bodyCompletenessKnown bool
	requiredFields        []string
}

type cachedScriptBody struct {
	URL, PageURL, ContentType, Hash string
	Body                            string
	CapturedAt                      time.Time
}

type runtimeRequestTrace struct {
	Method, URL, BodyType, Stack, ScriptURL string
	Timestamp                               int64
}

type workflowTaskCategory string
type authSessionState string

const (
	authUnknown          authSessionState = "UNKNOWN"
	authAuthenticating   authSessionState = "AUTHENTICATING"
	authAuthenticated    authSessionState = "AUTHENTICATED"
	authFailed           authSessionState = "AUTH_FAILED"
	authSessionLost      authSessionState = "SESSION_LOST"
	authReauthenticating authSessionState = "REAUTHENTICATING"
)

type workflowTaskStatus string

const (
	workflowForm       workflowTaskCategory = "FORM"
	workflowControl    workflowTaskCategory = "CONTROL"
	workflowNavigation workflowTaskCategory = "NAVIGATION"

	taskDiscovered      workflowTaskStatus = "discovered"
	taskQueued          workflowTaskStatus = "queued"
	taskExecuting       workflowTaskStatus = "executing"
	taskCompleted       workflowTaskStatus = "completed"
	taskFailed          workflowTaskStatus = "failed"
	taskFailedRetryable workflowTaskStatus = "failed_retryable"
	taskFailedFinal     workflowTaskStatus = "failed_final"
	taskSkipped         workflowTaskStatus = "skipped"
	taskInvalidated     workflowTaskStatus = "invalidated_by_navigation"
	taskSkippedStale    workflowTaskStatus = "skipped_stale_dom"
)

type semanticTaskRecord struct {
	ID                             string
	Category                       workflowTaskCategory
	PageURL, Selector, LastFailure string
	Status                         workflowTaskStatus
	Attempts, MaxAttempts          int
	LastDOM                        string
	GeneratedRequestIDs            []string
	CompletedAt                    time.Time
}

type workflowTask struct {
	ID                  string
	PageURL             string
	DOMStateFingerprint string
	Selector            string
	Category            workflowTaskCategory
	SemanticType        string
	VisibleLabel        string
	RecordIdentity      string
	RecordActionKey     string
	ParentWorkflowID    string
	Status              workflowTaskStatus
	FailureReason       string
	GeneratedRequestIDs []string
	Form                *domForm
}

type domForm struct {
	Action         string                   `json:"action"`
	Method         string                   `json:"method"`
	Enctype        string                   `json:"enctype"`
	ID             string                   `json:"id"`
	Name           string                   `json:"name"`
	Class          string                   `json:"class"`
	Selector       string                   `json:"selector"`
	SubmitSelector string                   `json:"submitSelector"`
	SubmitLabel    string                   `json:"submitLabel"`
	Visible        bool                     `json:"visible"`
	Fields         []map[string]interface{} `json:"fields"`
}

func hashWorkflowIdentity(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return fmt.Sprintf("%x", sum[:])
}

func controlWorkflowFingerprint(pageURL, _ string, control map[string]interface{}, overlay string) string {
	label := strings.ToLower(strings.Join(strings.Fields(strOr(control["label"])), " "))
	href := strOr(control["href"])
	action := strOr(control["targetAction"])
	// Overlay/DOM fingerprints are transient presentation state. Stable control
	// identity prevents a background action from being re-executed each time a
	// modal, toast, or drawer changes unrelated DOM state. Record identity and
	// associated form still keep genuinely distinct actions separate.
	return hashWorkflowIdentity(EndpointTemplate(pageURL), strOr(control["semanticType"]), label, href, action, strOr(control["selector"]), strOr(control["associatedForm"]), strOr(control["recordIdentity"]))
}

type interactionResult struct {
	Changed             bool                     `json:"changed"`
	Interacted          int                      `json:"interacted"`
	Clicked             int                      `json:"clicked"`
	Filled              int                      `json:"filled"`
	Submitted           int                      `json:"submitted"`
	Mutations           int                      `json:"mutations"`
	Discovered          int                      `json:"discovered"`
	ShouldContinue      bool                     `json:"shouldContinue"`
	Error               string                   `json:"error"`
	LastStep            string                   `json:"lastStep"`
	LastElement         string                   `json:"lastElement"`
	SubmitDiagnostics   []map[string]interface{} `json:"submitDiagnostics"`
	RuntimeErrors       []map[string]interface{} `json:"runtimeErrors"`
	FieldStates         []map[string]interface{} `json:"fieldStates"`
	FormValid           *bool                    `json:"formValid"`
	FormData            []map[string]interface{} `json:"formData"`
	Diagnostics         []map[string]interface{} `json:"diagnostics"`
	SubmitAttempted     bool                     `json:"submitAttempted"`
	SubmitEventObserved bool                     `json:"submitEventObserved"`
}

func evaluateAsyncInteraction(ctx context.Context, expression string, result *interactionResult) error {
	remote, exception, err := runtime.Evaluate(expression).WithAwaitPromise(true).WithReturnByValue(true).Do(ctx)
	if err != nil {
		return fmt.Errorf("evaluate async interaction: %w", err)
	}
	if exception != nil {
		return fmt.Errorf("interaction JavaScript exception: %s", exception.Text)
	}
	if remote == nil {
		return fmt.Errorf("interaction evaluation returned nil result")
	}
	log.Printf("INTERACTION_EVALUATION_REMOTE: type=%s subtype=%s description=%s hasValue=%t", remote.Type, remote.Subtype, remote.Description, remote.Value != nil)
	if remote.Subtype == runtime.SubtypePromise {
		return fmt.Errorf("interaction returned an unawaited Promise")
	}
	if remote.Value == nil {
		return fmt.Errorf("interaction evaluation returned no value: type=%s subtype=%s description=%s", remote.Type, remote.Subtype, remote.Description)
	}
	raw, err := json.Marshal(remote.Value)
	if err != nil {
		return fmt.Errorf("marshal interaction result: %w", err)
	}
	if err := json.Unmarshal(raw, result); err != nil {
		return fmt.Errorf("decode interaction result: %w; raw=%s", err, raw)
	}
	if result.Interacted == 0 && result.Clicked == 0 && result.Filled == 0 && result.Submitted == 0 && result.Discovered == 0 && result.Error == "" && result.LastStep == "" && result.LastElement == "" && len(result.FieldStates) == 0 && len(result.SubmitDiagnostics) == 0 && len(result.RuntimeErrors) == 0 {
		return fmt.Errorf("interaction returned an empty result; possible unawaited Promise or decoding failure")
	}
	return nil
}

func logInteractionDiagnostics(r interactionResult) {
	if r.FormValid == nil {
		log.Printf("FORM_VALID: unknown")
	} else {
		log.Printf("FORM_VALID: %t", *r.FormValid)
	}
	logItems := func(prefix string, items []map[string]interface{}) {
		for i, item := range items {
			raw, _ := json.Marshal(item)
			log.Printf("%s[%d]: %s", prefix, i, raw)
		}
	}
	logItems("FIELD_STATE", r.FieldStates)
	logItems("FORM_DATA", r.FormData)
	logItems("SUBMIT_DIAGNOSTIC", r.SubmitDiagnostics)
	logItems("RUNTIME_ERROR", r.RuntimeErrors)
	logItems("INTERACTION_DIAGNOSTIC", r.Diagnostics)
}

const safeInteractionJS = `(async function(){try{return await (%s)}catch(e){return {changed:false,interacted:0,clicked:0,filled:0,submitted:0,mutations:0,discovered:0,shouldContinue:false,error:String(e&& (e.stack||e)),lastStep:window.__raptorLastStep||'',lastElement:window.__raptorLastElement||'',submitDiagnostics:window.__raptorSubmitDiagnostics||[],runtimeErrors:window.__raptorRuntimeErrors||[],fieldStates:[],formValid:null,formData:[]}}})()`

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

func isBackendFetchURL(method, raw string, headers map[string]string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return false
	}
	if method != "GET" {
		return true
	}
	if strings.Contains(u.Path, "/_next/") || u.Query().Get("_rsc") != "" {
		return false
	}
	ext := strings.ToLower(path.Ext(u.Path))
	for _, n := range noiseExtensions {
		if ext == n {
			return false
		}
	}
	accept := strings.ToLower(HeaderValue(headers, "Accept"))
	return strings.Contains(accept, "json") || strings.Contains(accept, "graphql") ||
		strings.Contains(strings.ToLower(HeaderValue(headers, "Content-Type")), "json") ||
		strings.Contains(u.Path, "/api/")
}

func isApplicationAPIURL(u *url.URL, headers map[string]string) bool {
	if strings.Contains(u.Path, "/_next/") || strings.HasPrefix(strings.ToLower(u.Path), "/__next") || u.Query().Get("_rsc") != "" {
		return false
	}
	ct := strings.ToLower(HeaderValue(headers, "Content-Type"))
	accept := strings.ToLower(HeaderValue(headers, "Accept"))
	return strings.Contains(u.Path, "/api/") || strings.Contains(u.Path, "/auth/") ||
		strings.Contains(u.Path, "/login") || strings.Contains(ct, "json") || strings.Contains(ct, "graphql") ||
		strings.Contains(accept, "json") || strings.Contains(accept, "graphql")
}

func isFrameworkURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	return strings.Contains(p, "/_next/") || strings.HasPrefix(p, "/__next") || strings.Contains(p, "webpack") || strings.Contains(p, "source-map")
}

func isApplicationActivity(method, raw string, resource network.ResourceType) bool {
	if isFrameworkURL(raw) {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	ext := strings.ToLower(path.Ext(u.Path))
	for _, staticExt := range noiseExtensions {
		if ext == staticExt {
			return false
		}
	}
	method = strings.ToUpper(method)
	return method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE" ||
		resource == network.ResourceTypeXHR || resource == network.ResourceTypeFetch
}

func flowNumber(flow map[string]interface{}, key string) float64 {
	n, _ := flow[key].(float64)
	return n
}

func classifyInteractionOutcome(flow map[string]interface{}, observedCDP bool) string {
	if flowApplicationRequestCount(flow) > 0 {
		return "APPLICATION_REQUEST_OBSERVED"
	}
	if errors, ok := flow["runtimeErrors"].([]interface{}); ok && len(errors) > 0 {
		return "CLIENT_SIDE_EXCEPTION"
	}
	if valid, ok := flow["formValid"].(bool); ok && !valid {
		return "VALIDATION_BLOCKED"
	}
	if diag, ok := flow["submitDiagnostic"].(map[string]interface{}); ok {
		if valid, exists := diag["formValid"].(bool); exists && !valid {
			return "VALIDATION_BLOCKED"
		}
	}
	if flowNumber(flow, "beaconCalls") > 0 || flowNumber(flow, "wsCalls") > 0 {
		return "APPLICATION_REQUEST_OBSERVED"
	}
	prevented, _ := flow["preventDefault"].(bool)
	if prevented {
		return "PREVENT_DEFAULT_WITHOUT_REQUEST"
	}
	if flowNumber(flow, "submits") > 0 {
		return "NO_APPLICATION_REQUEST"
	}
	if observedCDP {
		return "REQUEST_ABORTED"
	}
	return "NAVIGATION_INTERRUPTED"
}

func flowApplicationRequestCount(flow map[string]interface{}) int {
	if requests, ok := flow["applicationRequests"].([]interface{}); ok {
		return len(requests)
	}
	return 0
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

func fieldBool(field map[string]interface{}, key string) bool { v, _ := field[key].(bool); return v }

func semanticFieldType(field map[string]interface{}, page string) string {
	parts := strings.ToLower(strings.Join([]string{strOr(field["type"]), strOr(field["name"]), strOr(field["id"]), strOr(field["label"]), strOr(field["placeholder"]), strOr(field["autocomplete"]), page}, " "))
	if strings.Contains(parts, "email") || strings.Contains(parts, "e-mail") || strings.Contains(parts, "mail address") {
		return "email"
	}
	if strings.Contains(parts, "confirm") && strings.Contains(parts, "pass") {
		return "password_confirmation"
	}
	t := strings.ToLower(strOr(field["type"]))
	if t == "password" {
		return "password"
	}
	if t == "checkbox" || t == "radio" || t == "number" || t == "tel" || t == "url" || t == "date" {
		return t
	}
	return "text"
}

func generatedFieldValue(field map[string]interface{}, semantic string, fields []map[string]interface{}) string {
	switch semantic {
	case "email":
		return "raptor.test@example.com"
	case "password":
		return "Test1234!"
	case "password_confirmation":
		return "Test1234!"
	case "number":
		return "1"
	case "tel":
		return "+15555550123"
	case "url":
		return "https://example.com"
	case "date":
		return "2025-01-01"
	}
	return "test"
}

func redactConsoleValue(value string) string {
	idx := strings.Index(value, "{")
	if idx < 0 {
		return redactSensitiveText(value)
	}
	return redactSensitiveText(value[:idx]) + redactSensitiveText(value[idx:])
}

func containsAuthText(s string) bool {
	s = strings.ToLower(s)
	return strings.Contains(s, "login") || strings.Contains(s, "sign in") || strings.Contains(s, "signin")
}

func utilityControl(control map[string]interface{}) bool {
	s := strings.ToLower(strings.TrimSpace(strOr(control["label"])))
	return strings.Contains(s, "close toast") || strings.Contains(s, "dismiss") || s == "english" || s == "አማርኛ" || s == "afaan oromoo" || s == "ትግርኛ" || s == "中文" || s == "français"
}

func authForm(form domForm, page string) bool {
	return classifyAuthForm(form, page).IsAuth
}

type authClassification struct {
	IsAuth             bool
	Confidence         int
	Positive, Negative []string
	Reason             string
}

func classifyAuthForm(form domForm, page string) authClassification {
	r := authClassification{}
	passwords, identities, unrelated := 0, 0, 0
	for _, f := range form.Fields {
		if fieldBool(f, "disabled") || (f["visible"] != nil && !fieldBool(f, "visible")) {
			continue
		}
		typ := strings.ToLower(strOr(f["type"]))
		sem := strings.ToLower(strings.Join([]string{strOr(f["name"]), strOr(f["id"]), strOr(f["label"]), strOr(f["autocomplete"]), typ}, " "))
		if typ == "password" || strings.Contains(sem, "password") {
			passwords++
			r.Positive = append(r.Positive, "password_control")
		}
		if strings.Contains(sem, "user") || strings.Contains(sem, "login") || strings.Contains(sem, "email") || strings.Contains(strings.ToLower(strOr(f["autocomplete"])), "username") {
			identities++
			r.Positive = append(r.Positive, "identity_control")
		}
		if !strings.Contains(sem, "password") && !strings.Contains(sem, "user") && !strings.Contains(sem, "login") && !strings.Contains(sem, "email") && typ != "hidden" {
			unrelated++
		}
	}
	submit := strings.ToLower(strings.TrimSpace(form.SubmitLabel))
	strongSubmit := submit == "login" || submit == "log in" || submit == "sign in" || submit == "signin"
	action := strings.ToLower(form.Action)
	strongAction := strings.Contains(action, "/login") || strings.Contains(action, "/signin") || strings.Contains(action, "oauth")
	if strongSubmit {
		r.Positive = append(r.Positive, "auth_submit_label")
	}
	if strongAction {
		r.Positive = append(r.Positive, "auth_form_action")
	}
	if unrelated > 1 {
		r.Negative = append(r.Negative, "business_fields")
	}
	if submit == "create" || submit == "save" || strings.Contains(submit, "request") || submit == "update" || submit == "apply" {
		r.Negative = append(r.Negative, "business_submit_label")
	}
	if passwords != 1 {
		r.Negative = append(r.Negative, "password_count")
	}
	if identities < 1 {
		r.Negative = append(r.Negative, "missing_identity")
	}
	r.Confidence = 0
	if passwords == 1 {
		r.Confidence += 2
	}
	if identities >= 1 {
		r.Confidence += 2
	}
	if strongSubmit {
		r.Confidence += 3
	}
	if strongAction {
		r.Confidence += 2
	}
	r.Confidence -= len(r.Negative)
	r.IsAuth = r.Confidence >= 5 && passwords == 1 && identities >= 1 && (strongSubmit || strongAction)
	if r.IsAuth {
		r.Reason = "strong_auth_evidence"
	} else {
		r.Reason = "business_or_weak_auth_evidence"
	}
	return r
}
func authFieldSemantics(form domForm) []string {
	out := []string{}
	for _, f := range form.Fields {
		out = append(out, semanticFieldType(f, ""))
	}
	return out
}
func authAttemptLimit() int {
	n := 1
	if v, e := strconv.Atoi(strings.TrimSpace(os.Getenv("RAPTOR_AUTH_MAX_ATTEMPTS"))); e == nil && v > 0 {
		n = v
	}
	return n
}

func unsupportedFieldOutcome(typ, role string) string {
	if strings.EqualFold(typ, "date") {
		return "UNSUPPORTED_DATE_PICKER"
	}
	if strings.EqualFold(typ, "contenteditable") {
		return "UNSUPPORTED_CONTENTEDITABLE"
	}
	if strings.EqualFold(role, "combobox") || strings.EqualFold(role, "listbox") {
		return "CUSTOM_WIDGET_NOT_RECOGNIZED"
	}
	return "UNKNOWN_CONTROL"
}

func fieldStrategy(typ, role string) string {
	if strings.EqualFold(typ, "file") {
		return "upload"
	}
	if strings.EqualFold(typ, "select") || strings.HasPrefix(strings.ToLower(typ), "select-") {
		return "native_select"
	}
	if role == "combobox" || role == "listbox" {
		return "custom_option_click"
	}
	return "trusted_keyboard"
}

// formWorkflowFingerprint distinguishes rerendered/wizard forms that reuse a
// CSS selector from the same form state. It intentionally uses semantic DOM
// content rather than endpoint names.
func formWorkflowFingerprint(pageURL, overlay, step string, fields []map[string]interface{}, submit string) string {
	submit = normalizeSubmitAction(submit)
	var b strings.Builder
	b.WriteString(pageURL)
	b.WriteByte('|')
	b.WriteString(overlay)
	b.WriteByte('|')
	b.WriteString(step)
	b.WriteByte('|')
	b.WriteString(submit)
	for _, f := range fields {
		b.WriteByte('|')
		b.WriteString(strOr(f["name"]))
		b.WriteByte(':')
		b.WriteString(strOr(f["type"]))
		b.WriteByte(':')
		b.WriteString(strOr(f["label"]))
		b.WriteByte(':')
		b.WriteString(strOr(f["required"]))
	}
	sum := sha256.Sum256([]byte(b.String()))
	return fmt.Sprintf("%x", sum[:])
}

func normalizeSubmitAction(label string) string {
	s := strings.ToLower(strings.Join(strings.Fields(label), " "))
	s = strings.TrimSpace(strings.Trim(s, ".…!"))
	if strings.Contains(s, "sign in") || strings.Contains(s, "signing in") || strings.Contains(s, "login") {
		return "sign in"
	}
	for _, base := range []string{"save", "submit", "create", "update", "send", "delete", "load"} {
		if s == base || s == base+"ing" {
			return base
		}
	}
	if strings.Contains(s, "loading") || strings.Contains(s, "please wait") || strings.Contains(s, "spinner") || strings.Contains(s, "logging in") {
		return "submit"
	}
	return s
}

func chooseUploadFile(dir, accept string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	accept = strings.ToLower(strings.TrimSpace(accept))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(entry.Name())
		ext := strings.ToLower(filepath.Ext(name))
		ok := accept == "" || strings.Contains(accept, "*/*")
		for _, token := range strings.Split(accept, ",") {
			token = strings.TrimSpace(token)
			if strings.HasPrefix(token, "image/") && (ext == ".jpg" || ext == ".jpeg" || ext == ".png" || ext == ".gif") {
				ok = true
			}
			if strings.HasPrefix(token, ".") && ext == token {
				ok = true
			}
			if token == "text/plain" && ext == ".txt" {
				ok = true
			}
			if token == "application/pdf" && ext == ".pdf" {
				ok = true
			}
		}
		if ok {
			return filepath.Join(dir, entry.Name())
		}
	}
	return ""
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
	config              CrawlerConfig
	callback            RequestCallback
	session             sessionmgr.Session
	sessionState        *sessionmgr.State
	contextProvider     sessionmgr.BrowserContextProvider
	contextHandle       sessionmgr.BrowserContext
	allowedHost         string
	browserCtx          context.Context
	seenFingerprints    map[string]struct{}
	seenURLs            map[string]struct{}
	pending             map[network.RequestID]*pendingNetworkRequest
	completedRequests   map[network.RequestID]pendingNetworkRequest
	mu                  sync.RWMutex
	queue               []urlQueueItem
	queueMu             sync.Mutex
	visitedCount        int
	maxPages            int
	maxDepth            int
	wg                  sync.WaitGroup
	workerPool          chan struct{}
	sessionMu           sync.RWMutex
	sessionExpired      bool
	runtimeTraces       []runtimeRequestTrace
	scriptBodies        map[string]cachedScriptBody
	activeTask          *workflowTask
	semanticTasks       map[string]*semanticTaskRecord
	authAttempts        int
	authenticated       bool
	authState           authSessionState
	authSuccessAttempt  string
	authInitialAttempts int
	authReauthAttempts  int
	authBaseline        authEvidence
	yieldCallback       func(*workflowTask, string, time.Duration)
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
		config:            config,
		callback:          callback,
		session:           activeSession,
		contextProvider:   provider,
		allowedHost:       host,
		seenFingerprints:  map[string]struct{}{},
		seenURLs:          map[string]struct{}{},
		pending:           map[network.RequestID]*pendingNetworkRequest{},
		completedRequests: map[network.RequestID]pendingNetworkRequest{},
		maxPages:          maxPages,
		maxDepth:          maxDepth,
		workerPool:        make(chan struct{}, 5),
		scriptBodies:      map[string]cachedScriptBody{},
		semanticTasks:     map[string]*semanticTaskRecord{},
		authState:         authUnknown,
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
	q := u.Query()
	for key := range q {
		lk := strings.ToLower(key)
		if lk == "_rsc" || strings.HasPrefix(lk, "_next_") || strings.HasPrefix(lk, "__next") {
			q.Del(key)
		}
	}
	u.RawQuery = q.Encode()
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
	return c.canonicalizeURL(rawURL)
}

func (c *DynamicCrawler) routeEligible(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || !c.IsInScope(rawURL) || u.User != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	if strings.Contains(p, "/_next/") || strings.HasPrefix(p, "/api/") || p == "/favicon.ico" || p == "/sw.js" {
		return false
	}
	if ext := strings.ToLower(path.Ext(p)); ext != "" {
		for _, n := range noiseExtensions {
			if ext == n {
				return false
			}
		}
		if ext == ".js" || ext == ".map" || ext == ".json" || ext == ".webmanifest" {
			return false
		}
	}
	return true
}

// domSnapshot represents the live DOM state.
type domSnapshot struct {
	URL              string `json:"url"`
	ReadyState       string `json:"readyState"`
	DOMFingerprint   string `json:"domFingerprint"`
	ActiveOverlay    string `json:"activeOverlay"`
	VisibleStepTitle string `json:"visibleStepTitle"`
	Links            []struct {
		Href string `json:"href"`
	} `json:"links"`
	Forms     []domForm `json:"forms"`
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
	Controls    []map[string]interface{} `json:"controls"`
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

type renderedDOMSignature struct {
	ReadyState   string   `json:"readyState"`
	URL          string   `json:"url"`
	Title        string   `json:"title"`
	BodyChildren int      `json:"bodyChildren"`
	BodyTextLen  int      `json:"bodyTextLen"`
	Links        int      `json:"links"`
	Buttons      int      `json:"buttons"`
	Forms        int      `json:"forms"`
	Controls     int      `json:"controls"`
	Hrefs        []string `json:"hrefs"`
	DOMState     string   `json:"domState"`
	SettleReason string   `json:"settleReason"`
	ElapsedMS    int      `json:"elapsedMs"`
	QuietMS      int      `json:"quietMs"`
}

// waitForRenderedDOM waits for document readiness and a bounded quiet period
// of meaningful DOM mutations. It intentionally does not wait for network
// silence: Next.js chunks, fonts, images and prefetches may remain active.
func (c *DynamicCrawler) waitForRenderedDOM(ctx context.Context) (renderedDOMSignature, []string, error) {
	const settleJS = `(async()=>{const min=500,quiet=400,max=6000,start=performance.now();let changed=start;
const hrefs=new Set(),capture=()=>document.querySelectorAll('a[href]').forEach(a=>{try{hrefs.add(a.href)}catch(_){}});
capture();const meaningful=m=>m.type!=='attributes'||['href','action','hidden','aria-hidden'].includes(m.attributeName);
const observer=new MutationObserver(ms=>{if(ms.some(meaningful)){changed=performance.now();capture()}});
if(document.documentElement)observer.observe(document.documentElement,{subtree:true,childList:true,characterData:true,attributes:true,attributeFilter:['href','action','hidden','aria-hidden']});
return await new Promise(resolve=>{const finish=reason=>{observer.disconnect();capture();const body=document.body;
resolve({readyState:document.readyState,url:location.href,title:document.title,bodyChildren:body?body.children.length:0,bodyTextLen:body?(body.innerText||'').length:0,links:document.querySelectorAll('a[href]').length,buttons:document.querySelectorAll('button').length,forms:document.querySelectorAll('form').length,controls:document.querySelectorAll('button,[role="button"],input,select,textarea,summary,[role="tab"],[role="menuitem"],[aria-expanded]').length,hrefs:[...hrefs],domState:body?'body-ready':'no-body',settleReason:reason,elapsedMs:Math.round(performance.now()-start),quietMs:Math.round(performance.now()-changed)})};
const tick=()=>{const now=performance.now(),ready=document.readyState==='interactive'||document.readyState==='complete',body=!!document.body,next=!!document.querySelector('#__next'),nextApp=!!document.querySelector('script[src*="/_next/"]'),rootReady=!nextApp||next||!!document.querySelector('main,[data-nextjs-scroll-focus-boundary]');
if(now-start>=max)return finish('maximum');if(ready&&body&&rootReady&&now-start>=min&&now-changed>=quiet)return finish('quiet');setTimeout(tick,50)};tick()})})()`
	var current renderedDOMSignature
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		remote, exception, err := runtime.Evaluate(settleJS).WithAwaitPromise(true).WithReturnByValue(true).Do(ctx)
		if err != nil {
			return err
		}
		if exception != nil {
			return fmt.Errorf("DOM settle JavaScript exception: %s", exception.Text)
		}
		if remote == nil || remote.Value == nil {
			return fmt.Errorf("DOM settle returned no value")
		}
		raw, err := json.Marshal(remote.Value)
		if err != nil {
			return err
		}
		return json.Unmarshal(raw, &current)
	})); err != nil {
		return current, nil, err
	}
	sort.Strings(current.Hrefs)
	log.Printf("DOM_SETTLED ready_state=%s location=%s title=%q body_children=%d body_text_len=%d anchors=%d buttons=%d forms=%d controls=%d dom_state=%s reason=%s elapsed_ms=%d quiet_ms=%d",
		current.ReadyState, current.URL, current.Title, current.BodyChildren, current.BodyTextLen, current.Links, current.Buttons, current.Forms, current.Controls, current.DOMState, current.SettleReason, current.ElapsedMS, current.QuietMS)
	return current, current.Hrefs, nil
}

func (c *DynamicCrawler) extractRouteCandidates(snap domSnapshot, traces []runtimeRequestTrace, targetURL string, depth int, seenPaths map[string]struct{}, next *[]string) {
	acceptedLinks, queuedLinks := 0, 0
	type candidate struct{ raw, source string }
	candidates := make([]candidate, 0, len(snap.Links)+len(snap.Forms)+len(traces))
	for _, link := range snap.Links {
		candidates = append(candidates, candidate{link.Href, "anchor"})
	}
	for _, form := range snap.Forms {
		if strings.EqualFold(form.Method, "GET") {
			candidates = append(candidates, candidate{form.Action, "form_get"})
		}
	}
	snapshotIdentity := strings.TrimSuffix(c.normalizeCrawlURL(snap.URL), "/")
	targetIdentity := strings.TrimSuffix(c.normalizeCrawlURL(targetURL), "/")
	if snap.URL != "" && snapshotIdentity != targetIdentity {
		candidates = append(candidates, candidate{snap.URL, "navigation"})
	}
	for _, trace := range traces {
		u, err := url.Parse(trace.URL)
		if err == nil && trace.Method == "GET" && u.Query().Get("_rsc") != "" {
			candidates = append(candidates, candidate{trace.URL, "nextjs_rsc_prefetch"})
		}
	}
	for _, route := range candidates {
		canonicalURL := c.canonicalizeURL(route.raw)
		if !c.routeEligible(canonicalURL) || canonicalURL == c.canonicalizeURL(targetURL) {
			log.Printf("ROUTE_SKIPPED url=%s source=%s reason=ineligible_or_current", route.raw, route.source)
			continue
		}
		acceptedLinks++
		log.Printf("ROUTE_DISCOVERED original=%s source=%s", route.raw, route.source)
		log.Printf("ROUTE_NORMALIZED original=%s canonical=%s", route.raw, canonicalURL)
		np := c.normalizeCrawlURL(canonicalURL)
		if _, seen := seenPaths[np]; seen {
			log.Printf("ROUTE_ALREADY_SEEN url=%s", canonicalURL)
			continue
		}
		if depth+1 <= c.maxDepth {
			seenPaths[np] = struct{}{}
			*next = append(*next, canonicalURL)
			queuedLinks++
			log.Printf("ROUTE_QUEUED url=%s depth=%d source=%s", canonicalURL, depth+1, route.source)
		} else {
			log.Printf("ROUTE_SKIPPED url=%s source=%s reason=max_depth", canonicalURL, route.source)
		}
		// An RSC prefetch is route evidence, not a document visit. Avoid
		// marking its clean URL seen before the outer crawl queue consumes it.
		if route.source != "nextjs_rsc_prefetch" {
			c.emit(&DiscoveredRequest{ID: CalculateFingerprint("GET", canonicalURL, "", ""), URL: canonicalURL, Method: "GET", SourceType: route.source, Depth: depth + 1, NormalizedURL: NormalizeURL(canonicalURL), Parameters: ExtractParameters(canonicalURL, "", "")})
		}
	}
	log.Printf("ROUTE_DISCOVERY_SUMMARY page=%s snapshot_links=%d accepted_in_scope=%d appended_to_next=%d", targetURL, len(snap.Links), acceptedLinks, queuedLinks)
}

// processSnapshotLinks is retained for focused route-processing tests and
// delegates to the unified snapshot route extractor.
func (c *DynamicCrawler) processSnapshotLinks(snap domSnapshot, targetURL string, depth int, seenPaths map[string]struct{}, next *[]string) {
	c.extractRouteCandidates(snap, nil, targetURL, depth, seenPaths, next)
}

// domExtractionJS extracts DOM information including JSON forms and API calls.
const domExtractionJS = `
(function() {
  function esc(value) { return CSS.escape(String(value)); }
  function unique(selector) { try { return document.querySelectorAll(selector).length === 1; } catch (_) { return false; } }
  function stableSelector(el, form, formIndex, elementIndex) {
    if (el.id && unique('#' + esc(el.id))) return '#' + esc(el.id);
    for (const attr of Array.from(el.attributes || [])) {
      if ((attr.name === 'data-testid' || (attr.name.indexOf('data-') === 0 && !/react|next|state/i.test(attr.name))) && attr.value) {
        const candidate='['+attr.name+'="'+CSS.escape(attr.value)+'"]';
        if (unique(candidate)) return candidate;
      }
    }
    const name=el.getAttribute('name'), type=el.getAttribute('type');
    if (name) {
      const candidate=el.tagName.toLowerCase()+'[name="'+CSS.escape(name)+'"]'+(type?'[type="'+CSS.escape(type)+'"]':'');
      if (unique(candidate)) return candidate;
    }
    if (el.tagName === 'FORM') return 'form:nth-of-type('+(formIndex+1)+')';
    if (form) {
      const parts=[]; let node=el;
      while(node && node!==form) {
        const tag=node.tagName.toLowerCase();
        const siblings=Array.from(node.parentElement.children).filter(function(s){return s.tagName===node.tagName});
        parts.unshift(tag+':nth-of-type('+(siblings.indexOf(node)+1)+')');
        node=node.parentElement;
      }
      if(node===form) return stableSelector(form, null, formIndex, formIndex)+' > '+parts.join(' > ');
    }
    var parts=[], node=el;
    while(node && node!==document.documentElement) {
      var tag=node.tagName.toLowerCase(), siblings=Array.from(node.parentElement.children).filter(function(s){return s.tagName===node.tagName});
      parts.unshift(tag+':nth-of-type('+(siblings.indexOf(node)+1)+')');
      node=node.parentElement;
    }
    return parts.join(' > ');
  }
  function fieldsOf(root, formIndex) {
    return Array.from(root.querySelectorAll('input, select, textarea')).map(function(el, elementIndex) {
      return {
        selector: stableSelector(el, root instanceof HTMLFormElement ? root : null, formIndex || 0, elementIndex),
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

  function visible(el) {
    if (!el || !el.isConnected) return false;
    var s=getComputedStyle(el);
    return s.display!=='none' && s.visibility!=='hidden' && s.visibility!=='collapse' &&
      !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  }
  function text(el) { return String(el && (el.innerText || el.value || el.getAttribute('aria-label') || el.getAttribute('title')) || '').trim(); }
  var overlayEl=Array.from(document.querySelectorAll('dialog[open],[role="dialog"]:not([aria-hidden="true"]),[aria-modal="true"],[data-state="open"],.drawer.open,.modal.show')).find(visible);
  var activeOverlay=overlayEl ? [overlayEl.id,overlayEl.getAttribute('aria-label'),overlayEl.getAttribute('aria-labelledby'),overlayEl.getAttribute('data-testid'),text(overlayEl.querySelector('h1,h2,h3,[role="heading"]'))].filter(Boolean).join('|') : '';
  var stepEl=Array.from(document.querySelectorAll('[aria-current="step"],[data-step][data-state="active"],.step.active,h1,h2,h3,[role="heading"]')).find(visible);
  var visibleStepTitle=text(stepEl);

  // Get all forms
  var forms = Array.from(document.querySelectorAll('form')).map(function(f, formIndex){
    var actionAttr = f.getAttribute('action') || '';
    var submit=f.querySelector('button[type="submit"],input[type="submit"],button:not([type])');
    return {
      action: actionAttr ? new URL(actionAttr, location.href).href : location.href,
      method: (f.getAttribute('method') || 'get').toUpperCase(),
      enctype: f.getAttribute('enctype') || 'application/x-www-form-urlencoded',
      id: f.getAttribute('id') || '',
      name: f.getAttribute('name') || '',
      class: f.getAttribute('class') || '',
      selector: stableSelector(f, null, formIndex, formIndex),
      submitSelector: submit ? stableSelector(submit, f, formIndex, 0) : '',
      submitLabel: text(submit),
      visible: visible(f),
      fields: fieldsOf(f, formIndex)
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

  var controls=Array.from(document.querySelectorAll('button,[role="button"],a[href^="#"],input[type="search"],summary,[role="tab"],[role="menuitem"],[aria-expanded]'))
    .filter(function(el){return visible(el) && !el.disabled && el.getAttribute('aria-disabled')!=='true' && !el.closest('form')})
    .map(function(el,index){return {
      selector:stableSelector(el,null,index,index),
      semanticType:el.type||el.getAttribute('role')||el.tagName.toLowerCase(),
      label:text(el),
      overlay:activeOverlay,
      expanded:el.getAttribute('aria-expanded')||'',
      selected:el.getAttribute('aria-selected')||'',
      href:el.closest('a[href]') ? el.closest('a[href]').href : (el.getAttribute('href')||''),
      targetAction:el.getAttribute('data-action')||el.getAttribute('formaction')||'',
      associatedForm:el.closest('form') ? (el.closest('form').getAttribute('name')||el.closest('form').getAttribute('action')||'') : '',
      recordIdentity:(function(){let n=el;while(n&&n!==document.body){for(const a of ['data-id','data-key','data-testid','data-resource-id','data-record-id']){if(n.getAttribute&&n.getAttribute(a))return a+'='+n.getAttribute(a)}if(n.tagName==='A'&&n.href)return 'href='+n.href;n=n.parentElement}return ''})()
    }});

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
    readyState: document.readyState,
    links: links, 
    forms: forms,
    jsonForms: jsonForms,
    jsonEndpoints: jsonEndpoints,
    standalone: standalone, 
    shadowHosts: shadowHosts, 
    scripts: scripts,
    apiCalls: apiCalls,
    controls: controls,
    url: location.href,
    activeOverlay: activeOverlay,
    visibleStepTitle: visibleStepTitle,
    domFingerprint: (function(){var raw=[location.href,activeOverlay,visibleStepTitle,forms.filter(function(f){return f.visible}).map(function(f){return [f.selector,f.submitLabel,f.fields.map(function(x){return [x.type,x.name,x.id,x.required].join(':')}).join(',')].join(':')}),controls.map(function(c){return [c.selector,c.semanticType,c.label,c.expanded,c.selected].join(':')})].join('|');var h=2166136261;for(var i=0;i<raw.length;i++){h^=raw.charCodeAt(i);h=Math.imul(h,16777619)}return (h>>>0).toString(16)})()
  });
})()
`

// formInteractionJS performs a real browser interaction. It never reports
// the form action as a request; the CDP network listener is the only writer.
const formInteractionJS = `(async function() {
  window.__raptorLastStep = 'start'; window.__raptorLastElement = '';
  window.__raptorSubmitDiagnostics = window.__raptorSubmitDiagnostics || [];
  const submitDiagnosticStart = window.__raptorSubmitDiagnostics.length;
  window.__raptorRuntimeErrors = window.__raptorRuntimeErrors || [];
  const runtimeErrorStart = window.__raptorRuntimeErrors.length;
  function isSensitiveFieldName(name){ return /password|passwd|passcode|secret|token|csrf|xsrf|auth|authorization|api[-_]?key|session|otp|pin/.test(String(name||'').toLowerCase()); }
  function redactFormEntries(form){ if(!(form instanceof HTMLFormElement)) return []; return Array.from(new FormData(form).entries()).map(function(pair){ const name=String(pair[0]||''); const rawValue=typeof pair[1]==='string'?pair[1]:'[file]'; return isSensitiveFieldName(name)?{name:name,value:'[redacted]',length:rawValue.length}:{name:name,value:rawValue}; }); }
  if (!window.__raptorSubmitObserverInstalled) {
    window.__raptorSubmitObserverInstalled = true;
    document.addEventListener('submit', function(event) {
      const form = event.target;
      const record={event:'submit',defaultPreventedAtCapture:event.defaultPrevented,defaultPreventedAfterDispatch:null,targetMatchesForm:!!form,action:form&&form.action||'',method:form&&form.method||'',valid:form&&form.checkValidity?form.checkValidity():null,values:redactFormEntries(form)};
      window.__raptorSubmitDiagnostics.push(record);
      queueMicrotask(function(){record.defaultPreventedAfterDispatch=event.defaultPrevented;});
    }, true);
  }
  if (!window.__raptorRuntimeObserverInstalled) {
    window.__raptorRuntimeObserverInstalled = true;
    window.addEventListener('error', function(event) { window.__raptorRuntimeErrors.push({type:'error',message:String(event.message||''),filename:String(event.filename||''),line:Number(event.lineno||0),column:Number(event.colno||0)}); });
    window.addEventListener('unhandledrejection', function(event) { window.__raptorRuntimeErrors.push({type:'unhandledrejection',message:String(event.reason&&(event.reason.stack||event.reason.message||event.reason)||'')}); });
  }
  function describeElement(el){if(!el)return '';let formAction='';try{formAction=el.form&&el.form.action?String(el.form.action):''}catch(_){}return JSON.stringify({tag:String(el.tagName||''),type:String(el.type||''),name:String(el.name||''),id:String(el.id||''),className:typeof el.className==='string'?el.className:'',formAction:formAction});}
  function mark(step, element){ window.__raptorLastStep=step; if(!element){window.__raptorLastElement='';return;} try{window.__raptorLastElement=describeElement(element)}catch(_){window.__raptorLastElement='[description-failed]'} }
  const nativeDispatchEvent=EventTarget.prototype.dispatchEvent;
  const nativeFocus=HTMLElement.prototype.focus;
  const nativeBlur=HTMLElement.prototype.blur;
  const nativeClick=HTMLElement.prototype.click;
  const nativeRequestSubmit=HTMLFormElement.prototype.requestSubmit;
  function dispatchNativeEvent(element,type){const ev=new Event(type,{bubbles:true,cancelable:true,composed:true});return Reflect.apply(nativeDispatchEvent,element,[ev]);}
  function tryStep(step,element,fn){mark(step,element);try{return {ok:true,value:fn()}}catch(error){const d={step:step,element:describeElement(element),error:String(error&&(error.stack||error))};diagnostics.push(d);return {ok:false,error:d.error}}}
  let explored = 0;
  let interacted = 0;
  let clicked = 0;
  let filled = 0;
  let submitted = 0;
  let discovered = 0;
  let mutations = 0;
  let lastFieldStates = [];
  let lastFormValid = null;
  let lastFormData = [];
  let diagnostics = [];
  let submitAttempted = false;
  window.__raptorInteracted = window.__raptorInteracted || new Set();
  const processedRadioGroups = new Set();
  window.__raptorSubmittedForms = window.__raptorSubmittedForms || new WeakSet();
  window.__raptorClickedControls = window.__raptorClickedControls || new WeakSet();
  window.__raptorInteractionInvocation = (window.__raptorInteractionInvocation || 0) + 1;
  mark('query-forms', null); const forms = window.__raptorTargetFormSelector ? Array.from(document.querySelectorAll(window.__raptorTargetFormSelector)).slice(0,1) : Array.from(document.querySelectorAll('form'));
  for (const form of forms) {
    if (window.__raptorSubmittedForms.has(form)) { continue; }
    mark('query-fields', form); const fields = Array.from(form.querySelectorAll('input,textarea,select')); discovered += fields.length;
    const password = fields.find(e => (e.type || '').toLowerCase() === 'password');
    const submit = form.querySelector('button[type="submit"],input[type="submit"],button:not([type])');
    if (submit) discovered++;
    if (!password && !submit) continue;
    for (const d of fields) console.log('DOM FIELD: ' + JSON.stringify({name:d.name||'',id:d.id||'',type:d.type||d.tagName.toLowerCase(),value:d.type==='password'?'******':(d.value||''),checked:!!d.checked,disabled:!!d.disabled,required:!!d.required}));
    if (submit) console.log('SUBMIT BUTTON FOUND: selector=' + submit.tagName.toLowerCase());
    else console.log('NO SUBMIT BUTTON FOUND');
    for (const e of fields) {
      if (e.disabled || e.readOnly || e.type === 'hidden' || e.type === 'submit') continue;
      const n = ((e.name || '') + ' ' + (e.id || '') + ' ' + (e.placeholder || '')).toLowerCase();
      const type=String(e.type||'').toLowerCase();
      if(window.__raptorTrustedSubmission && type!=='checkbox' && type!=='radio') { filled++; interacted++; continue; }
      if(type==='checkbox') {
        if(!e.checked) { const cr=tryStep('checkbox-native-click',e,()=>Reflect.apply(nativeClick,e,[])); if(!cr.ok) continue; }
        if(e.checked){filled++;interacted++;console.log('FIELD FILLED: name='+(e.name||e.id||'')+' type=checkbox checked=true');}
        continue;
      }
      if(type==='radio') {
        const group=e.name||''; if(group&&processedRadioGroups.has(group)) continue; if(group)processedRadioGroups.add(group);
        if(!e.checked) { const rr=tryStep('radio-native-click',e,()=>Reflect.apply(nativeClick,e,[])); if(!rr.ok) continue; }
        if(e.checked){filled++;interacted++;}
        continue;
      }
      const min=Number(e.getAttribute('minlength')||0), max=Number(e.getAttribute('maxlength')||0), pattern=e.getAttribute('pattern')||'', ac=e.getAttribute('autocomplete')||'';
      console.log('FIELD CONSTRAINTS: '+JSON.stringify({name:e.name||'',required:!!e.required,minlength:min,maxlength:max,pattern:pattern,disabled:!!e.disabled,readonly:!!e.readOnly,autocomplete:ac,placeholder:e.placeholder||'',ariaInvalid:e.getAttribute('aria-invalid')||'',validation:e.validationMessage||''}));
      let value = '';
      console.log('FIELD: name=' + (e.name || e.id || '') + ' type=' + e.type);
      if (e.type === 'password') value = 'Test1234!';
      else if (e.type === 'email' || n.includes('email')) value = 'test@example.com';
      else if (n.includes('user') || n.includes('login')) value = 'testuser';
      else if (e.type === 'number') value = '1';
      else if (!e.value) value = 'test';
      if (value && min > value.length) value=value+'x'.repeat(min-value.length);
      if (max > 0 && value.length > max) value=value.slice(0,max);
      if (value) {
        mark('native-focus', e); if(e instanceof HTMLElement) Reflect.apply(nativeFocus,e,[]);
        const proto = e instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : (e instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype);
        window.__raptorLastStep='get-value-descriptor'; window.__raptorLastElement=describeElement(e); const setter = Object.getOwnPropertyDescriptor(proto, 'value');
        const previousValue = e.value;
        if (setter && setter.set) { window.__raptorLastStep='native-value-setter'; Reflect.apply(setter.set,e,[value]); if (e._valueTracker) e._valueTracker.setValue(previousValue); } else { continue; }
      }
      mark('dispatch-input', e); const inputEvent = new InputEvent('input',{bubbles:true,composed:true,inputType:'insertText',data:value}); Reflect.apply(nativeDispatchEvent,e,[inputEvent]);
      mark('dispatch-change', e); dispatchNativeEvent(e,'change');
      console.log('FIELD FILLED: name=' + (e.name || e.id || '') + ' value=' + (e.type === 'password' ? '******' : value));
      filled++;
    }
    let submitSucceeded=false;
    console.log('FORM_STATE_BEFORE_SUBMIT: '+JSON.stringify({valid:typeof form.checkValidity==='function'?form.checkValidity():null,disabled:!!(submit&&submit.disabled),active:document.activeElement&&describeElement(document.activeElement)}));
    if (!window.__raptorTrustedSubmission && submit && !submit.disabled && typeof nativeRequestSubmit === 'function' && !window.__raptorSubmittedForms.has(form)) { window.__raptorSubmittedForms.add(form); submitAttempted=true; mark('form-request-submit',submit); const sr=tryStep('form-request-submit',submit,()=>Reflect.apply(nativeRequestSubmit,form,[submit])); if(sr.ok){submitSucceeded=true;} else {window.__raptorSubmittedForms.delete(form);} }
    if (!window.__raptorTrustedSubmission && !submitSucceeded && submit && !submit.disabled && !window.__raptorSubmittedForms.has(form)) { window.__raptorSubmittedForms.add(form); submitAttempted=true; mark('submit-native-click',submit); const sr=tryStep('submit-native-click',submit,()=>Reflect.apply(nativeClick,submit,[])); if(sr.ok){submitSucceeded=true;} else {window.__raptorSubmittedForms.delete(form);} }
    if(submitSucceeded){submitted++;clicked++;interacted++;}
    const fieldStates = fields.map(function(field) { const fieldName=field.name||field.id||''; const sensitive=isSensitiveFieldName(fieldName)||String(field.type||'').toLowerCase()==='password'; const state={name:fieldName,type:field.type||field.tagName.toLowerCase(),value:sensitive?'[redacted]':(field.value||''),length:sensitive?String((field.value||'').length):undefined,checked:!!field.checked,valid:typeof field.checkValidity==='function'?field.checkValidity():null,validationMessage:field.validationMessage||''}; return state; });
    const formValid = typeof form.checkValidity === 'function' ? form.checkValidity() : null;
    const formData = redactFormEntries(form);
    lastFieldStates = fieldStates;
    lastFormValid = formValid;
    lastFormData = formData;
    if (submitSucceeded) { await new Promise(function(resolve){ setTimeout(resolve, 250); }); }
    if (window.__raptorSubmitDiagnostics.length > submitDiagnosticStart) console.log('SUBMIT_EVENT_OBSERVED: '+JSON.stringify(window.__raptorSubmitDiagnostics.slice(submitDiagnosticStart)));
    if (window.__raptorRuntimeErrors.length > runtimeErrorStart) console.log('RUNTIME_ERROR: '+JSON.stringify(window.__raptorRuntimeErrors.slice(runtimeErrorStart)));
    console.log('FORM_STATE_AFTER_SUBMIT: '+JSON.stringify({valid:formValid,fields:fieldStates,formData:formData,active:document.activeElement&&describeElement(document.activeElement)}));
    if (submitted >= 1) break;
  }
  return {changed: explored>0 || submitted>0, interacted: interacted, clicked: clicked, filled: filled, submitted: submitted, mutations: mutations, discovered: discovered, shouldContinue: explored>0 || submitted>0, error:'', lastStep:window.__raptorLastStep, lastElement:window.__raptorLastElement, submitDiagnostics:window.__raptorSubmitDiagnostics.slice(submitDiagnosticStart), runtimeErrors:window.__raptorRuntimeErrors.slice(runtimeErrorStart), fieldStates:lastFieldStates, formValid:lastFormValid, formData:lastFormData, diagnostics:diagnostics, submitAttempted:submitAttempted, submitEventObserved:window.__raptorSubmitDiagnostics.length>submitDiagnosticStart};
})()`

const requestHookJS = `(function(){
 if (window.__raptorHooksInstalled) return; window.__raptorHooksInstalled=true;
 window.__raptorFlow={clicks:0,submits:0,preventDefault:false,fetchCalls:0,xhrOpenCalls:0,xhrSendCalls:0,beaconCalls:0,wsCalls:0,applicationRequests:[],submitDiagnostic:null,runtimeErrors:[]};
 function framework(url,body){var s=(String(url||'')+' '+String(body||'')).toLowerCase();return /\/_next\/|webpack-hmr|turbopack|react-devtools|client-file-logs|client-success|turbopack-subscribe|"event":"ping"/.test(s)||/\.(js|css|woff2?|ttf|png|jpe?g|gif|svg|ico)(\?|$)/.test(s);}
 function appRecord(api,method,url,body,bodyType,stack){var resolved='';try{resolved=new URL(String(url),location.href).href}catch(_){resolved=String(url||'')}if(framework(resolved,body))return;window.__raptorFlow.applicationRequests.push({apiType:api,method:String(method||'GET').toUpperCase(),url:resolved,bodyType:bodyType||'',bodyLength:body==null?0:String(body).length,timestamp:Date.now(),stack:stack||''});}
 document.addEventListener('click',function(e){var f=window.__raptorFlow;if(f&&(!f.expectedSubmitSelector||e.target.closest(f.expectedSubmitSelector)))f.clicks++},true);
 document.addEventListener('submit',function(e){var f=window.__raptorFlow;if(!f||f.submitDiagnostic)return;var expected=f.expectedFormSelector?document.querySelector(f.expectedFormSelector):null;var record={timestamp:Date.now(),targetMatchesExpectedForm:!expected||e.target===expected,defaultPreventedAtCapture:e.defaultPrevented,defaultPreventedAfterDispatch:null,formValid:e.target&&e.target.checkValidity?e.target.checkValidity():null,submitterSelector:f.expectedSubmitSelector||''};f.submits=1;f.submitDiagnostic=record;setTimeout(function(){record.defaultPreventedAfterDispatch=e.defaultPrevented;f.preventDefault=e.defaultPrevented},0)},true);
 window.addEventListener('error',function(e){if(window.__raptorFlow)window.__raptorFlow.runtimeErrors.push({type:'error',message:String(e.message||''),timestamp:Date.now()})});
 window.addEventListener('unhandledrejection',function(e){if(window.__raptorFlow)window.__raptorFlow.runtimeErrors.push({type:'unhandledrejection',message:String(e.reason&&(e.reason.stack||e.reason)||''),timestamp:Date.now()})});
 function emit(api,method,url,headers,body){
  try { var h={}; if(headers) headers.forEach ? headers.forEach((v,k)=>h[k]=v) : Object.assign(h,headers||{});
   if(body && typeof FormData!=='undefined' && body instanceof FormData){var o={};body.forEach((v,k)=>o[k]=/password|secret|token|pin/i.test(k)?'[redacted]':(typeof v==='string'?v:'[file]'));body=JSON.stringify(o);}
   var bt=''; var ct=(h['content-type']||h['Content-Type']||'').toLowerCase();
   if(ct.includes('json')) bt='json'; else if(ct.includes('urlencoded')) bt='form-urlencoded'; else if(ct.includes('multipart')) bt='multipart'; else if(body) bt='text';
   var stack=''; try { stack=(new Error()).stack||''; } catch(e) {}
   var resolved=new URL(String(url),location.href).href;appRecord(api,method,resolved,body,bt,stack);
   console.log('__RAPTOR_REQ__'+JSON.stringify({api_type:api,method:method||'GET',url:resolved,headers:h,body:body==null?'':String(body),body_type:bt,timestamp:Date.now(),stack:stack,script_url:String(document.currentScript&&document.currentScript.src||location.href)}));
  } catch(e){}
 }
 const of=window.fetch; window.fetch=function(input,init){init=init||{};var req=typeof Request!=='undefined'&&input instanceof Request;var method=init.method||(req&&input.method)||'GET',u=(typeof input==='string'||input instanceof URL)?String(input):input.url,headers=init.headers||(req&&input.headers),body=init.body;window.__raptorFlow.fetchCalls++;emit('fetch',method,u,headers,body);return Reflect.apply(of,this,arguments)};
 const xo=XMLHttpRequest.prototype.open, xs=XMLHttpRequest.prototype.send, xh=XMLHttpRequest.prototype.setRequestHeader;
 XMLHttpRequest.prototype.open=function(m,u){window.__raptorFlow.xhrOpenCalls++;this.__raptor={method:m,url:new URL(String(u),location.href).href,headers:{}};return Reflect.apply(xo,this,arguments)};
 XMLHttpRequest.prototype.setRequestHeader=function(k,v){if(this.__raptor)this.__raptor.headers[k]=v;return Reflect.apply(xh,this,arguments)};
 XMLHttpRequest.prototype.send=function(b){window.__raptorFlow.xhrSendCalls++;if(this.__raptor)emit('xhr',this.__raptor.method,this.__raptor.url,this.__raptor.headers,b);return Reflect.apply(xs,this,arguments)};
 const sb=navigator.sendBeacon;if(sb)navigator.sendBeacon=function(u,d){window.__raptorFlow.beaconCalls++;emit('beacon','POST',u,{},d);return Reflect.apply(sb,navigator,arguments)};
 const ws=window.WebSocket;if(ws){const wsend=ws.prototype.send;ws.prototype.send=function(d){if(!framework(this.url,d)){window.__raptorFlow.wsCalls++;emit('websocket','WS_SEND',this.url,{},typeof d==='string'?d:'[binary]')}return Reflect.apply(wsend,this,arguments)}}
 const es=window.EventSource;if(es){const WrappedES=function(){return Reflect.construct(es,arguments,new.target||WrappedES)};Object.setPrototypeOf(WrappedES,es);WrappedES.prototype=es.prototype;window.EventSource=WrappedES}
})()`
const mutationWaitJS = `(function(){return new Promise(function(resolve){let finished=false;const observer=new MutationObserver(function(){finish(true)});const timer=setTimeout(function(){finish(false)},2000);function finish(changed){if(finished)return;finished=true;clearTimeout(timer);observer.disconnect();resolve({changed:changed,interacted:0,clicked:0,filled:0,submitted:0,mutations:changed?1:0,discovered:0,shouldContinue:changed,error:''})}observer.observe(document.documentElement,{subtree:true,childList:true,attributes:true,attributeFilter:['disabled','hidden','aria-hidden','aria-invalid','aria-expanded','aria-disabled','class']});})})()`

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

func (c *DynamicCrawler) liveDOMSnapshot(ctx context.Context) (domSnapshot, error) {
	var raw string
	if err := chromedp.Run(ctx, chromedp.Evaluate(domExtractionJS, &raw)); err != nil {
		return domSnapshot{}, err
	}
	var snap domSnapshot
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		return domSnapshot{}, err
	}
	snap.URL = c.canonicalizeURL(snap.URL)
	return snap, nil
}

// executeWorkflowQueue drains supported work discovered from the live DOM.
// The trusted form engine remains formInteractionJS; this scheduler only
// selects one semantic form state at a time and gives every task a new bound.
func (c *DynamicCrawler) executeWorkflowQueue(pageCtx context.Context, initial domSnapshot, pageURL, parentWorkflowID string, applicationRequest <-chan struct{}, processRoutes func(domSnapshot)) {
	currentPageURL := pageURL
	var queue []*workflowTask
	recordActionSamples := map[string]int{}
	maxTasks := c.config.WorkflowMaxTasks
	if maxTasks <= 0 {
		maxTasks = 200
	}
	enqueue := func(snap domSnapshot, dynamic bool) int {
		added := 0
		var newlyVisibleForms []*workflowTask
		for i := range snap.Forms {
			form := &snap.Forms[i]
			if !form.Visible || form.Selector == "" || form.SubmitSelector == "" {
				continue
			}
			id := formWorkflowFingerprint(snap.URL, snap.ActiveOverlay, snap.VisibleStepTitle, form.Fields, form.SubmitLabel)
			c.mu.RLock()
			record := c.semanticTasks[id]
			blocked := record != nil && (record.Status == taskQueued || record.Status == taskExecuting || record.Status == taskCompleted || record.Status == taskFailedFinal)
			c.mu.RUnlock()
			if blocked {
				continue
			}
			c.mu.Lock()
			if record == nil {
				record = &semanticTaskRecord{ID: id, Category: workflowForm, MaxAttempts: 1}
				c.semanticTasks[id] = record
			}
			record.PageURL, record.Selector, record.Status, record.LastDOM = snap.URL, form.Selector, taskQueued, snap.DOMFingerprint
			c.mu.Unlock()
			task := &workflowTask{ID: id, PageURL: snap.URL, DOMStateFingerprint: snap.DOMFingerprint, Selector: form.Selector, Category: workflowForm, SemanticType: "form_submit", VisibleLabel: form.SubmitLabel, ParentWorkflowID: parentWorkflowID, Status: taskQueued, Form: form}
			newlyVisibleForms = append(newlyVisibleForms, task)
			added++
			log.Printf("WORKFLOW_TASK_QUEUED task_id=%s category=%s page=%s dom_state=%s selector=%s label=%q parent=%s status=%s", task.ID, task.Category, task.PageURL, task.DOMStateFingerprint, task.Selector, task.VisibleLabel, task.ParentWorkflowID, task.Status)
			if strings.Contains(task.PageURL, "/client/") {
				log.Printf("PROTECTED_FORM_QUEUED task_id=%s page=%s selector=%s", task.ID, task.PageURL, task.Selector)
			}
			if dynamic {
				log.Printf("DYNAMIC_FORM_QUEUED task_id=%s page=%s form=%s state=%s", task.ID, task.PageURL, task.Selector, task.ID)
			}
		}
		// Finish a revealed form/wizard state before unrelated controls can
		// replace the DOM that contains it.
		queue = append(newlyVisibleForms, queue...)
		for _, control := range snap.Controls {
			if utilityControl(control) {
				log.Printf("WORKFLOW_TASK_SKIPPED category=UTILITY_CONTROL page=%s label=%q", snap.URL, strOr(control["label"]))
				continue
			}
			id := controlWorkflowFingerprint(snap.URL, "", control, snap.ActiveOverlay)
			c.mu.RLock()
			record := c.semanticTasks[id]
			blocked := record != nil && (record.Status == taskQueued || record.Status == taskExecuting || record.Status == taskCompleted || record.Status == taskFailedFinal)
			c.mu.RUnlock()
			if blocked {
				continue
			}
			recordIdentity := strOr(control["recordIdentity"])
			key := EndpointTemplate(snap.URL) + "\x00" + strings.ToLower(strOr(control["semanticType"])) + "\x00" + strings.ToLower(strOr(control["label"]))
			if recordIdentity != "" {
				limit := c.config.RecordActionSampleLimit
				if limit < 0 {
					limit = 0
				}
				if limit > 0 && recordActionSamples[key] >= limit {
					log.Printf("WORKFLOW_TASK_SKIPPED category=RECORD_SAMPLE_LIMIT page=%s label=%q record=%q limit=%d", snap.URL, strOr(control["label"]), recordIdentity, limit)
					continue
				}
			}
			c.mu.Lock()
			if record == nil {
				record = &semanticTaskRecord{ID: id, Category: workflowControl, MaxAttempts: 2}
				c.semanticTasks[id] = record
			}
			record.PageURL, record.Selector, record.Status, record.LastDOM = snap.URL, strOr(control["selector"]), taskQueued, snap.DOMFingerprint
			c.mu.Unlock()
			task := &workflowTask{ID: id, PageURL: snap.URL, DOMStateFingerprint: snap.DOMFingerprint, Selector: strOr(control["selector"]), Category: workflowControl, SemanticType: strOr(control["semanticType"]), VisibleLabel: strOr(control["label"]), RecordIdentity: recordIdentity, RecordActionKey: key, ParentWorkflowID: parentWorkflowID, Status: taskQueued}
			queue = append(queue, task)
			added++
			log.Printf("WORKFLOW_TASK_QUEUED task_id=%s category=%s page=%s dom_state=%s selector=%s type=%s label=%q parent=%s status=%s", task.ID, task.Category, task.PageURL, task.DOMStateFingerprint, task.Selector, task.SemanticType, task.VisibleLabel, task.ParentWorkflowID, task.Status)
		}
		return added
	}

	taskCtx, cancel := context.WithTimeout(pageCtx, 8*time.Second)
	live, err := c.liveDOMSnapshot(taskCtx)
	cancel()
	if err != nil {
		log.Printf("WORKFLOW_REDISCOVERY_FAILED page=%s reason=%v", pageURL, err)
		return
	}
	log.Printf("DYNAMIC_FORM_DISCOVERY page=%s forms=%d controls=%d", live.URL, len(live.Forms), len(live.Controls))
	if processRoutes != nil {
		processRoutes(live)
	}
	if enqueue(live, true) == 0 {
		log.Printf("WORKFLOW_QUEUE_EMPTY page=%s forms=%d controls=%d", live.URL, len(live.Forms), len(live.Controls))
	}

	for completed := 0; len(queue) > 0 && completed < maxTasks; completed++ {
		task := queue[0]
		queue = queue[1:]
		if task.Category == workflowControl {
			var usable bool
			check := fmt.Sprintf(`(()=>{const e=document.querySelector(%q);if(!e||!e.isConnected)return false;const s=getComputedStyle(e);return s.display!=='none'&&s.visibility!=='hidden'&&!!(e.offsetWidth||e.offsetHeight||e.getClientRects().length)})()`, task.Selector)
			if err := chromedp.Run(pageCtx, chromedp.Evaluate(check, &usable)); err != nil || !usable {
				task.Status = taskSkippedStale
				c.mu.Lock()
				if r := c.semanticTasks[task.ID]; r != nil {
					r.Attempts++
					if r.Attempts < r.MaxAttempts {
						r.Status = taskFailedRetryable
					} else {
						r.Status = taskFailedFinal
					}
					r.LastFailure = "stale_dom"
				}
				c.mu.Unlock()
				log.Printf("WORKFLOW_TASK_RESULT task_id=%s category=%s status=%s reason=stale_dom", task.ID, task.Category, task.Status)
				continue
			}
		}
		task.Status = taskExecuting
		c.mu.Lock()
		if r := c.semanticTasks[task.ID]; r != nil {
			r.Status = taskExecuting
			r.Attempts++
		}
		c.mu.Unlock()
		c.mu.Lock()
		c.activeTask = task
		c.mu.Unlock()
		log.Printf("WORKFLOW_TASK_EXECUTING task_id=%s category=%s page=%s selector=%s status=%s", task.ID, task.Category, task.PageURL, task.Selector, task.Status)
		if task.Category == workflowForm && strings.Contains(task.PageURL, "/client/") {
			log.Printf("PROTECTED_FORM_EXECUTING task_id=%s page=%s selector=%s", task.ID, task.PageURL, task.Selector)
		}
		beforeURL := task.PageURL
		taskStarted := time.Now()
		if c.yieldCallback != nil {
			c.yieldCallback(task, "__BASELINE__", 0)
		}
		taskCtx, cancel := context.WithTimeout(pageCtx, 8*time.Second)
		var taskErr error
		if task.Category == workflowForm && task.Form != nil && classifyAuthForm(*task.Form, task.PageURL).IsAuth {
			c.mu.Lock()
			state, attempts := c.authState, c.authInitialAttempts
			c.mu.Unlock()
			if state == authAuthenticated || attempts >= authAttemptLimit() {
				cancel()
				task.Status = taskSkipped
				log.Printf("AUTH_FALSE_POSITIVE_SKIPPED page=%s reason=global_session_guard", task.PageURL)
				continue
			}
			c.mu.Lock()
			c.authInitialAttempts++
			c.authState = authAuthenticating
			c.mu.Unlock()
		}
		switch task.Category {
		case workflowForm:
			var result interactionResult
			setup := fmt.Sprintf(`window.__raptorTargetFormSelector=%q;window.__raptorSubmittedForms=new WeakSet();window.__raptorTrustedSubmission=false`, task.Selector)
			taskErr = chromedp.Run(taskCtx, chromedp.Evaluate(setup, nil), chromedp.ActionFunc(func(ctx context.Context) error {
				return evaluateAsyncInteraction(ctx, fmt.Sprintf(safeInteractionJS, formInteractionJS), &result)
			}), chromedp.Evaluate(`window.__raptorTargetFormSelector=''`, nil))
			if taskErr == nil && result.Submitted == 0 {
				taskErr = fmt.Errorf("trusted form engine did not submit: last_step=%s error=%s valid=%v", result.LastStep, result.Error, result.FormValid)
			}
			if taskErr == nil {
				log.Printf("DYNAMIC_FORM_EXECUTED task_id=%s page=%s form=%s submitted=%d", task.ID, task.PageURL, task.Selector, result.Submitted)
			}
		case workflowControl:
			if strings.EqualFold(task.SemanticType, "search") {
				taskErr = chromedp.Run(taskCtx, chromedp.ScrollIntoView(task.Selector, chromedp.ByQuery), chromedp.Click(task.Selector, chromedp.ByQuery), chromedp.KeyEvent("a", chromedp.KeyModifiers(input.ModifierCtrl)), chromedp.KeyEvent(kb.Backspace), chromedp.SendKeys(task.Selector, "raptor test", chromedp.ByQuery), chromedp.KeyEvent(kb.Enter), chromedp.Sleep(400*time.Millisecond))
			} else {
				taskErr = chromedp.Run(taskCtx, chromedp.ScrollIntoView(task.Selector, chromedp.ByQuery), chromedp.Click(task.Selector, chromedp.ByQuery), chromedp.Sleep(400*time.Millisecond))
			}
		}
		cancel()
		c.mu.Lock()
		if c.activeTask == task {
			c.activeTask = nil
		}
		c.mu.Unlock()
		if taskErr != nil {
			probeCtx, probeCancel := context.WithTimeout(pageCtx, 3*time.Second)
			probe, probeErr := c.liveDOMSnapshot(probeCtx)
			probeCancel()
			if probeErr == nil && probe.URL != beforeURL {
				taskErr = nil
				log.Printf("WORKFLOW_NAVIGATION_DETECTED_AFTER_CONTEXT_REPLACED task_id=%s old_page=%s new_page=%s", task.ID, beforeURL, probe.URL)
			}
		}
		if taskErr != nil {
			task.Status, task.FailureReason = taskFailed, taskErr.Error()
			c.mu.Lock()
			if r := c.semanticTasks[task.ID]; r != nil {
				if r.Attempts < r.MaxAttempts {
					r.Status = taskFailedRetryable
				} else {
					r.Status = taskFailedFinal
				}
				r.LastFailure = task.FailureReason
			}
			c.mu.Unlock()
			log.Printf("WORKFLOW_TASK_RESULT task_id=%s category=%s status=%s reason=%q", task.ID, task.Category, task.Status, task.FailureReason)
			if task.Category == workflowForm && strings.Contains(task.PageURL, "/client/") {
				log.Printf("PROTECTED_FORM_FAILED task_id=%s page=%s reason=%q", task.ID, task.PageURL, task.FailureReason)
			}
			if task.RecordIdentity != "" && task.FailureReason != "stale_dom" {
				recordActionSamples[task.RecordActionKey]++
			}
			if c.yieldCallback != nil {
				c.yieldCallback(task, "FAILED", time.Since(taskStarted))
			}
			continue
		}
		task.Status = taskCompleted
		if task.RecordIdentity != "" {
			recordActionSamples[task.RecordActionKey]++
		}
		c.mu.Lock()
		if r := c.semanticTasks[task.ID]; r != nil {
			r.Status = taskCompleted
			r.CompletedAt = time.Now()
		}
		c.mu.Unlock()
		hadApplicationRequest := false
		select {
		case <-applicationRequest:
			hadApplicationRequest = true
		default:
		}
		if c.yieldCallback != nil {
			status := "NO_YIELD"
			if hadApplicationRequest {
				status = "NEW_ENDPOINT"
			}
			c.yieldCallback(task, status, time.Since(taskStarted))
		}
		log.Printf("WORKFLOW_TASK_RESULT task_id=%s category=%s status=%s", task.ID, task.Category, task.Status)
		if task.Category == workflowForm && strings.Contains(task.PageURL, "/client/") {
			log.Printf("PROTECTED_FORM_COMPLETED task_id=%s page=%s", task.ID, task.PageURL)
		}

		taskCtx, cancel = context.WithTimeout(pageCtx, 8*time.Second)
		fresh, rediscoverErr := c.liveDOMSnapshot(taskCtx)
		cancel()
		if rediscoverErr != nil {
			log.Printf("WORKFLOW_REDISCOVERY_FAILED task_id=%s reason=%v", task.ID, rediscoverErr)
			continue
		}
		navigated := fresh.URL != beforeURL
		if navigated {
			for _, pendingTask := range queue {
				if pendingTask.PageURL == beforeURL {
					pendingTask.Status = taskInvalidated
					c.mu.Lock()
					if r := c.semanticTasks[pendingTask.ID]; r != nil {
						r.Status = taskInvalidated
					}
					c.mu.Unlock()
					log.Printf("WORKFLOW_TASK_INVALIDATED task_id=%s caused_by=%s status=%s old_page=%s new_page=%s", pendingTask.ID, task.ID, pendingTask.Status, beforeURL, fresh.URL)
				}
			}
			filtered := queue[:0]
			for _, pendingTask := range queue {
				if pendingTask.Status != taskInvalidated {
					filtered = append(filtered, pendingTask)
				}
			}
			queue = filtered
			log.Printf("WORKFLOW_NAVIGATION_REDISCOVERY task_id=%s old_page=%s new_page=%s dom_state=%s", task.ID, beforeURL, fresh.URL, fresh.DOMFingerprint)
		}
		currentPageURL = fresh.URL
		log.Printf("DYNAMIC_FORM_DISCOVERY page=%s forms=%d controls=%d caused_by=%s", currentPageURL, len(fresh.Forms), len(fresh.Controls), task.ID)
		if processRoutes != nil {
			processRoutes(fresh)
		}
		enqueue(fresh, true)
	}
	if len(queue) > 0 {
		c.mu.Lock()
		for _, abandoned := range queue {
			if r := c.semanticTasks[abandoned.ID]; r != nil && r.Status == taskQueued {
				r.Status = taskFailedRetryable
				r.LastFailure = "workflow_queue_abandoned"
			}
		}
		c.mu.Unlock()
		log.Printf("WORKFLOW_SAFETY_GUARD_REACHED max_tasks=%d pending=%d", maxTasks, len(queue))
	} else {
		log.Printf("WORKFLOW_QUEUE_DRAINED page=%s pending=0 executing=0 navigation_pending=false", currentPageURL)
	}
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
	applicationRequest := make(chan struct{}, 1)

	// Listen for network events
	chromedp.ListenTarget(navCtx, func(ev interface{}) {
		switch e := ev.(type) {
		case *runtime.EventConsoleAPICalled:
			var parts []string
			for _, arg := range e.Args {
				value := strings.TrimSpace(string(arg.Value))
				if strings.HasPrefix(value, `"`) {
					var decoded string
					if json.Unmarshal(arg.Value, &decoded) == nil {
						value = decoded
					}
				}
				if value == "" {
					value = strings.TrimSpace(string(arg.UnserializableValue))
				}
				if value == "" {
					value = arg.Description
				}
				if value == "" {
					if raw, err := json.Marshal(arg); err == nil {
						value = string(raw)
					}
				}
				parts = append(parts, redactConsoleValue(value))
			}
			log.Printf("CONSOLE [%s]: %s", e.Type, strings.Join(parts, " "))
			if strings.Contains(strings.Join(parts, " "), "__RAPTOR_SUBMIT_HANDLER__") {
				log.Printf("APPLICATION SUBMIT HANDLER EVENT OBSERVED")
			}
			for _, part := range parts {
				if strings.HasPrefix(part, "__RAPTOR_WS__") {
					log.Printf("BROWSER WEBSOCKET HOOK: %s", strings.TrimPrefix(part, "__RAPTOR_WS__"))
				}
			}
			for _, part := range parts {
				if strings.HasPrefix(part, "__RAPTOR_REQ__") {
					c.emitHookRequest(strings.TrimPrefix(part, "__RAPTOR_REQ__"), depth)
				}
			}
		case *runtime.EventExceptionThrown:
			description := ""
			if e.ExceptionDetails.Exception != nil {
				description = e.ExceptionDetails.Exception.Description
			}
			log.Printf("PAGE ERROR: text=%s description=%s url=%s line=%d column=%d", e.ExceptionDetails.Text, description, e.ExceptionDetails.URL, e.ExceptionDetails.LineNumber, e.ExceptionDetails.ColumnNumber)
		case *network.EventRequestWillBeSent:
			if e.Request.Method != "GET" {
				log.Printf("CDP_REQUEST_SEEN id=%s method=%s url=%s body_len=0 source_type=unknown", e.RequestID, e.Request.Method, e.Request.URL)
			}
			if isApplicationActivity(e.Request.Method, e.Request.URL, e.Type) {
				select {
				case applicationRequest <- struct{}{}:
				default:
				}
			}
			c.trackRequest(navCtx, e, depth)
		case *fetchproto.EventRequestPaused:
			if e.Request.Method != "GET" {
				log.Printf("FETCH DOMAIN NON-GET: method=%s url=%s", e.Request.Method, e.Request.URL)
			}
			go func(id fetchproto.RequestID, method, rawURL string) {
				err := chromedp.Run(c.browserCtx, fetchproto.ContinueRequest(id))
				if method != "GET" {
					if err != nil {
						log.Printf("FETCH_CONTINUE_ERROR id=%s method=%s url=%s body_len=0 source_type=unknown error=%v", id, method, rawURL, err)
					} else {
						log.Printf("FETCH_CONTINUE_SUCCESS id=%s method=%s url=%s body_len=0 source_type=unknown", id, method, rawURL)
					}
				}
			}(e.RequestID, e.Request.Method, e.Request.URL)
		case *network.EventRequestWillBeSentExtraInfo:
			c.mergeExtraRequestHeaders(e)
		case *network.EventLoadingFinished:
			c.captureStaticScript(navCtx, e.RequestID, depth, targetURL)
			c.updateLifecycle(e.RequestID, "completed", "")
			c.mu.Lock()
			delete(c.pending, e.RequestID)
			c.mu.Unlock()
		case *network.EventResponseReceived:
			method := ""
			c.mu.RLock()
			if pending := c.pending[e.RequestID]; pending != nil {
				method = pending.method
			}
			c.mu.RUnlock()
			if method != "GET" {
				log.Printf("RESPONSE: status=%d method=%s url=%s", e.Response.Status, method, e.Response.URL)
			}
			c.completeRequest(e, depth)
		case *network.EventLoadingFailed:
			log.Printf("REQUEST FAILED: request_id=%s error=%s", e.RequestID, e.ErrorText)
			c.updateLifecycle(e.RequestID, "failed", e.ErrorText)
			c.mu.Lock()
			delete(c.pending, e.RequestID)
			c.mu.Unlock()
		}
	})

	var observedRenderedHrefs []string
	err := chromedp.Run(navCtx,
		network.Enable(),
		// Pause only API-capable resource classes; pausing documents/scripts can
		// deadlock navigation before the DOM exists if a target emits events late.
		fetchproto.Enable().WithPatterns([]*fetchproto.RequestPattern{
			{ResourceType: network.ResourceTypeXHR, RequestStage: fetchproto.RequestStageRequest},
			{ResourceType: network.ResourceTypeFetch, RequestStage: fetchproto.RequestStageRequest},
		}),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(requestHookJS).Do(ctx)
			return err
		}),
		chromedp.Navigate(targetURL),
		chromedp.WaitReady("body", chromedp.ByQuery),
	)
	if err != nil {
		c.callback(nil, fmt.Errorf("navigating %s: %w", targetURL, err))
		return next
	}
	settle, hrefs, err := c.waitForRenderedDOM(navCtx)
	if err != nil {
		c.callback(nil, fmt.Errorf("settling DOM for %s: %w", targetURL, err))
		return next
	}
	observedRenderedHrefs = hrefs
	snap, err := c.liveDOMSnapshot(navCtx)
	if err != nil {
		c.callback(nil, fmt.Errorf("taking authoritative DOM snapshot for %s: %w", targetURL, err))
		return next
	}
	c.mu.RLock()
	currentAuth := c.authState
	c.mu.RUnlock()
	if currentAuth == authAuthenticated && !isAuthPageURL(targetURL) && isAuthPageURL(snap.URL) {
		c.mu.Lock()
		c.authState = authSessionLost
		c.mu.Unlock()
		log.Printf("AUTH_REDIRECT_TO_SIGNIN requested_url=%s final_location=%s", targetURL, snap.URL)
		log.Printf("AUTH_SESSION_LOST requested_url=%s", targetURL)
		return next
	}
	log.Printf("DOM_SNAPSHOT page=%s snapshot_url=%s ready_state=%s links=%d forms=%d controls=%d scripts=%d dom_state=%s",
		targetURL, snap.URL, snap.ReadyState, len(snap.Links), len(snap.Forms), len(snap.Controls), len(snap.Scripts), snap.DOMFingerprint)
	c.mu.RLock()
	initialTraces := append([]runtimeRequestTrace(nil), c.runtimeTraces...)
	c.mu.RUnlock()
	// Preserve document route discovery before any workflow interaction can
	// navigate or replace the DOM that produced this snapshot.
	c.extractRouteCandidates(snap, initialTraces, targetURL, depth, seenPaths, &next)
	// Mutation settling records anchors across the bounded hydration window.
	// These are route observations, not fields merged into the authoritative
	// post-settle snapshot used by workflows.
	if len(observedRenderedHrefs) > 0 {
		observed := domSnapshot{URL: settle.URL}
		for _, href := range observedRenderedHrefs {
			observed.Links = append(observed.Links, struct {
				Href string `json:"href"`
			}{Href: href})
		}
		c.extractRouteCandidates(observed, nil, targetURL, depth, seenPaths, &next)
	}
	for _, f := range snap.Forms {
		log.Printf("FORM FOUND: action=%s fields=%d", f.Action, len(f.Fields))
	}
	trustedAttempted := false
	navigatedDuringInitialForms := false
	for formIndex, form := range snap.Forms {
		if form.Selector == "" || form.SubmitSelector == "" {
			continue
		}
		attemptKey := formWorkflowFingerprint(c.canonicalizeURL(targetURL), snap.ActiveOverlay, snap.VisibleStepTitle, form.Fields, form.SubmitLabel)
		c.mu.Lock()
		alreadyAttempted := false
		if rec := c.semanticTasks[attemptKey]; rec != nil && (rec.Status == taskQueued || rec.Status == taskExecuting || rec.Status == taskCompleted || rec.Status == taskFailedFinal) {
			alreadyAttempted = true
		} else {
			c.semanticTasks[attemptKey] = &semanticTaskRecord{ID: attemptKey, Category: workflowForm, PageURL: targetURL, Selector: form.Selector, Status: taskExecuting, Attempts: 1, MaxAttempts: 1, LastDOM: snap.DOMFingerprint}
		}
		c.mu.Unlock()
		if alreadyAttempted {
			continue
		}
		authInfo := classifyAuthForm(form, snap.URL)
		isAuthForm := authInfo.IsAuth
		if isAuthForm {
			log.Printf("AUTH_FORM_CANDIDATE requested_page=%s snapshot_url=%s current_location=%s form_selector=%s submit_label=%s field_semantics=%v confidence=%d positive_evidence=%v negative_evidence=%v reason=%s", targetURL, snap.URL, snap.URL, form.Selector, form.SubmitLabel, authFieldSemantics(form), authInfo.Confidence, authInfo.Positive, authInfo.Negative, authInfo.Reason)
		}
		if isAuthForm {
			c.mu.Lock()
			state := c.authState
			attempts := c.authInitialAttempts
			reauth := c.authReauthAttempts
			c.mu.Unlock()
			max := authAttemptLimit()
			if state == authAuthenticated {
				if isAuthPageURL(snap.URL) {
					c.mu.Lock()
					c.authState = authSessionLost
					c.mu.Unlock()
					log.Printf("AUTH_REDIRECT_TO_SIGNIN requested_url=%s final_location=%s", targetURL, snap.URL)
					log.Printf("AUTH_SESSION_LOST requested_url=%s final_location=%s", targetURL, snap.URL)
					state = authSessionLost
				} else {
					log.Printf("AUTH_FALSE_POSITIVE_SKIPPED page=%s reason=session_already_authenticated", snap.URL)
					continue
				}
			}
			if state == authSessionLost {
				allow := strings.EqualFold(os.Getenv("RAPTOR_ALLOW_REAUTH"), "true")
				rmax := 1
				if v, e := strconv.Atoi(os.Getenv("RAPTOR_REAUTH_MAX_ATTEMPTS")); e == nil && v > 0 {
					rmax = v
				}
				if !allow || reauth >= rmax {
					log.Printf("AUTH_REAUTH_SKIPPED_POLICY page=%s", snap.URL)
					continue
				}
				c.mu.Lock()
				c.authReauthAttempts++
				c.authState = authReauthenticating
				c.mu.Unlock()
			} else {
				if attempts >= max {
					log.Printf("AUTH_FALSE_POSITIVE_SKIPPED page=%s reason=global_attempt_limit", snap.URL)
					continue
				}
				c.mu.Lock()
				c.authInitialAttempts++
				c.authState = authAuthenticating
				c.mu.Unlock()
			}
		}
		trustedAttempted = true
		if isAuthForm {
			c.authBaseline = c.captureAuthEvidence(navCtx, form)
			c.mu.Lock()
			c.authAttempts++
			c.mu.Unlock()
			log.Printf("AUTH_FORM_IDENTIFIED page=%s snapshot_url=%s selector=%s attempt_id=%s", snap.URL, snap.URL, form.Selector, attemptKey)
			log.Printf("AUTH_ATTEMPT_STARTED page=%s selector=%s attempt_id=%s", snap.URL, form.Selector, attemptKey)
		}
		attemptID := fmt.Sprintf("form-%d-%d", formIndex, time.Now().UnixNano())
		reset := fmt.Sprintf(`window.__raptorFlow={attemptId:%q,attemptTimestamp:Date.now(),expectedFormSelector:%q,expectedSubmitSelector:%q,clicks:0,submits:0,preventDefault:false,fetchCalls:0,xhrOpenCalls:0,xhrSendCalls:0,beaconCalls:0,wsCalls:0,applicationRequests:[],submitDiagnostic:null,runtimeErrors:[]}`, attemptID, form.Selector, form.SubmitSelector)
		if err := chromedp.Run(navCtx, chromedp.Evaluate(reset, nil)); err != nil {
			log.Printf("INTERACTION_OUTCOME: FORM_INTERACTION_TIMEOUT")
			continue
		}
		log.Printf("TRUSTED_INTERACTION_START attempt=%s form=%s fields=%d submit=%s", attemptID, form.Selector, len(form.Fields), form.SubmitSelector)
		fillFailed := false
		fillOutcome := "FIELD_INTERACTION_TIMEOUT"
		failureReason := "unknown interaction failure"
		lastType, lastRole := "", ""
		for fieldIndex, field := range form.Fields {
			selector, _ := field["selector"].(string)
			typ, _ := field["type"].(string)
			lastType = typ
			disabled, _ := field["disabled"].(bool)
			readonly, _ := field["readonly"].(bool)
			semantic := semanticFieldType(field, targetURL)
			log.Printf("FIELD_DISCOVERED page=%s form=%s index=%d total=%d selector=%s type=%s semantic=%s name=%s id=%s required=%t disabled=%t readonly=%t", targetURL, form.Selector, fieldIndex, len(form.Fields), selector, typ, semantic, strOr(field["name"]), strOr(field["id"]), fieldBool(field, "required"), disabled, readonly)
			if selector == "" || disabled || readonly || typ == string(FieldHidden) {
				if disabled {
					log.Printf("FIELD_SKIPPED selector=%s reason=CONTROL_DISABLED", selector)
				}
				if typ == string(FieldHidden) {
					log.Printf("FIELD_SKIPPED selector=%s reason=FIELD_HIDDEN", selector)
				}
				continue
			}
			fieldStart := time.Now()
			log.Printf("FIELD_INTERACTION_START page=%s form=%s index=%d selector=%s", targetURL, form.Selector, fieldIndex, selector)
			fieldCtx, cancelField := context.WithTimeout(navCtx, 4*time.Second)
			if strings.EqualFold(typ, "file") {
				required := fieldBool(field, "required")
				uploadDir := strings.TrimSpace(os.Getenv("RAPTOR_UPLOAD_DIR"))
				allowed := strings.EqualFold(os.Getenv("RAPTOR_ALLOW_FILE_UPLOADS"), "true")
				if !allowed || uploadDir == "" {
					cancelField()
					if required {
						fillFailed = true
						fillOutcome = "REQUIRED_FILE_UPLOAD_NOT_CONFIGURED"
						log.Printf("REQUIRED_FILE_UPLOAD_NOT_CONFIGURED selector=%s accept=%s", selector, strOr(field["accept"]))
					} else {
						log.Printf("FILE_INPUT_OPTIONAL_SKIPPED selector=%s", selector)
					}
					if fillFailed {
						break
					}
					continue
				}
				filePath := chooseUploadFile(uploadDir, strOr(field["accept"]))
				if filePath == "" {
					cancelField()
					fillFailed = required
					fillOutcome = "FIELD_REQUIRED_UNSUPPORTED"
					log.Printf("FILE_UPLOAD_FAILED selector=%s reason=no_compatible_file", selector)
					if fillFailed {
						break
					}
					continue
				}
				err := chromedp.Run(fieldCtx, chromedp.SetUploadFiles(selector, []string{filePath}), chromedp.Sleep(100*time.Millisecond))
				var count int
				if err == nil {
					err = chromedp.Run(fieldCtx, chromedp.Evaluate(fmt.Sprintf(`(document.querySelector(%q).files||[]).length`, selector), &count))
				}
				cancelField()
				if err != nil || count == 0 {
					fillFailed = required
					fillOutcome = "FIELD_FAILED"
					failureReason = "file upload failed"
					log.Printf("FILE_UPLOAD_FAILED selector=%s error=%v", selector, err)
				} else {
					log.Printf("FILE_UPLOAD_SUCCESS selector=%s filename=%s", selector, filepath.Base(filePath))
				}
				if fillFailed {
					break
				}
				continue
			}
			role := strings.ToLower(strOr(field["role"]))
			lastRole = role
			if strings.EqualFold(typ, "select") || strings.HasPrefix(strings.ToLower(typ), "select-") || role == "combobox" || role == "listbox" {
				// Prefer trusted interaction with the control, then choose the first
				// enabled, non-placeholder option exposed by the browser.
				err := chromedp.Run(fieldCtx, chromedp.ScrollIntoView(selector), chromedp.Click(selector), chromedp.Sleep(100*time.Millisecond), chromedp.Evaluate(fmt.Sprintf(`(()=>{const root=document.querySelector(%q); if(root&&root.tagName==='SELECT'){const o=[...root.options].find(x=>!x.disabled&&x.value); if(o){root.value=o.value; root.dispatchEvent(new Event('change',{bubbles:true})); return true}} const o=document.querySelector('[role="option"]:not([aria-disabled="true"])'); if(o){o.click(); return true} return false})()`, selector), nil))
				cancelField()
				if err != nil {
					fillFailed = true
					log.Printf("FIELD_INTERACTION_FAILED page=%s form=%s index=%d selector=%s reason=custom_control:%v", targetURL, form.Selector, fieldIndex, selector, err)
				} else {
					log.Printf("FIELD_INTERACTION_SUCCESS page=%s form=%s index=%d selector=%s elapsed_ms=%d", targetURL, form.Selector, fieldIndex, selector, time.Since(fieldStart).Milliseconds())
				}
				if fillFailed {
					break
				}
				continue
			}
			switch strings.ToLower(typ) {
			case "checkbox", "radio":
				required, _ := field["required"].(bool)
				if !required {
					continue
				}
				var checked bool
				if err := chromedp.Run(fieldCtx, chromedp.Evaluate(fmt.Sprintf(`!!document.querySelector(%q).checked`, selector), &checked)); err != nil {
					fillFailed = true
				} else if !checked {
					fillFailed = chromedp.Run(fieldCtx, chromedp.Click(selector), chromedp.Sleep(75*time.Millisecond), chromedp.Evaluate(fmt.Sprintf(`!!document.querySelector(%q).checked`, selector), &checked)) != nil || !checked
				}
			default:
				value := generatedFieldValue(field, semantic, form.Fields)
				if isAuthForm {
					name := strings.ToLower(strings.Join([]string{strOr(field["name"]), strOr(field["id"]), strOr(field["label"]), strOr(field["autocomplete"]), typ}, " "))
					if strings.Contains(name, "password") && strings.TrimSpace(os.Getenv("RAPTOR_AUTH_PASSWORD")) != "" {
						value = os.Getenv("RAPTOR_AUTH_PASSWORD")
					}
					if (strings.Contains(name, "user") || strings.Contains(name, "login") || strings.Contains(name, "email")) && strings.TrimSpace(os.Getenv("RAPTOR_AUTH_USERNAME")) != "" {
						value = os.Getenv("RAPTOR_AUTH_USERNAME")
					}
				}
				if semantic == "email" && strings.TrimSpace(os.Getenv("RAPTOR_CONTROLLED_TEST_EMAIL")) != "" {
					value = strings.TrimSpace(os.Getenv("RAPTOR_CONTROLLED_TEST_EMAIL"))
				}
				log.Printf("FIELD_VALUE_GENERATED page=%s form=%s index=%d category=%s value_len=%d", targetURL, form.Selector, fieldIndex, semantic, len(value))
				switch semantic {
				case "email":
					if value == "" {
						value = "raptor.test@example.com"
					}
				case "password":
					if value == "" {
						value = "Test1234!"
					}
				}
				err := chromedp.Run(fieldCtx,
					chromedp.ScrollIntoView(selector), chromedp.Click(selector), chromedp.Focus(selector),
					chromedp.KeyEvent("a", chromedp.KeyModifiers(input.ModifierCtrl)),
					chromedp.KeyEvent(kb.Backspace),
					chromedp.SendKeys(selector, value),
					chromedp.KeyEvent(kb.Tab),
					chromedp.Sleep(75*time.Millisecond),
				)
				var actual string
				if err == nil {
					err = chromedp.Run(fieldCtx, chromedp.Evaluate(fmt.Sprintf(`document.querySelector(%q).value`, selector), &actual))
				}
				if err != nil || actual != value {
					fillFailed = true
					failureReason = "value verification failed"
					if errors.Is(err, context.DeadlineExceeded) {
						fillOutcome = unsupportedFieldOutcome(typ, role)
						failureReason = "field interaction deadline"
					}
					log.Printf("TRUSTED_FIELD_VERIFY_FAILED selector=%s type=%s expected_len=%d actual_len=%d error=%v", selector, typ, len(value), len(actual), err)
				} else {
					log.Printf("TRUSTED_FIELD_VERIFIED selector=%s type=%s value_len=%d", selector, typ, len(actual))
					var syncState struct {
						DOMValueLen  int  `json:"domValueLen"`
						FormValueLen int  `json:"formValueLen"`
						Persisted    bool `json:"persisted"`
						Focused      bool `json:"focused"`
					}
					diag := fmt.Sprintf(`(()=>{const e=document.querySelector(%q),f=e&&e.form;let v=e&&('value' in e?e.value:(e.textContent||''));let fv='';if(f&&e&&e.name){const x=new FormData(f).getAll(e.name);fv=x.length?String(x[x.length-1]):''}return {domValueLen:String(v||'').length,formValueLen:String(fv||'').length,persisted:String(v||'')===String(%q),focused:document.activeElement===e}})()`, selector, value)
					_ = chromedp.Run(fieldCtx, chromedp.Evaluate(diag, &syncState))
					status := "SYNCED_DOM_AND_EVENTS"
					fieldName := strOr(field["name"])
					if fieldName == "" {
						status = "FORMDATA_NOT_APPLICABLE"
					} else if syncState.FormValueLen > 0 {
						status = "FORMDATA_SYNCHRONIZED"
					} else if !syncState.Persisted {
						status = "STATE_NOT_SYNCHRONIZED"
					}
					log.Printf("CONTROLLED_FIELD_SYNC_RESULT selector=%s dom_value_len=%d formdata_value_len=%d persisted_after_blur=%t focused=%t status=%s", selector, syncState.DOMValueLen, syncState.FormValueLen, syncState.Persisted, syncState.Focused, status)
				}
			}
			cancelField()
			if !fillFailed {
				log.Printf("FIELD_INTERACTION_SUCCESS page=%s form=%s index=%d selector=%s elapsed_ms=%d", targetURL, form.Selector, fieldIndex, selector, time.Since(fieldStart).Milliseconds())
			} else {
				log.Printf("FIELD_INTERACTION_FAILED page=%s form=%s index=%d selector=%s reason=interaction_error", targetURL, form.Selector, fieldIndex, selector)
			}
			if fillFailed {
				break
			}
		}
		if fillFailed {
			log.Printf("FIELD_EXECUTION_FAILURE page=%s form=%s field_type=%s reason=%s supported_strategy=%s", targetURL, form.Selector, lastType, failureReason, fieldStrategy(lastType, lastRole))
			log.Printf("INTERACTION_OUTCOME: %s", fillOutcome)
			continue
		}
		_ = chromedp.Run(navCtx, chromedp.Sleep(200*time.Millisecond))
		var preflight struct {
			Valid, Present, Disabled, AriaDisabled bool
		}
		preflightJS := fmt.Sprintf(`(()=>{const f=document.querySelector(%q),s=document.querySelector(%q);return {valid:!!f&&f.checkValidity(),present:!!s,disabled:!!s&&s.disabled,ariaDisabled:!!s&&s.getAttribute('aria-disabled')==='true'}})()`, form.Selector, form.SubmitSelector)
		if err := chromedp.Run(navCtx, chromedp.Evaluate(preflightJS, &preflight)); err != nil || !preflight.Present {
			log.Printf("INTERACTION_OUTCOME: SUBMIT_CONTROL_NOT_FOUND")
			continue
		}
		log.Printf("FORM_VALID: %t", preflight.Valid)
		var preState string
		preStateJS := fmt.Sprintf(`(()=>{const f=document.querySelector(%q);if(!f)return '[]';return JSON.stringify([...f.elements].map(e=>{let fv='';if(e.name)try{const x=new FormData(f).getAll(e.name);fv=x.length?String(x[x.length-1]):''}catch(_){};return {name:e.name||'',id:e.id||'',type:e.type||e.tagName.toLowerCase(),domValueLen:('value'in e?String(e.value||'').length:0),hasName:!!e.name,formDataApplicable:!!e.name,formValueLen:fv.length,checked:!!e.checked,required:!!e.required,valid:e.validity?e.validity.valid:null,validationMessage:e.validationMessage||'',disabled:!!e.disabled,ariaInvalid:e.getAttribute('aria-invalid')||'',ariaDescribedBy:e.getAttribute('aria-describedby')||''}}))})()`, form.Selector)
		_ = chromedp.Run(navCtx, chromedp.Evaluate(preStateJS, &preState))
		log.Printf("PRE_SUBMIT_FORM_STATE page=%s form=%s state=%s", targetURL, form.Selector, preState)
		if preflight.Disabled || preflight.AriaDisabled {
			log.Printf("INTERACTION_OUTCOME: BUTTON_DISABLED")
			continue
		}
		if !preflight.Valid {
			log.Printf("INTERACTION_OUTCOME: FORM_INVALID")
			continue
		}
		postSetup := fmt.Sprintf(`(()=>{const f=document.querySelector(%q),s=document.querySelector(%q);const text=e=>(e&&e.innerText||'').trim();const vis=e=>!!e&&!!(e.offsetWidth||e.offsetHeight||e.getClientRects().length);const msgs=()=>[...document.querySelectorAll('[role="alert"],[aria-live],[aria-invalid="true"],[aria-describedby],dialog,.toast,.error,.validation-error')].filter(vis).map(text).filter(Boolean);const before={url:location.href,history:history.length,button:s?{disabled:!!s.disabled,ariaDisabled:s.getAttribute('aria-disabled'),text:text(s),loading:/load|progress|wait/i.test(text(s))}:null,messages:msgs()};const changes=[];const ob=new MutationObserver(ms=>ms.forEach(m=>changes.push({type:m.type,attribute:m.attributeName||'',added:m.addedNodes.length,removed:m.removedNodes.length,text:[...m.addedNodes].map(text).filter(Boolean).join(' ')})));ob.observe(document.documentElement,{subtree:true,childList:true,characterData:true,attributes:true,attributeFilter:['disabled','aria-disabled','aria-busy','class','value','hidden']});window.__raptorPostSubmit={f:f,button:s,before:before,changes:changes,observer:ob,msgs:msgs};})()`, form.Selector, form.SubmitSelector)
		_ = chromedp.Run(navCtx, chromedp.Evaluate(postSetup, nil))
		if err := chromedp.Run(navCtx, chromedp.Click(form.SubmitSelector)); err != nil {
			log.Printf("INTERACTION_OUTCOME: CLICK_NOT_DELIVERED")
			continue
		}
		log.Printf("TRUSTED_SUBMIT_CLICKED attempt=%s selector=%s", attemptID, form.SubmitSelector)
		deadline := time.NewTimer(2 * time.Second)
		ticker := time.NewTicker(50 * time.Millisecond)
		observedCDP := false
	waitLoop:
		for {
			select {
			case <-applicationRequest:
				observedCDP = true
				break waitLoop
			case <-ticker.C:
				var done bool
				_ = chromedp.Run(navCtx, chromedp.Evaluate(`(()=>{const f=window.__raptorFlow||{};return (f.applicationRequests||[]).length>0||(f.runtimeErrors||[]).length>0})()`, &done))
				if done {
					break waitLoop
				}
			case <-deadline.C:
				break waitLoop
			}
		}
		ticker.Stop()
		if !deadline.Stop() {
			select {
			case <-deadline.C:
			default:
			}
		}
		var flow map[string]interface{}
		_ = chromedp.Run(navCtx, chromedp.Sleep(20*time.Millisecond), chromedp.Evaluate(`window.__raptorFlow||{}`, &flow))
		var postState struct {
			FormState  interface{} `json:"formState"`
			Messages   []string    `json:"messages"`
			Changes    interface{} `json:"changes"`
			Button     interface{} `json:"button"`
			URLBefore  string      `json:"urlBefore"`
			URLAfter   string      `json:"urlAfter"`
			Navigation bool        `json:"navigation"`
		}
		postJS := `(()=>{const p=window.__raptorPostSubmit||{};if(p.observer)p.observer.disconnect();const f=p.f,s=p.button;const vis=e=>!!e&&!!(e.offsetWidth||e.offsetHeight||e.getClientRects().length);const val=e=>e&&('value'in e?String(e.value||''):String(e.textContent||''));const fs=f?[...f.elements].map(e=>({name:e.name||'',id:e.id||'',domValueLen:val(e).length,checked:!!e.checked,disabled:!!e.disabled,valid:e.validity?e.validity.valid:null,validationMessage:e.validationMessage||'',visible:vis(e),connected:e.isConnected})):[];const msgs=[...document.querySelectorAll('[role="alert"],[aria-live],[aria-invalid="true"],[aria-describedby],dialog,.toast,.error,.validation-error')].filter(vis).map(e=>String(e.innerText||'').trim()).filter(Boolean);const b=s?{disabled:!!s.disabled,ariaDisabled:s.getAttribute('aria-disabled'),text:String(s.innerText||'').trim(),loading:/load|progress|wait/i.test(String(s.innerText||''))||s.getAttribute('aria-busy')==='true',connected:s.isConnected}:null;return {formState:fs,messages:[...new Set(msgs)],changes:p.changes||[],button:b,urlBefore:p.before&&p.before.url||location.href,urlAfter:location.href,navigation:!!p.before&&p.before.url!==location.href}})()`
		_ = chromedp.Run(navCtx, chromedp.Evaluate(postJS, &postState))
		log.Printf("POST_SUBMIT_FORM_STATE page=%s form=%s state=%v", targetURL, form.Selector, postState.FormState)
		log.Printf("APPLICATION_DOM_CHANGE page=%s form=%s changes=%v", targetURL, form.Selector, postState.Changes)
		log.Printf("APPLICATION_VALIDATION_MESSAGE page=%s form=%s messages=%v", targetURL, form.Selector, postState.Messages)
		log.Printf("SUBMIT_BUTTON_STATE page=%s form=%s before=%v after=%v", targetURL, form.Selector, postState.URLBefore, postState.Button)
		if postState.Navigation {
			log.Printf("NAVIGATION_OBSERVED page=%s before=%s after=%s", targetURL, postState.URLBefore, postState.URLAfter)
			navigatedDuringInitialForms = true
		}
		raw, _ := json.Marshal(flow)
		log.Printf("APPLICATION_FLOW: %s", raw)
		outcome := classifyInteractionOutcome(flow, observedCDP)
		log.Printf("INTERACTION_OUTCOME: %s", outcome)
		c.mu.Lock()
		if rec := c.semanticTasks[attemptKey]; rec != nil {
			if observedCDP {
				rec.Status = taskCompleted
				rec.CompletedAt = time.Now()
			} else {
				rec.Status = taskFailed
				rec.LastFailure = outcome
			}
		}
		c.mu.Unlock()
		if isAuthForm {
			log.Printf("AUTH_REQUEST_OBSERVED page=%s attempt_id=%s", targetURL, attemptKey)
			authRequestObserved := c.authRequestCompleted(flow)
			authState, verifyErr := c.verifyAuthenticatedSession(navCtx, targetURL)
			if authRequestObserved && verifyErr == nil && authState.Established {
				log.Printf("AUTH_SESSION_ESTABLISHED page=%s snapshot_url=%s attempt_id=%s", targetURL, authState.Location, attemptKey)
				c.mu.Lock()
				c.authenticated = true
				c.authState = authAuthenticated
				c.authSuccessAttempt = attemptKey
				c.mu.Unlock()
			} else if strings.Contains(outcome, "VALIDATION") || !observedCDP {
				log.Printf("AUTH_FAILED page=%s attempt_id=%s", targetURL, attemptKey)
				c.mu.Lock()
				c.authState = authFailed
				c.mu.Unlock()
			} else {
				log.Printf("AUTH_SESSION_UNPROVEN page=%s final_location=%s reason=%v", targetURL, authState.Location, verifyErr)
				c.mu.Lock()
				c.authState = authFailed
				c.mu.Unlock()
			}
		}
		if outcome == "PREVENT_DEFAULT_WITHOUT_REQUEST" || outcome == "CLIENT_SIDE_EXCEPTION" || outcome == "NO_APPLICATION_REQUEST" {
			c.analyzeApplicationFailure(navCtx, snap.Scripts, targetURL, outcome, depth)
		}
		log.Printf("INTERACTION_STRATEGY: chromedp_keyboard_click")
		if navigatedDuringInitialForms {
			log.Printf("INITIAL_FORM_TASKS_INVALIDATED reason=navigation old_page=%s new_page=%s", postState.URLBefore, postState.URLAfter)
			break
		}
	}
	c.executeWorkflowQueue(navCtx, snap, targetURL, fmt.Sprintf("page-%x", sha256.Sum256([]byte(c.canonicalizeURL(targetURL)))), applicationRequest, func(fresh domSnapshot) {
		c.mu.RLock()
		traces := append([]runtimeRequestTrace(nil), c.runtimeTraces...)
		c.mu.RUnlock()
		c.extractRouteCandidates(fresh, traces, fresh.URL, depth, seenPaths, &next)
	})
	// The unified scheduler owns both initially empty and dynamically revealed
	// form states; do not invoke the legacy whole-document fallback afterward.
	trustedAttempted = true

	// Trigger application submit handlers in the live page. Any resulting
	// request is captured by trackRequest/completeRequest with its real body.
	var submittedForms interactionResult
	interactionScript := fmt.Sprintf(safeInteractionJS, formInteractionJS)
	if !trustedAttempted {
		if err := chromedp.Run(navCtx,
			chromedp.ActionFunc(func(ctx context.Context) error {
				return evaluateAsyncInteraction(ctx, interactionScript, &submittedForms)
			}),
			chromedp.ActionFunc(func(context.Context) error { log.Printf("WAITING FOR NETWORK..."); return nil }),
			chromedp.Sleep(5*time.Second),
			chromedp.ActionFunc(func(context.Context) error { log.Printf("DONE WAITING"); return nil }),
		); err != nil {
			log.Printf("form interaction on %s failed: %v", targetURL, err)
		} else if submittedForms.Interacted > 0 {
			log.Printf("SUBMITTING: %d interaction(s) on %s; persisting only observed network requests", submittedForms.Interacted, targetURL)
		}
	}
	log.Printf("INITIAL INTERACTION RESULT: changed=%t interacted=%d clicked=%d filled=%d submitted=%d discovered=%d continue=%t error=%s lastStep=%s lastElement=%s fieldStates=%d formData=%d submitDiagnostics=%d runtimeErrors=%d formValid=%v", submittedForms.Changed, submittedForms.Interacted, submittedForms.Clicked, submittedForms.Filled, submittedForms.Submitted, submittedForms.Discovered, submittedForms.ShouldContinue, submittedForms.Error, submittedForms.LastStep, submittedForms.LastElement, len(submittedForms.FieldStates), len(submittedForms.FormData), len(submittedForms.SubmitDiagnostics), len(submittedForms.RuntimeErrors), submittedForms.FormValid)
	log.Printf("INITIAL INTERACTION RESULT DETAILS: fieldStates=%d formData=%d submitDiagnostics=%d runtimeErrors=%d formValid=%v submitAttempted=%t submitEventObserved=%t", len(submittedForms.FieldStates), len(submittedForms.FormData), len(submittedForms.SubmitDiagnostics), len(submittedForms.RuntimeErrors), submittedForms.FormValid, submittedForms.SubmitAttempted, submittedForms.SubmitEventObserved)
	logInteractionDiagnostics(submittedForms)
	// Iteratively rediscover the live DOM. Newly rendered dialogs, tabs,
	// accordions and wizard steps get another interaction pass.
	for pass := 0; !trustedAttempted && pass < 5; pass++ {
		var changed interactionResult
		if err := chromedp.Run(navCtx,
			chromedp.Evaluate(mutationWaitJS, &changed),
			chromedp.ActionFunc(func(ctx context.Context) error {
				return evaluateAsyncInteraction(ctx, interactionScript, &submittedForms)
			}),
		); err != nil {
			log.Printf("interaction state exploration stopped on pass %d: %v", pass+1, err)
			break
		}
		log.Printf("INTERACTION STATE PASS: %d changed=%t interacted=%d clicked=%d filled=%d submitted=%d mutations=%d discovered=%d shouldContinue=%t error=%s", pass+1, changed.Changed, changed.Interacted, changed.Clicked, changed.Filled, changed.Submitted, changed.Mutations, changed.Discovered, changed.ShouldContinue, changed.Error)
		if changed.Error != "" {
			log.Printf("JavaScript interaction failure: %s", changed.Error)
			break
		}
		if !changed.ShouldContinue {
			break
		}
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

	// Final route pass includes RSC prefetches that arrived during workflows.
	c.mu.RLock()
	traces := append([]runtimeRequestTrace(nil), c.runtimeTraces...)
	c.mu.RUnlock()
	finalSnap, finalErr := c.liveDOMSnapshot(navCtx)
	if finalErr == nil {
		log.Printf("DOM_SNAPSHOT page=%s snapshot_url=%s ready_state=%s links=%d forms=%d controls=%d scripts=%d dom_state=%s phase=final",
			targetURL, finalSnap.URL, finalSnap.ReadyState, len(finalSnap.Links), len(finalSnap.Forms), len(finalSnap.Controls), len(finalSnap.Scripts), finalSnap.DOMFingerprint)
		c.extractRouteCandidates(finalSnap, traces, targetURL, depth, seenPaths, &next)
	}

	return next
}

func flowHasAuthRequest(flow map[string]interface{}) bool {
	xs, ok := flow["applicationRequests"].([]interface{})
	if !ok {
		return false
	}
	for _, raw := range xs {
		m, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		u := strings.ToLower(strOr(m["url"]))
		if strings.Contains(u, "/login") || strings.Contains(u, "/signin") || strings.Contains(u, "oauth") {
			return true
		}
	}
	return false
}
func (c *DynamicCrawler) authRequestCompleted(flow map[string]interface{}) bool {
	xs, ok := flow["applicationRequests"].([]interface{})
	if !ok {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, raw := range xs {
		m, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		method := strings.ToUpper(strOr(m["method"]))
		u := strOr(m["url"])
		// Authentication pages are documents.  The login API commonly shares
		// the same path (for example POST /Login), so URL page heuristics must
		// never reject a non-GET API request.
		if method == "GET" || method == "OPTIONS" || method == "HEAD" || strings.Contains(strings.ToLower(u), "_rsc") {
			continue
		}
		for _, p := range c.completedRequests {
			if p.url == u && strings.EqualFold(p.method, method) && p.response != nil && p.lifecycleState == "completed" {
				return p.response.StatusCode >= 200 && p.response.StatusCode < 400
			}
		}
		for _, p := range c.pending {
			if p.url == u && strings.EqualFold(p.method, method) && p.response != nil && p.lifecycleState == "completed" {
				return p.response.StatusCode >= 200 && p.response.StatusCode < 400
			}
		}
	}
	return false
}

type authVerification struct {
	Established       bool
	Location          string
	FormCount         int
	LogoutControl     bool
	CookieNamesHash   string
	LocalKeys         []string
	SessionKeys       []string
	CookieFingerprint string
	LocalHashes       map[string]string
	SessionHashes     map[string]string
}
type authEvidence struct {
	Location                   string
	CookieFingerprint          string
	LocalHashes, SessionHashes map[string]string
	LoginFingerprint           string
}

func isAuthPageURL(raw string) bool {
	u, _ := url.Parse(raw)
	p := strings.ToLower(u.Path)
	return strings.Contains(p, "/login") || strings.Contains(p, "/signin") || strings.Contains(p, "/sign-in") || strings.Contains(p, "/forgot-password")
}
func (c *DynamicCrawler) captureAuthEvidence(ctx context.Context, form domForm) authEvidence {
	var v struct {
		Location string            `json:"location"`
		Local    map[string]string `json:"local"`
		Session  map[string]string `json:"session"`
		Login    string            `json:"login"`
	}
	js := `(()=>{const digest=o=>{const r={};for(const k of Object.keys(o||{}).sort()){let s=String(o[k]||''),h=2166136261;for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,16777619)}r[k]=String(h>>>0)}return r};const f=[...document.querySelectorAll('form')].find(x=>x.contains(document.activeElement))||document.querySelector('form');return {location:location.href,local:digest(localStorage),session:digest(sessionStorage),login:f?String(f.outerHTML).replace(/value="[^"]*"/g,'value=""'):''}})()`
	_ = chromedp.Run(ctx, chromedp.Evaluate(js, &v))
	cookies, _ := network.GetCookies().Do(ctx)
	parts := []string{}
	for _, ck := range cookies {
		h := sha256.Sum256([]byte(ck.Value))
		parts = append(parts, fmt.Sprintf("%s|%s|%s|%x", ck.Name, ck.Domain, ck.Path, h[:]))
	}
	sort.Strings(parts)
	h := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return authEvidence{Location: v.Location, CookieFingerprint: fmt.Sprintf("%x", h[:]), LocalHashes: v.Local, SessionHashes: v.Session, LoginFingerprint: v.Login}
}
func (c *DynamicCrawler) verifyAuthenticatedSession(ctx context.Context, requested string) (authVerification, error) {
	var first, second authVerification
	js := `(()=>{const vis=e=>!!e&&!!(e.offsetWidth||e.offsetHeight||e.getClientRects().length);const fs=[...document.querySelectorAll('form')].filter(vis).filter(f=>[...f.querySelectorAll('input')].some(i=>(i.type||'').toLowerCase()==='password'));const controls=[...document.querySelectorAll('button,a,[role="button"]')].filter(vis).map(e=>(e.innerText||e.getAttribute('aria-label')||'').trim().toLowerCase());const names=s=>{try{return Object.keys(s||{}).sort()}catch(_){return []}};const cookies=(document.cookie||'').split(';').map(x=>x.split('=')[0].trim()).filter(Boolean).sort().join('|');let h=2166136261;for(const c of cookies){h^=c.charCodeAt(0)||0;h=Math.imul(h,16777619)};return {location:location.href,formCount:fs.length,logoutControl:controls.some(x=>x==='logout'||x==='log out'||x==='sign out'),cookieNamesHash:String(h>>>0),localKeys:names(localStorage),sessionKeys:names(sessionStorage)}})()`
	if err := chromedp.Run(ctx, chromedp.Evaluate(js, &first)); err != nil {
		return first, err
	}
	log.Printf("AUTH_POST_LOGIN_SETTLED requested_url=%s final_location=%s visible_login_forms=%d logout_control=%t", requested, first.Location, first.FormCount, first.LogoutControl)
	if err := chromedp.Run(ctx, chromedp.Sleep(350*time.Millisecond), chromedp.Evaluate(js, &second)); err != nil {
		return second, err
	}
	log.Printf("AUTH_STORAGE_EVIDENCE cookie_names_hash=%s local_storage_key_names=%v session_storage_key_names=%v", second.CookieNamesHash, second.LocalKeys, second.SessionKeys)
	postEvidence := c.captureAuthEvidence(ctx, domForm{})
	second.CookieFingerprint = postEvidence.CookieFingerprint
	second.LocalHashes = postEvidence.LocalHashes
	second.SessionHashes = postEvidence.SessionHashes
	stable := first.Location == second.Location && first.FormCount == second.FormCount && first.LogoutControl == second.LogoutControl && first.CookieNamesHash == second.CookieNamesHash
	strong := (!isAuthPageURL(second.Location) || second.FormCount == 0) && second.FormCount == 0 && (second.LogoutControl || c.authBaseline.CookieFingerprint != postEvidence.CookieFingerprint || authStorageDelta(c.authBaseline.LocalHashes, postEvidence.LocalHashes) || authStorageDelta(c.authBaseline.SessionHashes, postEvidence.SessionHashes))
	second.Established = stable && strong
	if !second.Established {
		return second, fmt.Errorf("stable_authenticated_evidence_absent")
	}
	log.Printf("AUTH_SESSION_ESTABLISHED location=%s", second.Location)
	return second, nil
}
func authStorageDelta(before, after map[string]string) bool {
	for k, v := range after {
		n := strings.ToLower(k)
		if strings.Contains(n, "token") || strings.Contains(n, "auth") || strings.Contains(n, "session") || strings.Contains(n, "user") || strings.Contains(n, "identity") || strings.Contains(n, "jwt") {
			if before[k] != v {
				return true
			}
		}
	}
	return false
}

func (c *DynamicCrawler) analyzeApplicationFailure(ctx context.Context, scripts []string, pageURL, outcome string, depth int) {
	_ = ctx
	log.Printf("APPLICATION_ANALYSIS_START page=%s outcome=%s scripts_considered=%d", pageURL, outcome, len(scripts))
	skipped, analyzed, bytes, candidates, reasons := 0, 0, 0, 0, 0
	for _, scriptURL := range scripts {
		if !c.IsInScope(scriptURL) {
			skipped++
			continue
		}
		lower := strings.ToLower(scriptURL)
		if strings.Contains(lower, "/_next/") && (strings.Contains(lower, "node_modules") || strings.Contains(lower, "turbopack") || strings.Contains(lower, "hmr")) {
			skipped++
			continue
		}
		c.mu.RLock()
		cached, ok := c.scriptBodies[scriptURL]
		c.mu.RUnlock()
		if !ok || cached.Body == "" || len(cached.Body) > c.config.MaxJSSize {
			skipped++
			continue
		}
		source := cached.Body
		analyzed++
		bytes += len(source)
		analysis := AnalyzeApplicationScript(source, scriptURL, pageURL)
		candidates += len(analysis.APICandidates)
		reasons += len(analysis.FailureReasonCandidates)
		log.Printf("APPLICATION_SCRIPT_ANALYZED url=%s hash=%s bytes=%d", scriptURL, cached.Hash, len(source))
		for i := range analysis.APICandidates {
			analysis.APICandidates[i].InteractionOutcome = outcome
			analysis.APICandidates[i].Evidence += "; interaction=" + outcome
			if store, err := NewRequestStore(c.config.DBPath); err == nil {
				_ = store.SaveStaticCandidate(analysis.APICandidates[i])
				_ = store.Close()
			}
			log.Printf("APPLICATION_API_CANDIDATE method=%s url=%s raw=%s line=%d confidence=%.2f outcome=%s", analysis.APICandidates[i].Method, analysis.APICandidates[i].URL, analysis.APICandidates[i].RawURLExpression, analysis.APICandidates[i].Line, analysis.APICandidates[i].Confidence, outcome)
		}
		for _, reason := range analysis.FailureReasonCandidates {
			log.Printf("APPLICATION_FAILURE_REASON condition=%s source=%s line=%d confidence=%.2f", reason.Condition, reason.SourceURL, reason.Line, reason.Confidence)
		}
	}
	log.Printf("APPLICATION_ANALYSIS_RESULT scripts_considered=%d scripts_skipped=%d scripts_analyzed=%d bytes=%d candidates=%d failure_reasons=%d", len(scripts), skipped, analyzed, bytes, candidates, reasons)
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
	// Form inspection is metadata only. Do not persist a guessed request;
	// Playwright's network events below are the source of truth.
	_ = contentTypeInfo
	return

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
func (c *DynamicCrawler) processForm(f domForm, targetURL string, depth int, seenPaths map[string]struct{}, next *[]string) {
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
	// Never turn an HTML form into a synthetic request. A real request is
	// emitted only from RequestWillBeSent/ResponseReceived interception after
	// the page's own submit handler executes.
	_ = contentTypeInfo
	return

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
			_ = contentTypeInfo
			continue

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

		for _, runtime := range ExtractRuntimeAPIEndpoints(body) {
			resolved := ResolveJSEndpoint(runtime.URL, jsURL, baseURL)
			if !c.IsInScope(resolved) {
				continue
			}
			sourceType := "js_discovered_api"
			if strings.Contains(strings.ToLower(runtime.URL), "graphql") {
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
					Method:        runtime.Method,
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
	if !c.IsInScope(e.Request.URL) && e.Request.Method == "GET" {
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
	if e.Request.Method != "GET" {
		log.Printf("REQUEST_BODY_EXTRACTED id=%s method=%s url=%s body_len=%d source_type=unknown", e.RequestID, e.Request.Method, e.Request.URL, len(postData))
	}
	logBody := redactSensitiveText(decodeJSONBodyIfBase64(postData))
	log.Printf("REQUEST: method=%s url=%s type=%s content_type=%s body=%s", e.Request.Method, e.Request.URL, e.Type, HeaderValue(headers, "Content-Type"), logBody)

	// Detect content type
	contentType := ""
	if ct, ok := headers["Content-Type"]; ok {
		contentType = strings.ToLower(ct)
	}
	if strings.Contains(contentType, "json") {
		postData = decodeJSONBodyIfBase64(postData)
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

	c.mu.Lock()
	var active workflowTask
	if c.activeTask != nil {
		active = *c.activeTask
	}
	c.pending[e.RequestID] = &pendingNetworkRequest{
		requestID:        e.RequestID,
		method:           e.Request.Method,
		url:              e.Request.URL,
		headers:          headers,
		body:             postData,
		depth:            reqDepth,
		isDocument:       isDoc,
		resourceTyp:      e.Type,
		startTime:        time.Now(),
		isFetch:          isFetch,
		initiator:        initiator,
		fetchCode:        fetchCode,
		contentType:      contentType,
		lifecycleState:   "observed",
		requestTimestamp: float64(time.Now().UnixNano()) / 1e9,
		pageURL:          active.PageURL, taskID: active.ID, taskSelector: active.Selector,
		interactionType: active.SemanticType, parentWorkflowID: active.ParentWorkflowID,
	}
	if active.Form != nil {
		for _, field := range active.Form.Fields {
			if fieldBool(field, "required") && !fieldBool(field, "disabled") {
				name := strOr(field["name"])
				if name == "" {
					name = strOr(field["id"])
				}
				if name != "" {
					c.pending[e.RequestID].requiredFields = append(c.pending[e.RequestID].requiredFields, name)
				}
			}
		}
		c.pending[e.RequestID].bodyCompletenessKnown = len(c.pending[e.RequestID].requiredFields) > 0
		c.pending[e.RequestID].bodyComplete = requestContainsRequiredFields(postData, contentType, c.pending[e.RequestID].requiredFields)
	}
	if e.Request.Method != "GET" {
		log.Printf("PENDING_REQUEST_CREATED id=%s method=%s url=%s body_len=%d source_type=unknown", e.RequestID, e.Request.Method, e.Request.URL, len(postData))
	}
	c.mu.Unlock()
	if e.Request.Method == "POST" || e.Request.Method == "PUT" || e.Request.Method == "PATCH" || e.Request.Method == "DELETE" {
		c.persistProvisional(e.RequestID)
	}

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
				pending.bodyComplete = requestContainsRequiredFields(pending.body, pending.contentType, pending.requiredFields)
			}
			c.mu.Unlock()
			c.persistProvisional(e.RequestID)
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

func (c *DynamicCrawler) persistProvisional(id network.RequestID) {
	c.mu.RLock()
	p := c.pending[id]
	if p == nil {
		c.mu.RUnlock()
		return
	}
	copy := *p
	c.mu.RUnlock()
	req := &DiscoveredRequest{ID: string(id), URL: copy.url, Method: copy.method, Headers: copy.headers, Body: copy.body, BodyType: bodyTypeFromContentType(copy.contentType), SourceType: "cdp_observed", Depth: copy.depth, NormalizedURL: NormalizeURL(copy.url), CDPRequestID: string(id), LifecycleState: copy.lifecycleState, RequestTimestamp: copy.requestTimestamp, CreatedAt: time.Now().UTC(), FetchDetails: &FetchDetails{Method: copy.method, URL: copy.url, Headers: copy.headers, Body: copy.body, BodyType: copy.contentType}, PageURL: copy.pageURL, TaskID: copy.taskID, TaskSelector: copy.taskSelector, InteractionType: copy.interactionType, ParentWorkflowID: copy.parentWorkflowID, BodyComplete: copy.bodyComplete, BodyCompletenessKnown: copy.bodyCompletenessKnown}
	if trace := c.matchingRuntimeTrace(copy.method, copy.url, copy.startTime); trace != nil {
		req.CallStack, req.ScriptURL = trace.Stack, trace.ScriptURL
	}
	c.callback(req, nil)
}

func (c *DynamicCrawler) updateLifecycle(id network.RequestID, state, reason string) {
	c.mu.Lock()
	p := c.pending[id]
	if p == nil {
		c.mu.Unlock()
		return
	}
	p.lifecycleState, p.failureReason = state, reason
	copy := *p
	if state == "completed" || state == "failed" || state == "timed_out" || state == "flushed_on_shutdown" {
		c.completedRequests[id] = copy
	}
	c.mu.Unlock()
	req := &DiscoveredRequest{ID: string(id), URL: copy.url, Method: copy.method, Headers: copy.headers, Body: copy.body, BodyType: bodyTypeFromContentType(copy.contentType), SourceType: "cdp_observed", Depth: copy.depth, NormalizedURL: NormalizeURL(copy.url), CDPRequestID: string(id), LifecycleState: state, FailureReason: reason, RequestTimestamp: copy.requestTimestamp, ResponseTimestamp: copy.responseTimestamp, Response: copy.response, CreatedAt: time.Now().UTC(), PageURL: copy.pageURL, TaskID: copy.taskID, TaskSelector: copy.taskSelector, InteractionType: copy.interactionType, ParentWorkflowID: copy.parentWorkflowID, BodyComplete: copy.bodyComplete, BodyCompletenessKnown: copy.bodyCompletenessKnown}
	if state == "completed" || state == "failed" || state == "timed_out" || state == "flushed_on_shutdown" {
		req.CompletedAt = time.Now().UTC()
	}
	if trace := c.matchingRuntimeTrace(copy.method, copy.url, copy.startTime); trace != nil {
		req.CallStack, req.ScriptURL = trace.Stack, trace.ScriptURL
	}
	c.callback(req, nil)
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

func (c *DynamicCrawler) emitHookRequest(raw string, depth int) {
	var v struct {
		Method, URL      string
		Headers          map[string]string
		Body, BodyType   string
		Stack, ScriptURL string
		Timestamp        int64
	}
	if json.Unmarshal([]byte(raw), &v) != nil || v.URL == "" || (!c.IsInScope(v.URL) && strings.EqualFold(v.Method, "GET")) {
		return
	}
	source := classifyRuntimeURL(v.Method, v.URL)
	if source == "framework_internal" {
		return
	}
	c.mu.Lock()
	c.runtimeTraces = append(c.runtimeTraces, runtimeRequestTrace{Method: strings.ToUpper(v.Method), URL: NormalizeURL(v.URL), BodyType: v.BodyType, Stack: v.Stack, ScriptURL: v.ScriptURL, Timestamp: v.Timestamp})
	if len(c.runtimeTraces) > 100 {
		c.runtimeTraces = append([]runtimeRequestTrace(nil), c.runtimeTraces[len(c.runtimeTraces)-100:]...)
	}
	c.mu.Unlock()
	log.Printf("RUNTIME_APPLICATION_CALL method=%s url=%s body_type=%s body_len=%d timestamp=%d", strings.ToUpper(v.Method), v.URL, v.BodyType, len(v.Body), v.Timestamp)
}

func classifyRuntimeURL(method, raw string) string {
	u := strings.ToLower(raw)
	if strings.Contains(u, "/_next/") || strings.Contains(u, "webpack-hmr") || strings.Contains(u, "turbopack") || strings.Contains(u, "react-devtools") || strings.Contains(u, "client-success") || strings.Contains(u, "client-file-logs") || strings.Contains(u, "turbopack-subscribe") || strings.Contains(u, "/ping") {
		return "framework_internal"
	}
	if method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE" {
		return "runtime_trace"
	}
	return "runtime_trace"
}

func (c *DynamicCrawler) matchingRuntimeTrace(method, raw string, started time.Time) *runtimeRequestTrace {
	normalized := NormalizeURL(raw)
	startMillis := started.UnixMilli()
	c.mu.RLock()
	defer c.mu.RUnlock()
	for i := len(c.runtimeTraces) - 1; i >= 0; i-- {
		trace := c.runtimeTraces[i]
		if trace.Method == strings.ToUpper(method) && trace.URL == normalized && (trace.Timestamp == 0 || (trace.Timestamp >= startMillis-2000 && trace.Timestamp <= startMillis+2000)) {
			copy := trace
			return &copy
		}
	}
	return nil
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
	c.mu.Unlock()

	// Request intelligence is intended to describe backend traffic.  Document
	// navigations, script loads and other page resources are not API requests
	// and must not compete with the XHR/fetch record for the same workflow.
	if pending.resourceTyp != network.ResourceTypeXHR &&
		pending.resourceTyp != network.ResourceTypeFetch &&
		pending.resourceTyp != network.ResourceTypeWebSocket {
		return
	}
	// Chromium labels Next.js RSC navigations and some script loads as Fetch.
	// They are frontend resources, not backend API calls.
	if pending.resourceTyp == network.ResourceTypeFetch && !isBackendFetchURL(pending.method, pending.url, pending.headers) {
		return
	}
	if pending.method == "GET" && pending.resourceTyp == network.ResourceTypeXHR {
		u, err := url.Parse(pending.url)
		if err != nil || !isApplicationAPIURL(u, pending.headers) {
			return
		}
	}

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
	c.mu.Lock()
	if live := c.pending[e.RequestID]; live != nil {
		live.response = response
		live.responseTimestamp = float64(time.Now().UnixNano()) / 1e9
	}
	c.mu.Unlock()
	if response.StatusCode == 401 || response.StatusCode == 403 {
		c.sessionMu.Lock()
		c.sessionExpired = true
		c.sessionMu.Unlock()
		c.mu.Lock()
		if c.authState == authAuthenticated {
			c.authState = authSessionLost
			log.Printf("AUTH_SESSION_LOST url=%s status=%d", pending.url, response.StatusCode)
		}
		c.mu.Unlock()
	}

	cookies := parseCookieHeader(HeaderValue(pending.headers, "Cookie"))
	contentType := HeaderValue(pending.headers, "Content-Type")

	sourceType := "ajax_fetch"
	if isFrameworkURL(pending.url) {
		sourceType = "framework_internal"
	}
	if pending.method != "GET" {
		log.Printf("REQUEST_CLASSIFIED id=%s method=%s url=%s body_len=%d source_type=%s", e.RequestID, pending.method, pending.url, len(pending.body), sourceType)
	}
	if pending.resourceTyp == network.ResourceTypeXHR {
		sourceType = "xhr"
	}
	if pending.resourceTyp == network.ResourceTypeWebSocket {
		sourceType = "websocket"
	} else if strings.Contains(strings.ToLower(HeaderValue(pending.headers, "Accept")), "graphql") ||
		strings.Contains(strings.ToLower(contentType), "graphql") {
		sourceType = "graphql"
	}

	fingerprint := CalculateFingerprint(pending.method, pending.url, pending.body, contentType)
	c.mu.RLock()
	_, seen := c.seenFingerprints[fingerprint]
	c.mu.RUnlock()

	if !seen {
		contentTypeInfo := DetectContentType(contentType)
		trace := c.matchingRuntimeTrace(pending.method, pending.url, pending.startTime)
		if pending.method != "GET" {
			log.Printf("RUNTIME_CDP_CORRELATION method=%s url=%s matched=%t", pending.method, pending.url, trace != nil)
		}

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
			if trace != nil {
				fetchDetails.CallStack = trace.Stack
				fetchDetails.ScriptURL = trace.ScriptURL
			}
		}

		if pending.method != "GET" {
			log.Printf("REQUEST_COMPLETED id=%s method=%s url=%s body_len=%d source_type=%s", e.RequestID, pending.method, pending.url, len(pending.body), sourceType)
		}
		converted := &DiscoveredRequest{
			ID:              string(e.RequestID),
			URL:             pending.url,
			Method:          pending.method,
			Headers:         pending.headers,
			Body:            pending.body,
			BodyType:        bodyTypeFromContentType(contentType),
			SourceType:      "cdp_observed",
			Depth:           pending.depth,
			NormalizedURL:   NormalizeURL(pending.url),
			Parameters:      ExtractParameters(pending.url, pending.body, contentType),
			Cookies:         cookies,
			Response:        response,
			FetchDetails:    fetchDetails,
			ContentTypeInfo: &contentTypeInfo,
			JSONFormat:      ParseJSONFormat(pending.body, contentType),
			CDPRequestID:    string(e.RequestID), LifecycleState: "response_received", RequestTimestamp: float64(pending.startTime.UnixNano()) / 1e9, ResponseTimestamp: float64(time.Now().UnixNano()) / 1e9,
			PageURL: pending.pageURL, TaskID: pending.taskID, TaskSelector: pending.taskSelector, InteractionType: pending.interactionType, ParentWorkflowID: pending.parentWorkflowID,
		}
		if trace != nil {
			converted.CallStack = trace.Stack
			converted.ScriptURL = trace.ScriptURL
		}
		c.emit(converted)
		if c.config.DBPath != "" {
			if store, err := NewRequestStore(c.config.DBPath); err == nil {
				_ = store.MarkStaticCandidateConfirmed(pending.method, pending.url, pending.url)
				_ = store.Close()
			}
		}
		if pending.method != "GET" {
			log.Printf("REQUEST_CONVERTED method=%s url=%s content_type=%s body_type=%s observed_source=%s api_classification=%s body_len=%d", pending.method, pending.url, contentType, bodyTypeFromContentType(contentType), sourceType, "json_api", len(pending.body))
		}
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

func (c *DynamicCrawler) captureStaticScript(ctx context.Context, id network.RequestID, depth int, pageURL string) {
	c.mu.RLock()
	pending := c.pending[id]
	if pending == nil {
		c.mu.RUnlock()
		return
	}
	p := *pending
	c.mu.RUnlock()
	ct := strings.ToLower(p.contentType)
	isJS := p.resourceTyp == network.ResourceTypeScript || strings.Contains(ct, "javascript") || strings.HasSuffix(strings.ToLower(strings.Split(p.url, "?")[0]), ".js") || strings.HasSuffix(strings.ToLower(strings.Split(p.url, "?")[0]), ".mjs")
	if !isJS || !c.IsInScope(p.url) {
		return
	}
	result, err := network.GetResponseBody(id).Do(ctx)
	if err != nil {
		return
	}
	body := string(result)
	if len(body) > 5*1024*1024 {
		return
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(result))
	c.mu.Lock()
	c.scriptBodies[p.url] = cachedScriptBody{URL: p.url, PageURL: pageURL, ContentType: p.contentType, Hash: hash, Body: body, CapturedAt: time.Now().UTC()}
	c.mu.Unlock()
	for _, candidate := range ExtractStaticAPICandidates(body, p.url, pageURL) {
		log.Printf("STATIC_API_CANDIDATE: method=%s url=%s evidence=%s script=%s", candidate.Method, candidate.URL, candidate.Evidence, candidate.SourceJSURL)
		if c.config.DBPath != "" {
			if store, e := NewRequestStore(c.config.DBPath); e == nil {
				_ = store.SaveStaticCandidate(candidate)
				_ = store.Close()
			}
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

		log.Printf("DOCUMENT_NAVIGATION_START url=%s depth=%d", item.url, item.depth)
		nextURLs := c.CrawlURL(ctx, item.url, item.depth)
		log.Printf("DOCUMENT_NAVIGATION_COMPLETE url=%s depth=%d", item.url, item.depth)
		c.queueMu.Lock()
		for _, nextURL := range nextURLs {
			if !c.routeEligible(nextURL) {
				log.Printf("ROUTE_SKIPPED url=%s reason=ineligible", nextURL)
				continue
			}
			canonical := c.canonicalizeURL(nextURL)
			c.mu.RLock()
			_, seen := c.seenURLs[canonical]
			c.mu.RUnlock()
			if seen {
				log.Printf("ROUTE_ALREADY_SEEN url=%s", canonical)
				continue
			}
			c.mu.Lock()
			c.seenURLs[canonical] = struct{}{}
			c.mu.Unlock()
			log.Printf("ROUTE_QUEUED url=%s depth=%d", canonical, item.depth+1)
			c.queue = append(c.queue, urlQueueItem{url: canonical, depth: item.depth + 1})
		}
		c.queueMu.Unlock()
	}
	return nil
}

func (c *DynamicCrawler) Close() {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.RLock()
		n := len(c.pending)
		c.mu.RUnlock()
		if n == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	c.mu.RLock()
	ids := make([]network.RequestID, 0, len(c.pending))
	for id := range c.pending {
		ids = append(ids, id)
	}
	c.mu.RUnlock()
	for _, id := range ids {
		c.updateLifecycle(id, "flushed_on_shutdown", "context closed")
	}
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
