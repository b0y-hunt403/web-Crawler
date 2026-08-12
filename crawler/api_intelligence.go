package crawler

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type RequestClassification string

const (
	ClassApplication             RequestClassification = "APPLICATION"
	ClassAuthPage                RequestClassification = "AUTH_PAGE"
	ClassAuthAPI                 RequestClassification = "AUTH_API"
	ClassAuthRecoveryAPI         RequestClassification = "AUTH_RECOVERY_API"
	ClassAuthSession             RequestClassification = "AUTH_SESSION"
	ClassGraphQL                 RequestClassification = "GRAPHQL"
	ClassNavigation              RequestClassification = "NAVIGATION"
	ClassFramework               RequestClassification = "FRAMEWORK"
	ClassStatic                  RequestClassification = "STATIC"
	ClassAnalytics               RequestClassification = "ANALYTICS"
	ClassPreflight               RequestClassification = "PREFLIGHT"
	ClassDevelopment             RequestClassification = "DEVELOPMENT"
	ClassUnknown                 RequestClassification = "UNKNOWN"
	ClassParameterizedNavigation RequestClassification = "PARAMETERIZED_NAVIGATION"
	// Compatibility aliases for callers using the earlier names.
	ClassAuth         = ClassAuthAPI
	ClassAuthRecovery = ClassAuthRecoveryAPI
)

type ParameterRecord struct {
	Source, Path, Type                                 string
	SampleLength                                       int
	CrawlerSupplied, ApplicationState, ScannerEligible bool
	ReflectionStatus, ExclusionReason                  string
}

type RequestAnalysis struct {
	Classification                                                        RequestClassification
	EndpointTemplate, ContentType, SchemaHash, AuthContext, Replayability string
	Parameters                                                            []ParameterRecord
	SQLMapEligible, DalfoxEligible                                        bool
	SQLMapReason, DalfoxReason                                            string
	ExclusionReasons                                                      []string
	GraphQLOperationType, GraphQLOperationName, GraphQLQueryHash          string
}

var (
	uuidSegment      = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	cveSegment       = regexp.MustCompile(`(?i)^CVE-[0-9]{4}-[0-9]{4,}$`)
	cpeSegment       = regexp.MustCompile(`(?i)^cpe:2\.3:`)
	intSegment       = regexp.MustCompile(`^[0-9]+$`)
	hexSegment       = regexp.MustCompile(`(?i)^[0-9a-f]{20,}$`)
	opaqueSegment    = regexp.MustCompile(`^[A-Za-z0-9_-]{24,}$`)
	staticExtensions = map[string]bool{".js": true, ".css": true, ".map": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".ico": true, ".webp": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".mp4": true, ".webm": true, ".pdf": true}
)

func EndpointTemplate(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	parts := strings.Split(u.EscapedPath(), "/")
	for i, escaped := range parts {
		seg, e := url.PathUnescape(escaped)
		if e != nil {
			seg = escaped
		}
		switch {
		case uuidSegment.MatchString(seg):
			parts[i] = "{uuid}"
		case cveSegment.MatchString(seg):
			parts[i] = "{cve}"
		case cpeSegment.MatchString(seg):
			parts[i] = "{cpe}"
		case intSegment.MatchString(seg):
			parts[i] = "{int}"
		case hexSegment.MatchString(seg):
			parts[i] = "{hash}"
		case opaqueSegment.MatchString(seg):
			parts[i] = "{id}"
		}
	}
	result := strings.Join(parts, "/")
	if result == "" {
		result = "/"
	}
	return result
}

func ClassifyObservedRequest(req *DiscoveredRequest) RequestClassification {
	method := strings.ToUpper(req.Method)
	if method == "OPTIONS" {
		return ClassPreflight
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		return ClassUnknown
	}
	p := strings.ToLower(u.Path)
	q := u.Query()
	if strings.Contains(p, "__nextjs") || strings.Contains(p, "webpack-hmr") || strings.Contains(p, "sockjs-node") {
		return ClassDevelopment
	}
	if strings.HasPrefix(p, "/_next/") || q.Has("_rsc") || strings.Contains(p, "/_rsc") {
		return ClassFramework
	}
	if staticExtensions[strings.ToLower(path.Ext(p))] {
		return ClassStatic
	}
	if strings.Contains(p, "analytics") || strings.Contains(p, "telemetry") || strings.Contains(u.Host, "google-analytics") || strings.Contains(u.Host, "segment.") {
		return ClassAnalytics
	}
	if strings.Contains(p, "refresh-token") || strings.Contains(p, "refresh_token") || strings.Contains(p, "/session/") || strings.HasSuffix(p, "/session") {
		return ClassAuthSession
	}
	if isGraphQLRequest(req) {
		return ClassGraphQL
	}
	accept := strings.ToLower(HeaderValue(req.Headers, "Accept"))
	document := strings.EqualFold(req.ResourceType, "Document") || strings.EqualFold(req.ResourceType, "document") || strings.Contains(strings.ToLower(HeaderValue(req.Headers, "Sec-Fetch-Dest")), "document") || req.SourceType == "navigation" || strings.Contains(accept, "text/html")
	authPath := strings.Contains(p, "login") || strings.Contains(p, "signin") || strings.Contains(p, "oauth") || strings.Contains(p, "callback")
	recoveryPath := strings.Contains(p, "forgot-password") || strings.Contains(p, "reset-password") || strings.Contains(p, "recover")
	if document {
		if authPath {
			return ClassAuthPage
		}
		if method == "GET" && hasMeaningfulQuery(req.URL) {
			return ClassParameterizedNavigation
		}
		return ClassNavigation
	}
	if recoveryPath {
		return ClassAuthRecoveryAPI
	}
	if authPath {
		return ClassAuthAPI
	}
	if method == "HEAD" {
		return ClassUnknown
	}
	if method == "GET" && hasMeaningfulQuery(req.URL) {
		return ClassParameterizedNavigation
	}
	if req.SourceType == "cdp" || strings.HasPrefix(req.SourceType, "cdp_") {
		return ClassApplication
	}
	return ClassUnknown
}

func authContext(req *DiscoveredRequest) string {
	if HeaderValue(req.Headers, "Authorization") != "" || HeaderValue(req.Headers, "Cookie") != "" || len(req.Cookies) > 0 || req.AuthSessionID != "" {
		return "AUTHENTICATED"
	}
	return "ANONYMOUS"
}

func AnalyzeRequest(req *DiscoveredRequest) RequestAnalysis {
	a := RequestAnalysis{Classification: ClassifyObservedRequest(req), EndpointTemplate: EndpointTemplate(req.URL), AuthContext: authContext(req)}
	a.ContentType = NormalizeContentType(HeaderValue(req.Headers, "Content-Type"))
	if a.ContentType == "" {
		a.ContentType = NormalizeContentType(req.BodyType)
	}
	a.Parameters = extractParameters(req, &a)
	for i := range a.Parameters {
		p := &a.Parameters[i]
		if req.TaskID != "" {
			p.CrawlerSupplied = true
		}
		if p.Source == "path" || strings.Contains(strings.ToLower(p.Path), "id") {
			p.ApplicationState = true
		}
	}
	a.Replayability, a.ExclusionReasons = replayability(req, a)
	application := a.Classification == ClassApplication || a.Classification == ClassGraphQL || a.Classification == ClassParameterizedNavigation || a.Classification == ClassAuthAPI || a.Classification == ClassAuthRecoveryAPI
	a.SQLMapEligible = application && strings.HasPrefix(a.Replayability, "REPLAYABLE") && hasEligible(a.Parameters)
	a.DalfoxEligible = (a.Classification == ClassApplication || a.Classification == ClassGraphQL || a.Classification == ClassParameterizedNavigation) && strings.EqualFold(req.Method, "GET") && hasEligibleQuery(a.Parameters)
	if !a.SQLMapEligible {
		a.SQLMapReason = strings.Join(a.ExclusionReasons, ",")
		if a.SQLMapReason == "" {
			a.SQLMapReason = "no_meaningful_controllable_parameter"
		}
	}
	if !a.DalfoxEligible {
		a.DalfoxReason = strings.Join(a.ExclusionReasons, ",")
		if a.DalfoxReason == "" {
			a.DalfoxReason = "not_parameterized_get"
		}
	}
	schema := map[string]interface{}{"method": strings.ToUpper(req.Method), "template": a.EndpointTemplate, "content_type": a.ContentType, "auth": a.AuthContext, "parameters": schemaParameters(a.Parameters), "graphql_operation": a.GraphQLOperationName, "graphql_type": a.GraphQLOperationType}
	b, _ := json.Marshal(schema)
	sum := sha256.Sum256(b)
	a.SchemaHash = hex.EncodeToString(sum[:])
	return a
}

func extractParameters(req *DiscoveredRequest, a *RequestAnalysis) []ParameterRecord {
	var out []ParameterRecord
	u, err := url.Parse(req.URL)
	if err == nil {
		keys := make([]string, 0, len(u.Query()))
		for k := range u.Query() {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, v := range u.Query()[k] {
				out = append(out, param("query", "query."+k, inferString(v), v, true))
			}
		}
		segments := strings.Split(strings.Trim(u.Path, "/"), "/")
		templates := strings.Split(strings.Trim(EndpointTemplate(req.URL), "/"), "/")
		for i := range segments {
			if i < len(templates) && strings.HasPrefix(templates[i], "{") {
				out = append(out, param("path", fmt.Sprintf("path.segment[%d]", i), strings.Trim(templates[i], "{}"), segments[i], false))
			}
		}
	}
	ct := DetectContentType(HeaderValue(req.Headers, "Content-Type"))
	if ct.IsJSON || strings.EqualFold(req.BodyType, "json") {
		var v interface{}
		if json.Unmarshal([]byte(req.Body), &v) == nil {
			flattenJSON("json", v, &out)
			detectGraphQL(v, a)
			out = append(out, a.Parameters...)
			a.Parameters = nil
		}
	}
	if ct.IsURLEncoded || strings.EqualFold(req.BodyType, "form-urlencoded") {
		if vals, e := url.ParseQuery(req.Body); e == nil {
			keys := make([]string, 0, len(vals))
			for k := range vals {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				for _, v := range vals[k] {
					out = append(out, param("form", "form."+k, inferString(v), v, true))
				}
			}
		}
	}
	if ct.IsMultipart && ct.Boundary != "" {
		mr := multipart.NewReader(strings.NewReader(req.Body), ct.Boundary)
		for {
			p, e := mr.NextPart()
			if e != nil {
				break
			}
			name := p.FormName()
			if p.FileName() != "" {
				out = append(out, param("multipart", "multipart.file."+name, "file", p.FileName(), false))
			} else {
				buf := make([]byte, 4097)
				n, _ := p.Read(buf)
				out = append(out, param("multipart", "multipart."+name, inferString(string(buf[:n])), string(buf[:n]), true))
			}
		}
	}
	return dedupeParameters(out)
}

func param(source, p, t, v string, eligible bool) ParameterRecord {
	reason := ""
	if sensitiveName(p) {
		eligible = false
		reason = "sensitive_or_security_parameter"
	}
	return ParameterRecord{Source: source, Path: p, Type: t, SampleLength: len(v), ScannerEligible: eligible, ReflectionStatus: "UNKNOWN", ExclusionReason: reason}
}
func inferString(v string) string {
	if v == "true" || v == "false" {
		return "boolean"
	}
	if _, e := strconv.ParseInt(v, 10, 64); e == nil {
		return "integer"
	}
	if _, e := strconv.ParseFloat(v, 64); e == nil {
		return "number"
	}
	return "string"
}
func flattenJSON(prefix string, v interface{}, out *[]ParameterRecord) {
	switch x := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			flattenJSON(prefix+"."+k, x[k], out)
		}
	case []interface{}:
		for i, c := range x {
			flattenJSON(fmt.Sprintf("%s[%d]", prefix, i), c, out)
		}
	case string:
		*out = append(*out, param("json", prefix, "string", x, true))
	case float64:
		t := "number"
		if x == float64(int64(x)) {
			t = "integer"
		}
		*out = append(*out, param("json", prefix, t, fmt.Sprint(x), true))
	case bool:
		*out = append(*out, param("json", prefix, "boolean", fmt.Sprint(x), true))
	case nil:
		*out = append(*out, param("json", prefix, "null", "", false))
	}
}
func isGraphQLRequest(req *DiscoveredRequest) bool {
	u, _ := url.Parse(req.URL)
	if strings.Contains(strings.ToLower(u.Path), "graphql") {
		return true
	}
	var v map[string]interface{}
	return json.Unmarshal([]byte(req.Body), &v) == nil && (v["query"] != nil || v["operationName"] != nil)
}
func detectGraphQL(v interface{}, a *RequestAnalysis) {
	m, ok := v.(map[string]interface{})
	if !ok {
		return
	}
	if s, ok := m["operationName"].(string); ok {
		a.GraphQLOperationName = s
	}
	if q, ok := m["query"].(string); ok {
		t := strings.TrimSpace(q)
		if strings.HasPrefix(t, "mutation") {
			a.GraphQLOperationType = "mutation"
		} else {
			a.GraphQLOperationType = "query"
		}
		h := sha256.Sum256([]byte(q))
		a.GraphQLQueryHash = hex.EncodeToString(h[:])
		if vars, ok := m["variables"]; ok {
			var ps []ParameterRecord
			flattenJSON("graphql.variables", vars, &ps)
			a.Parameters = append(a.Parameters, ps...)
		}
	}
}
func replayability(req *DiscoveredRequest, a RequestAnalysis) (string, []string) {
	var reasons []string
	u, e := url.Parse(req.URL)
	if e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		reasons = append(reasons, "malformed_url")
	}
	if req.Method == "" {
		reasons = append(reasons, "missing_method")
	}
	m := strings.ToUpper(req.Method)
	meaningfulParams := len(a.Parameters) > 0
	if m != "GET" && m != "HEAD" && req.Body == "" && !meaningfulParams {
		reasons = append(reasons, "missing_body")
	}
	if req.BodyCompletenessKnown && !req.BodyComplete {
		reasons = append(reasons, "request_body_incomplete")
	}
	if req.LifecycleState != "" && req.LifecycleState != "completed" && req.LifecycleState != "loadingFinished" {
		reasons = append(reasons, "lifecycle_not_completed")
	}
	if len(reasons) > 0 {
		return "INCOMPLETE", reasons
	}
	if a.AuthContext == "AUTHENTICATED" {
		return "REPLAYABLE_PRIVATE_AUTH", reasons
	}
	return "REPLAYABLE", reasons
}
func schemaParameters(ps []ParameterRecord) []string {
	r := make([]string, 0, len(ps))
	for _, p := range ps {
		r = append(r, p.Path+":"+p.Type)
	}
	sort.Strings(r)
	return r
}
func hasEligible(ps []ParameterRecord) bool {
	for _, p := range ps {
		if p.ScannerEligible {
			return true
		}
	}
	return false
}
func hasEligibleQuery(ps []ParameterRecord) bool {
	for _, p := range ps {
		if p.Source == "query" && p.ScannerEligible && !noiseQuery(p.Path) {
			return true
		}
	}
	return false
}
func noiseQuery(p string) bool {
	n := strings.TrimPrefix(strings.ToLower(p), "query.")
	return n == "_rsc" || n == "_" || strings.HasPrefix(n, "utm_") || n == "fbclid" || n == "gclid" || n == "page" || n == "limit" || n == "offset"
}
func hasMeaningfulQuery(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	for k := range u.Query() {
		if !noiseQuery("query."+k) && !sensitiveName(k) {
			return true
		}
	}
	return false
}
func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
func dedupeParameters(in []ParameterRecord) []ParameterRecord {
	seen := map[string]bool{}
	out := in[:0]
	for _, p := range in {
		k := p.Source + "\x00" + p.Path
		if !seen[k] {
			seen[k] = true
			out = append(out, p)
		}
	}
	return out
}

func normalizedSensitiveName(name string) string {
	name = strings.TrimSpace(name)
	name = regexp.MustCompile(`([a-z0-9])([A-Z])`).ReplaceAllString(name, `${1}_${2}`)
	name = strings.ToLower(strings.NewReplacer("-", "_", " ", "_", ".", "_", "[", "_", "]", "").Replace(name))
	name = strings.Trim(name, "_")
	return name
}
func sensitiveName(name string) bool {
	n := normalizedSensitiveName(name)
	if strings.HasPrefix(n, "x_") {
		n = strings.TrimPrefix(n, "x_")
	}
	for _, part := range strings.Split(n, "_") {
		switch part {
		case "password", "passwd", "passcode", "token", "accesstoken", "refreshtoken", "idtoken", "authorization", "cookie", "session", "csrf", "xsrf", "secret":
			return true
		}
	}
	return strings.Contains(n, "password") || strings.Contains(n, "token") || strings.Contains(n, "session") || strings.Contains(n, "csrf") || strings.Contains(n, "authorization")
}

func requestContainsRequiredFields(body, contentType string, required []string) bool {
	if len(required) == 0 {
		return true
	}
	values := map[string]string{}
	ct := DetectContentType(contentType)
	if ct.IsJSON {
		var v interface{}
		if json.Unmarshal([]byte(body), &v) == nil {
			collectNamedValues(v, values)
		}
	} else if ct.IsURLEncoded {
		if parsed, err := url.ParseQuery(body); err == nil {
			for k, v := range parsed {
				if len(v) > 0 {
					values[k] = v[len(v)-1]
				}
			}
		}
	} else if ct.IsMultipart && ct.Boundary != "" {
		mr := multipart.NewReader(strings.NewReader(body), ct.Boundary)
		for {
			p, err := mr.NextPart()
			if err != nil {
				break
			}
			buf := make([]byte, 4097)
			n, _ := p.Read(buf)
			values[p.FormName()] = string(buf[:n])
		}
	}
	for _, name := range required {
		if strings.TrimSpace(values[name]) == "" {
			return false
		}
	}
	return true
}

func collectNamedValues(v interface{}, values map[string]string) {
	switch x := v.(type) {
	case map[string]interface{}:
		for k, child := range x {
			switch scalar := child.(type) {
			case string:
				values[k] = scalar
			case float64:
				values[k] = fmt.Sprint(scalar)
			case bool:
				values[k] = fmt.Sprint(scalar)
			}
			collectNamedValues(child, values)
		}
	case []interface{}:
		for _, child := range x {
			collectNamedValues(child, values)
		}
	}
}

func (s *RequestStore) IndexRequest(req *DiscoveredRequest) error {
	if req == nil || !(req.SourceType == "cdp" || strings.HasPrefix(req.SourceType, "cdp_")) {
		return nil
	}
	a := AnalyzeRequest(req)
	now := time.Now().UTC()
	// The derived relation key must always reference the persisted raw row.
	// CDPRequestID is correlation evidence, not the discovered_requests PK.
	requestID := req.ID
	origin := requestOrigin(req.URL)
	bodyHash := sha256.Sum256([]byte(req.Body))
	bodyKey := hex.EncodeToString(bodyHash[:])
	identity := strings.Join([]string{origin, strings.ToUpper(req.Method), a.EndpointTemplate, a.AuthContext, a.GraphQLOperationType, a.GraphQLOperationName, a.GraphQLQueryHash}, "\x00")
	eh := sha256.Sum256([]byte(identity))
	endpointIdentity := hex.EncodeToString(eh[:])
	h := sha256.Sum256([]byte(identity + "\x00" + a.SchemaHash))
	inventoryID := hex.EncodeToString(h[:])
	paramsJSON, _ := json.Marshal(schemaParameters(a.Parameters))
	reasonsJSON, _ := json.Marshal(a.ExclusionReasons)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var oldInventory string
	_ = tx.QueryRow(`SELECT inventory_id FROM request_inventory_state WHERE request_id=?`, requestID).Scan(&oldInventory)
	if oldInventory != "" && oldInventory != inventoryID {
		_, err = tx.Exec(`DELETE FROM request_parameters WHERE request_id=?`, req.ID)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`DELETE FROM scanner_candidates WHERE request_id=?`, req.ID)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`DELETE FROM api_inventory_observations WHERE request_id=?`, requestID)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`DELETE FROM api_inventory_request_bodies WHERE request_id=?`, requestID)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`DELETE FROM api_inventory_request_statuses WHERE request_id=?`, requestID)
		if err != nil {
			return err
		}
		if err = rebuildInventoryAggregates(tx, oldInventory); err != nil {
			return err
		}
		_, err = tx.Exec(`DELETE FROM api_endpoint_inventory WHERE id=? AND NOT EXISTS(SELECT 1 FROM api_inventory_observations WHERE inventory_id=?)`, oldInventory, oldInventory)
		if err != nil {
			return err
		}
	}
	_, err = tx.Exec(`INSERT INTO api_endpoint_inventory(id,method,endpoint_template,origin,endpoint_identity,classification,content_type,request_schema_hash,authentication_context,first_request_id,representative_request_id,observation_count,distinct_body_count,parameter_paths,status_codes,replayability,sqlmap_eligible,dalfox_eligible,exclusion_reasons,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,0,0,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET endpoint_identity=excluded.endpoint_identity,parameter_paths=excluded.parameter_paths,replayability=CASE WHEN excluded.replayability LIKE 'REPLAYABLE%' THEN excluded.replayability ELSE api_endpoint_inventory.replayability END,sqlmap_eligible=excluded.sqlmap_eligible,dalfox_eligible=excluded.dalfox_eligible,exclusion_reasons=excluded.exclusion_reasons,updated_at=excluded.updated_at`, inventoryID, strings.ToUpper(req.Method), a.EndpointTemplate, origin, endpointIdentity, string(a.Classification), a.ContentType, a.SchemaHash, a.AuthContext, requestID, requestID, string(paramsJSON), "[]", a.Replayability, a.SQLMapEligible, a.DalfoxEligible, string(reasonsJSON), now, now)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT OR IGNORE INTO api_inventory_observations(inventory_id,request_id) VALUES(?,?)`, inventoryID, requestID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT OR REPLACE INTO api_inventory_request_bodies(request_id,inventory_id,body_hash) VALUES(?,?,?)`, requestID, inventoryID, bodyKey)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM api_inventory_body_hashes WHERE inventory_id=?`, inventoryID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT OR IGNORE INTO api_inventory_body_hashes(inventory_id,body_hash) SELECT inventory_id,body_hash FROM api_inventory_request_bodies WHERE inventory_id=?`, inventoryID)
	if err != nil {
		return err
	}
	if req.Response != nil {
		_, err = tx.Exec(`INSERT OR REPLACE INTO api_inventory_request_statuses(request_id,inventory_id,status_code) VALUES(?,?,?)`, requestID, inventoryID, req.Response.StatusCode)
		if err != nil {
			return err
		}
	}
	_, err = tx.Exec(`DELETE FROM api_inventory_status_codes WHERE inventory_id=?`, inventoryID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT OR IGNORE INTO api_inventory_status_codes(inventory_id,status_code) SELECT inventory_id,status_code FROM api_inventory_request_statuses WHERE inventory_id=?`, inventoryID)
	if err != nil {
		return err
	}
	if oldInventory == inventoryID { /* lifecycle enrichment only */
	}
	var rep string
	_ = tx.QueryRow(`SELECT representative_request_id FROM api_endpoint_inventory WHERE id=?`, inventoryID).Scan(&rep)
	if rep == "" || requestPreferred(tx, req, rep) {
		_, err = tx.Exec(`UPDATE api_endpoint_inventory SET representative_request_id=? WHERE id=?`, requestID, inventoryID)
		if err != nil {
			return err
		}
	}
	var obs, bodies int
	_ = tx.QueryRow(`SELECT COUNT(*) FROM api_inventory_observations WHERE inventory_id=?`, inventoryID).Scan(&obs)
	_ = tx.QueryRow(`SELECT COUNT(*) FROM api_inventory_body_hashes WHERE inventory_id=?`, inventoryID).Scan(&bodies)
	statuses := []int{}
	rows, _ := tx.Query(`SELECT status_code FROM api_inventory_status_codes WHERE inventory_id=? ORDER BY status_code`, inventoryID)
	if rows != nil {
		for rows.Next() {
			var code int
			_ = rows.Scan(&code)
			statuses = append(statuses, code)
		}
		rows.Close()
	}
	statusJSON, _ := json.Marshal(statuses)
	_, err = tx.Exec(`UPDATE api_endpoint_inventory SET observation_count=?,distinct_body_count=?,status_codes=? WHERE id=?`, obs, bodies, string(statusJSON), inventoryID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO request_inventory_state(request_id,inventory_id,indexed_body_hash,indexed_lifecycle,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(request_id) DO UPDATE SET inventory_id=excluded.inventory_id,indexed_body_hash=excluded.indexed_body_hash,indexed_lifecycle=excluded.indexed_lifecycle,updated_at=excluded.updated_at`, requestID, inventoryID, bodyKey, req.LifecycleState, now)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM request_parameters WHERE request_id=?`, req.ID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM scanner_candidates WHERE request_id=?`, req.ID)
	if err != nil {
		return err
	}
	for _, p := range a.Parameters {
		id := CalculateFingerprint("PARAM", req.ID, p.Path, p.Type)
		_, err = tx.Exec(`INSERT OR REPLACE INTO request_parameters(id,request_id,inventory_id,source,parameter_path,inferred_type,sample_length,crawler_supplied,application_state,reflection_status,scanner_eligible,exclusion_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, id, req.ID, inventoryID, p.Source, p.Path, p.Type, p.SampleLength, p.CrawlerSupplied, p.ApplicationState, p.ReflectionStatus, p.ScannerEligible, p.ExclusionReason)
		if err != nil {
			return err
		}
	}
	for _, scanner := range []struct {
		name     string
		eligible bool
		reason   string
	}{{"SQLMAP", a.SQLMapEligible, a.SQLMapReason}, {"DALFOX", a.DalfoxEligible, a.DalfoxReason}} {
		id := CalculateFingerprint(scanner.name, req.ID, "", "")
		_, err = tx.Exec(`INSERT OR REPLACE INTO scanner_candidates(id,request_id,scanner,eligible,reason,replayability,created_at) VALUES(?,?,?,?,?,?,?)`, id, req.ID, scanner.name, scanner.eligible, scanner.reason, a.Replayability, now)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func rebuildInventoryAggregates(tx *sql.Tx, inventoryID string) error {
	var observations, bodies int
	if err := tx.QueryRow(`SELECT COUNT(DISTINCT request_id) FROM api_inventory_observations WHERE inventory_id=?`, inventoryID).Scan(&observations); err != nil {
		return err
	}
	if err := tx.QueryRow(`SELECT COUNT(DISTINCT body_hash) FROM api_inventory_request_bodies WHERE inventory_id=?`, inventoryID).Scan(&bodies); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM api_inventory_body_hashes WHERE inventory_id=?`, inventoryID); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO api_inventory_body_hashes(inventory_id,body_hash) SELECT inventory_id,body_hash FROM api_inventory_request_bodies WHERE inventory_id=?`, inventoryID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM api_inventory_status_codes WHERE inventory_id=?`, inventoryID); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO api_inventory_status_codes(inventory_id,status_code) SELECT inventory_id,status_code FROM api_inventory_request_statuses WHERE inventory_id=?`, inventoryID); err != nil {
		return err
	}
	statuses := []int{}
	rows, err := tx.Query(`SELECT status_code FROM api_inventory_status_codes WHERE inventory_id=? ORDER BY status_code`, inventoryID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var x int
		_ = rows.Scan(&x)
		statuses = append(statuses, x)
	}
	rows.Close()
	statusJSON, _ := json.Marshal(statuses)
	var rep string
	rows, err = tx.Query(`SELECT request_id FROM api_inventory_observations WHERE inventory_id=? ORDER BY request_id`, inventoryID)
	if err != nil {
		return err
	}
	var best *RequestQuality
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		var r DiscoveredRequest
		var resp, headers string
		_ = tx.QueryRow(`SELECT id,body,completeness_status,lifecycle_state,response,headers,request_timestamp,page_url,task_id,auth_session_id FROM discovered_requests WHERE id=?`, id).Scan(&r.ID, &r.Body, &r.CompletenessStatus, &r.LifecycleState, &resp, &headers, &r.RequestTimestamp, &r.PageURL, &r.TaskID, &r.AuthSessionID)
		_ = json.Unmarshal([]byte(resp), &r.Response)
		_ = json.Unmarshal([]byte(headers), &r.Headers)
		q := qualityFor(&r)
		if best == nil || qualityLess(*best, q) {
			copy := q
			best = &copy
			rep = id
		}
	}
	rows.Close()
	if _, err = tx.Exec(`UPDATE api_endpoint_inventory SET observation_count=?,distinct_body_count=?,status_codes=?,representative_request_id=? WHERE id=?`, observations, bodies, string(statusJSON), rep, inventoryID); err != nil {
		return err
	}
	return nil
}
func qualityLess(a, b RequestQuality) bool {
	va, vb := []int{a.Completeness, a.Lifecycle, a.Body, a.Response, a.Meaningful, a.Auth, a.Correlated}, []int{b.Completeness, b.Lifecycle, b.Body, b.Response, b.Meaningful, b.Auth, b.Correlated}
	for i := range va {
		if va[i] != vb[i] {
			return va[i] < vb[i]
		}
	}
	if a.Timestamp != b.Timestamp {
		return a.Timestamp > b.Timestamp
	}
	return a.ID > b.ID
}

func requestOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + host + ":" + port
}

type RequestQuality struct {
	Body, Completeness, Lifecycle, Response, Meaningful, Auth, Correlated int
	Timestamp                                                             float64
	ID                                                                    string
}

func qualityFor(req *DiscoveredRequest) RequestQuality {
	q := RequestQuality{ID: req.ID, Timestamp: req.RequestTimestamp}
	if req.Body != "" {
		q.Body = 1
	}
	switch req.CompletenessStatus {
	case "COMPLETE":
		q.Completeness = 3
	case "UNKNOWN":
		q.Completeness = 2
	case "INCOMPLETE":
		q.Completeness = 1
	}
	if q.Completeness == 0 {
		if req.BodyCompletenessKnown {
			if req.BodyComplete {
				q.Completeness = 3
			} else {
				q.Completeness = 1
			}
		} else {
			q.Completeness = 2
		}
	}
	switch req.LifecycleState {
	case "completed", "loadingFinished":
		q.Lifecycle = 4
	case "response_received":
		q.Lifecycle = 3
	case "observed":
		q.Lifecycle = 2
	case "failed", "timed_out":
		q.Lifecycle = 1
	}
	if req.Response != nil {
		q.Response = 1
		if req.Response.StatusCode >= 200 && req.Response.StatusCode < 400 {
			q.Meaningful = 1
		}
	}
	if req.AuthSessionID != "" || HeaderValue(req.Headers, "Authorization") != "" || HeaderValue(req.Headers, "Cookie") != "" {
		q.Auth = 1
	}
	if req.PageURL != "" || req.TaskID != "" {
		q.Correlated = 1
	}
	return q
}
func requestPreferred(tx *sql.Tx, req *DiscoveredRequest, existing string) bool {
	var old DiscoveredRequest
	var body, complete, life string
	var responseJSON, headers string
	var ts float64
	if err := tx.QueryRow(`SELECT id,body,completeness_status,lifecycle_state,response,headers,request_timestamp,page_url,task_id,auth_session_id FROM discovered_requests WHERE id=?`, existing).Scan(&old.ID, &body, &complete, &life, &responseJSON, &headers, &ts, &old.PageURL, &old.TaskID, &old.AuthSessionID); err != nil {
		return false
	}
	old.Body = body
	old.CompletenessStatus = complete
	old.LifecycleState = life
	old.RequestTimestamp = ts
	_ = json.Unmarshal([]byte(responseJSON), &old.Response)
	_ = json.Unmarshal([]byte(headers), &old.Headers)
	a, b := qualityFor(req), qualityFor(&old)
	va, vb := []int{a.Completeness, a.Lifecycle, a.Body, a.Response, a.Meaningful, a.Auth, a.Correlated}, []int{b.Completeness, b.Lifecycle, b.Body, b.Response, b.Meaningful, b.Auth, b.Correlated}
	for i := range va {
		if va[i] != vb[i] {
			return va[i] > vb[i]
		}
	}
	if a.Timestamp != b.Timestamp {
		return a.Timestamp < b.Timestamp
	}
	return a.ID < b.ID
}
