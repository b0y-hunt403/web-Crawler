package crawler

// Generic replay/export pipeline.  Exports are deliberately derived only
// from authoritative persisted browser requests; static candidates are never
// included.
import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type ReplayRequest struct {
	ID              string
	Method          string
	URL             string
	Headers         map[string]string
	Body            string
	BodyType        string
	Template        string
	Parameters      []string
	PageURL, TaskID string
	Status          int
	Replayability   string
	AuthRequired    bool
}

func authSessionRequest(rawURL string) bool {
	u, _ := url.Parse(rawURL)
	return strings.Contains(strings.ToLower(u.Path), "refresh-token")
}

func redactSensitiveText(body string) string {
	var value interface{}
	if json.Unmarshal([]byte(body), &value) == nil {
		redactSensitiveValue(&value)
		b, _ := json.Marshal(value)
		return string(b)
	}
	parts := strings.Split(body, "&")
	for i, p := range parts {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) == 2 && sensitiveName(kv[0]) {
			parts[i] = kv[0] + "=%5BREDACTED%5D"
		}
	}
	body = strings.Join(parts, "&")
	multipart := regexp.MustCompile(`(?is)(name=["']?(?:password|token|refreshToken|accessToken|authorization|cookie|session)["']?[^\r\n]*\r?\n\r?\n)([^\r\n-]*)`)
	body = multipart.ReplaceAllString(body, "${1}[REDACTED]")
	jwt := regexp.MustCompile(`(?i)\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`)
	return jwt.ReplaceAllStringFunc(body, func(s string) string { return fmt.Sprintf("[JWT_REDACTED:length=%d]", len(s)) })
}

func redactSensitiveURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	for k := range q {
		if sensitiveName(k) {
			q.Set(k, "[REDACTED]")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func redactSensitiveValue(v *interface{}) {
	switch x := (*v).(type) {
	case map[string]interface{}:
		for k, child := range x {
			if sensitiveName(k) {
				x[k] = "[REDACTED]"
			} else {
				redactSensitiveValue(&child)
				x[k] = child
			}
		}
	case []interface{}:
		for i := range x {
			redactSensitiveValue(&x[i])
		}
	}
}

func curatedReplayRows(s *RequestStore, private, exportAuth, exportMutations, exportDestructive bool) ([]ReplayRequest, error) {
	rows, err := s.db.Query(`SELECT d.id,d.method,d.url,d.headers,d.body,d.body_type,i.endpoint_template,i.parameter_paths,d.page_url,d.task_id,d.response,i.replayability,i.authentication_context
		FROM api_endpoint_inventory i JOIN discovered_requests d ON d.id=i.representative_request_id
		WHERE i.sqlmap_eligible=1 AND i.classification IN ('APPLICATION','GRAPHQL','PARAMETERIZED_NAVIGATION','AUTH_API','AUTH_RECOVERY_API') ORDER BY i.created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReplayRequest
	for rows.Next() {
		var r ReplayRequest
		var headersJSON, paramsJSON, responseJSON, auth string
		if err := rows.Scan(&r.ID, &r.Method, &r.URL, &headersJSON, &r.Body, &r.BodyType, &r.Template, &paramsJSON, &r.PageURL, &r.TaskID, &responseJSON, &r.Replayability, &auth); err != nil {
			return nil, err
		}
		if isFrameworkURL(r.URL) || authSessionRequest(r.URL) {
			continue
		}
		if (r.Method == "DELETE" && !exportDestructive) || (r.Method != "GET" && r.Method != "HEAD" && r.Method != "DELETE" && !exportMutations) {
			continue
		}
		r.AuthRequired = auth == "AUTHENTICATED"
		if r.AuthRequired && !exportAuth {
			continue
		}
		h := map[string]string{}
		_ = json.Unmarshal([]byte(headersJSON), &h)
		r.Headers = h
		_ = json.Unmarshal([]byte(paramsJSON), &r.Parameters)
		var response ResponseMetadata
		if json.Unmarshal([]byte(responseJSON), &response) == nil {
			r.Status = response.StatusCode
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// requestReplayRows is retained for internal compatibility and returns the
// safe, non-authenticated, non-destructive curated corpus.
func requestReplayRows(s *RequestStore) ([]ReplayRequest, error) {
	rows, err := s.db.Query(`SELECT id,method,url,headers,body,body_type FROM discovered_requests WHERE source_type LIKE 'cdp%' AND method NOT IN ('GET','OPTIONS','HEAD') ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReplayRequest
	for rows.Next() {
		var r ReplayRequest
		var headersJSON string
		if err := rows.Scan(&r.ID, &r.Method, &r.URL, &headersJSON, &r.Body, &r.BodyType); err != nil {
			return nil, err
		}
		if isFrameworkURL(r.URL) || authSessionRequest(r.URL) {
			continue
		}
		r.Headers = map[string]string{}
		_ = json.Unmarshal([]byte(headersJSON), &r.Headers)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ExportReplayArtifacts writes SQLMap request files, Burp-compatible raw
// requests, a HAR document, and a Postman collection.
func ExportReplayArtifacts(store *RequestStore, dir string) error {
	private := strings.EqualFold(os.Getenv("RAPTOR_EXPORT_PRIVATE_REPLAY"), "true")
	exportAuth := strings.EqualFold(os.Getenv("RAPTOR_EXPORT_AUTH_REQUESTS"), "true")
	exportMutations := strings.EqualFold(os.Getenv("RAPTOR_EXPORT_MUTATIONS"), "true")
	exportDestructive := strings.EqualFold(os.Getenv("RAPTOR_EXPORT_DESTRUCTIVE"), "true")
	if private {
		dir = filepath.Join(dir, "private-replay")
	} else {
		dir = filepath.Join(dir, "safe")
	}
	requests, err := curatedReplayRows(store, private, exportAuth, exportMutations, exportDestructive)
	if err != nil {
		return err
	}
	mode := os.FileMode(0755)
	if private {
		mode = 0700
	}
	if err := os.MkdirAll(dir, mode); err != nil {
		return err
	}
	for _, sub := range []string{"sqlmap", "burp", "postman", "har", "dalfox"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), mode); err != nil {
			return err
		}
	}
	har := map[string]interface{}{"log": map[string]interface{}{"version": "1.2", "creator": map[string]string{"name": "Raptor", "version": "2"}, "entries": []interface{}{}}}
	entries := har["log"].(map[string]interface{})["entries"].([]interface{})
	postman := map[string]interface{}{"info": map[string]string{"name": "Raptor observed APIs", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"}, "item": []interface{}{}}
	items := postman["item"].([]interface{})
	index := make([]map[string]interface{}, 0, len(requests))
	for i, r := range requests {
		if !private && !authSessionRequest(r.URL) {
			r.URL = redactSensitiveURL(r.URL)
			r.Body = redactSensitiveText(r.Body)
			for k := range r.Headers {
				if sensitiveName(k) {
					r.Headers[k] = "[REDACTED]"
				}
			}
		}
		raw, _ := replayText(r)
		if authSessionRequest(r.URL) && !private {
			continue
		}
		if !authSessionRequest(r.URL) {
			filename := fmt.Sprintf("request-%03d.txt", i+1)
			_ = os.WriteFile(filepath.Join(dir, "sqlmap", filename), []byte(raw), 0600)
			_ = os.WriteFile(filepath.Join(dir, "burp", fmt.Sprintf("burp-%03d.req", i+1)), []byte(raw), 0600)
			index = append(index, map[string]interface{}{"request_filename": filename, "request_id": r.ID, "method": r.Method, "original_url": r.URL, "endpoint_template": r.Template, "parameter_paths": r.Parameters, "body_type": r.BodyType, "authentication_required": r.AuthRequired, "source_page": r.PageURL, "task_id": r.TaskID, "response_status": r.Status, "replayability": r.Replayability, "exclusion_warnings": []string{}})
		}
		entries = append(entries, map[string]interface{}{"request": map[string]interface{}{"method": r.Method, "url": r.URL, "headers": r.Headers, "postData": map[string]string{"mimeType": r.BodyType, "text": r.Body}}, "response": nil})
		u, _ := url.Parse(r.URL)
		if !authSessionRequest(r.URL) {
			items = append(items, map[string]interface{}{"name": r.Method + " " + r.URL, "request": map[string]interface{}{"method": r.Method, "header": headersArray(r.Headers), "body": map[string]string{"mode": "raw", "raw": r.Body}, "url": map[string]interface{}{"raw": r.URL, "protocol": u.Scheme, "host": strings.Split(u.Host, "."), "path": strings.Split(strings.Trim(u.Path, "/"), "/")}}})
		}
	}
	har["log"].(map[string]interface{})["entries"] = entries
	postman["item"] = items
	writeJSON := func(name string, v interface{}) error {
		b, e := json.MarshalIndent(v, "", "  ")
		if e != nil {
			return e
		}
		return os.WriteFile(filepath.Join(dir, name), b, 0600)
	}
	if err := writeJSON(filepath.Join("har", "capture.har"), har); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join("postman", "collection.json"), postman); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join("sqlmap", "index.json"), index); err != nil {
		return err
	}
	return exportDalfox(store, filepath.Join(dir, "dalfox"), private, exportAuth)
}

func exportDalfox(store *RequestStore, dir string, private, exportAuth bool) error {
	rows, err := store.db.Query(`SELECT d.id,d.method,d.url,d.page_url,i.authentication_context,p.source,p.parameter_path,p.inferred_type,p.reflection_status
		FROM scanner_candidates s JOIN discovered_requests d ON d.id=s.request_id JOIN api_endpoint_inventory i ON i.representative_request_id=d.id JOIN request_parameters p ON p.request_id=d.id
		WHERE s.scanner='DALFOX' AND s.eligible=1 AND p.scanner_eligible=1 ORDER BY d.created_at,p.parameter_path`)
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := map[string]bool{}
	var urls strings.Builder
	candidates := []map[string]interface{}{}
	for rows.Next() {
		var id, method, raw, page, auth, source, paramPath, sampleType, reflection string
		if err := rows.Scan(&id, &method, &raw, &page, &auth, &source, &paramPath, &sampleType, &reflection); err != nil {
			return err
		}
		if source != "query" || noiseQuery(paramPath) {
			continue
		}
		authRequired := auth == "AUTHENTICATED"
		reason := ""
		if authRequired && !exportAuth {
			reason = "private_auth_required"
		}
		if reason == "" && !seen[raw] {
			seen[raw] = true
			urls.WriteString(raw + "\n")
		}
		candidates = append(candidates, map[string]interface{}{"request_id": id, "method": method, "url": raw, "parameter_path": paramPath, "sample_type": sampleType, "reflection_status": reflection, "source_page": page, "auth_required": authRequired, "recommended_input_format": "url", "exclusion_reason": reason})
	}
	if err := os.WriteFile(filepath.Join(dir, "urls.txt"), []byte(urls.String()), 0600); err != nil {
		return err
	}
	b, err := json.MarshalIndent(candidates, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "candidates.json"), b, 0600)
}

func headersArray(h map[string]string) []map[string]string {
	out := make([]map[string]string, 0, len(h))
	for k, v := range h {
		out = append(out, map[string]string{"key": k, "value": v})
	}
	return out
}
func replayText(r ReplayRequest) (string, error) {
	u, _ := url.Parse(r.URL)
	host := u.Host
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", r.Method, u.RequestURI(), host)
	for k, v := range r.Headers {
		if strings.EqualFold(k, "host") {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")
	b.WriteString(r.Body)
	return b.String(), nil
}
