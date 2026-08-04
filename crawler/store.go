// crawler/store.go
package crawler

import (
	"database/sql"
	"encoding/json"
	"time"

	_ "modernc.org/sqlite"
)

// RequestStore persists DiscoveredRequest records to SQLite
type RequestStore struct {
	db *sql.DB
}

func NewRequestStore(dbPath string) (*RequestStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;`); err != nil {
		db.Close()
		return nil, err
	}

	schema := `
CREATE TABLE IF NOT EXISTS discovered_requests (
	id TEXT PRIMARY KEY,
	auth_session_id TEXT,
	url TEXT NOT NULL,
	method TEXT NOT NULL,
	headers TEXT,
	body TEXT,
	source_type TEXT,
	depth INTEGER,
	normalized_url TEXT,
	created_at TIMESTAMP,
	form_fields TEXT,
	form TEXT,
	spa_route TEXT,
	shadow_dom_elements TEXT,
	parameters TEXT,
	cookies TEXT,
	response TEXT,
	body_type TEXT,
	json_format TEXT
	,call_stack TEXT, script_url TEXT, line INTEGER, column_number INTEGER,
	cdp_request_id TEXT, lifecycle_state TEXT, failure_reason TEXT, request_timestamp REAL, response_timestamp REAL, completed_at TIMESTAMP,
	page_url TEXT, task_id TEXT, task_selector TEXT, interaction_type TEXT, parent_workflow_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_normalized_url ON discovered_requests(normalized_url);
CREATE INDEX IF NOT EXISTS idx_source_type ON discovered_requests(source_type);
CREATE TABLE IF NOT EXISTS static_api_candidates (
 id TEXT PRIMARY KEY, url TEXT, raw_url_expression TEXT, method TEXT,
 body_template TEXT, content_type TEXT, headers_template TEXT,
 source_js_url TEXT, page_url TEXT, line INTEGER, column_number INTEGER,
 framework TEXT, confidence REAL, evidence TEXT, body_hash TEXT, original_source_url TEXT, original_line INTEGER, original_column INTEGER, interaction_outcome TEXT, related_error TEXT, confirmed INTEGER, created_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS api_endpoint_inventory (
 id TEXT PRIMARY KEY, method TEXT NOT NULL, endpoint_template TEXT NOT NULL,
 origin TEXT NOT NULL DEFAULT '', endpoint_identity TEXT NOT NULL DEFAULT '',
 classification TEXT NOT NULL, content_type TEXT, request_schema_hash TEXT NOT NULL,
 authentication_context TEXT NOT NULL, first_request_id TEXT NOT NULL,
 representative_request_id TEXT NOT NULL, observation_count INTEGER NOT NULL DEFAULT 1,
 distinct_body_count INTEGER NOT NULL DEFAULT 1, parameter_paths TEXT, status_codes TEXT,
 replayability TEXT, sqlmap_eligible INTEGER NOT NULL DEFAULT 0,
 dalfox_eligible INTEGER NOT NULL DEFAULT 0, exclusion_reasons TEXT,
 created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_api_inventory_method_template ON api_endpoint_inventory(method,endpoint_template);
CREATE TABLE IF NOT EXISTS api_inventory_observations (inventory_id TEXT NOT NULL, request_id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS api_inventory_body_hashes (inventory_id TEXT NOT NULL, body_hash TEXT NOT NULL, PRIMARY KEY(inventory_id,body_hash));
CREATE TABLE IF NOT EXISTS api_inventory_status_codes (inventory_id TEXT NOT NULL, status_code INTEGER NOT NULL, PRIMARY KEY(inventory_id,status_code));
CREATE TABLE IF NOT EXISTS api_inventory_request_bodies (request_id TEXT PRIMARY KEY, inventory_id TEXT NOT NULL, body_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS api_inventory_request_statuses (request_id TEXT NOT NULL, inventory_id TEXT NOT NULL, status_code INTEGER NOT NULL, PRIMARY KEY(request_id,status_code));
CREATE TABLE IF NOT EXISTS request_inventory_state (request_id TEXT PRIMARY KEY, inventory_id TEXT NOT NULL, indexed_body_hash TEXT NOT NULL, indexed_lifecycle TEXT, updated_at TIMESTAMP NOT NULL);
CREATE TABLE IF NOT EXISTS request_parameters (
 id TEXT PRIMARY KEY, request_id TEXT NOT NULL, inventory_id TEXT,
 source TEXT NOT NULL, parameter_path TEXT NOT NULL, inferred_type TEXT,
 sample_length INTEGER, crawler_supplied INTEGER NOT NULL DEFAULT 0,
 application_state INTEGER NOT NULL DEFAULT 0, reflection_status TEXT NOT NULL DEFAULT 'UNKNOWN',
 scanner_eligible INTEGER NOT NULL DEFAULT 0, exclusion_reason TEXT,
 FOREIGN KEY(request_id) REFERENCES discovered_requests(id)
);
CREATE INDEX IF NOT EXISTS idx_request_parameters_request ON request_parameters(request_id);
CREATE TABLE IF NOT EXISTS scanner_candidates (
 id TEXT PRIMARY KEY, request_id TEXT NOT NULL, scanner TEXT NOT NULL,
 parameter_path TEXT, eligible INTEGER NOT NULL, reason TEXT, replayability TEXT,
 created_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS workflow_yield (
 task_id TEXT PRIMARY KEY, page_url TEXT, route_template TEXT, interaction_type TEXT,
 semantic_action TEXT, record_identity TEXT, status TEXT,
 new_endpoint_count INTEGER DEFAULT 0, new_schema_count INTEGER DEFAULT 0,
 new_parameter_count INTEGER DEFAULT 0, application_request_count INTEGER DEFAULT 0,
 framework_request_count INTEGER DEFAULT 0, new_route_count INTEGER DEFAULT 0,
	 elapsed_ms INTEGER DEFAULT 0, failure_reason TEXT, baseline_endpoints TEXT, baseline_schemas TEXT, baseline_parameters TEXT, baseline_routes TEXT
);
CREATE TABLE IF NOT EXISTS coverage_gaps (
 id INTEGER PRIMARY KEY AUTOINCREMENT, candidate_type TEXT, method TEXT,
 url_or_expression TEXT, source TEXT, associated_route TEXT, confidence REAL,
 reason_unconfirmed TEXT, required_capability TEXT, created_at TIMESTAMP NOT NULL
);
`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}

	migrations := map[string]string{
		"auth_session_id": "TEXT", "parameters": "TEXT", "cookies": "TEXT", "response": "TEXT",
		"body_type": "TEXT", "json_format": "TEXT", "call_stack": "TEXT", "script_url": "TEXT",
		"line": "INTEGER", "column_number": "INTEGER",
		"cdp_request_id": "TEXT", "lifecycle_state": "TEXT", "failure_reason": "TEXT", "request_timestamp": "REAL", "response_timestamp": "REAL", "completed_at": "TIMESTAMP",
		"page_url": "TEXT", "task_id": "TEXT", "task_selector": "TEXT", "interaction_type": "TEXT", "parent_workflow_id": "TEXT",
		"frame_url": "TEXT", "frame_id": "TEXT", "shadow_host": "TEXT", "body_complete": "INTEGER", "body_completeness_known": "INTEGER",
		"completeness_status": "TEXT", "resource_type": "TEXT", "document_url": "TEXT", "initiator_type": "TEXT",
	}
	for col, typ := range migrations {
		_, _ = db.Exec("ALTER TABLE discovered_requests ADD COLUMN " + col + " " + typ)
	}
	staticMigrations := map[string]string{"original_source_url": "TEXT", "original_line": "INTEGER", "original_column": "INTEGER", "interaction_outcome": "TEXT", "related_error": "TEXT", "confirmed": "INTEGER"}
	for col, typ := range staticMigrations {
		_, _ = db.Exec("ALTER TABLE static_api_candidates ADD COLUMN " + col + " " + typ)
	}
	_, _ = db.Exec("ALTER TABLE api_endpoint_inventory ADD COLUMN origin TEXT NOT NULL DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE api_endpoint_inventory ADD COLUMN endpoint_identity TEXT NOT NULL DEFAULT ''")
	for _, col := range []string{"baseline_endpoints", "baseline_schemas", "baseline_parameters", "baseline_routes"} {
		_, _ = db.Exec("ALTER TABLE workflow_yield ADD COLUMN " + col + " TEXT")
	}

	return &RequestStore{db: db}, nil
}

func (s *RequestStore) SaveStaticCandidate(c StaticAPICandidate) error {
	id := CalculateFingerprint(c.Method, c.URL+c.RawURLExpression+c.SourceJSURL, c.BodyTemplate, c.ContentType)
	_, err := s.db.Exec(`INSERT OR REPLACE INTO static_api_candidates (id,url,raw_url_expression,method,body_template,content_type,headers_template,source_js_url,page_url,line,column_number,framework,confidence,evidence,body_hash,original_source_url,original_line,original_column,interaction_outcome,related_error,confirmed,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, c.URL, c.RawURLExpression, c.Method, c.BodyTemplate, c.ContentType, c.HeadersTemplate, c.SourceJSURL, c.PageURL, c.Line, c.Column, c.Framework, c.Confidence, c.Evidence, c.BodyHash, c.OriginalSourceURL, c.OriginalLine, c.OriginalColumn, c.InteractionOutcome, c.RelatedError, c.Confirmed, time.Now().UTC())
	return err
}

func (s *RequestStore) MarkStaticCandidateConfirmed(method, rawURL, observedURL string) error {
	_, err := s.db.Exec(`UPDATE static_api_candidates SET confirmed=1 WHERE UPPER(method)=UPPER(?) AND (url=? OR raw_url_expression=?)`, method, observedURL, rawURL)
	return err
}

func (s *RequestStore) Close() error {
	return s.db.Close()
}

// SaveRequest upserts a discovered request
func (s *RequestStore) SaveRequest(req *DiscoveredRequest) error {
	if req.CompletenessStatus == "" {
		if req.BodyCompletenessKnown {
			if req.BodyComplete {
				req.CompletenessStatus = "COMPLETE"
			} else {
				req.CompletenessStatus = "INCOMPLETE"
			}
		} else {
			req.CompletenessStatus = "UNKNOWN"
		}
	}
	headersJSON, _ := json.Marshal(req.Headers)
	fieldsJSON, _ := json.Marshal(req.FormFields)
	formJSON, _ := json.Marshal(req.Form)
	spaJSON, _ := json.Marshal(req.SPARoute)
	shadowJSON, _ := json.Marshal(req.ShadowDOMElements)
	paramsJSON, _ := json.Marshal(req.Parameters)
	cookiesJSON, _ := json.Marshal(req.Cookies)
	responseJSON, _ := json.Marshal(req.Response)
	jsonFormatJSON, _ := json.Marshal(req.JSONFormat)

	if req.CreatedAt.IsZero() {
		req.CreatedAt = time.Now().UTC()
	}

	_, err := s.db.Exec(`
INSERT INTO discovered_requests
	(id, auth_session_id, url, method, headers, body, source_type, depth, normalized_url, created_at,
	 form_fields, form, spa_route, shadow_dom_elements, parameters, cookies, response, body_type, json_format, call_stack, script_url, line, column_number, cdp_request_id, lifecycle_state, failure_reason, request_timestamp, response_timestamp, completed_at,
	 page_url, task_id, task_selector, interaction_type, parent_workflow_id, frame_url, frame_id, shadow_host, body_complete, body_completeness_known, completeness_status, resource_type, document_url, initiator_type)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET
	auth_session_id=COALESCE(excluded.auth_session_id, discovered_requests.auth_session_id),
	url=excluded.url, method=excluded.method, headers=excluded.headers, body=excluded.body,
	source_type=excluded.source_type, depth=MIN(discovered_requests.depth, excluded.depth),
	normalized_url=excluded.normalized_url, form_fields=excluded.form_fields, form=excluded.form,
	spa_route=excluded.spa_route, shadow_dom_elements=excluded.shadow_dom_elements,
	parameters=excluded.parameters, cookies=excluded.cookies,
	response=CASE WHEN excluded.response IS NOT NULL AND excluded.response != 'null' THEN excluded.response ELSE discovered_requests.response END,
	body_type=CASE WHEN excluded.body_type != '' THEN excluded.body_type ELSE discovered_requests.body_type END,
	json_format=CASE WHEN excluded.json_format IS NOT NULL AND excluded.json_format != 'null' THEN excluded.json_format ELSE discovered_requests.json_format END,
	call_stack=CASE WHEN excluded.call_stack != '' THEN excluded.call_stack ELSE discovered_requests.call_stack END,
	script_url=CASE WHEN excluded.script_url != '' THEN excluded.script_url ELSE discovered_requests.script_url END,
	line=CASE WHEN excluded.line != 0 THEN excluded.line ELSE discovered_requests.line END,
	column_number=CASE WHEN excluded.column_number != 0 THEN excluded.column_number ELSE discovered_requests.column_number END,
	cdp_request_id=excluded.cdp_request_id, lifecycle_state=excluded.lifecycle_state, failure_reason=excluded.failure_reason, request_timestamp=excluded.request_timestamp, response_timestamp=CASE WHEN excluded.response_timestamp != 0 THEN excluded.response_timestamp ELSE discovered_requests.response_timestamp END, completed_at=CASE WHEN excluded.completed_at IS NOT NULL THEN excluded.completed_at ELSE discovered_requests.completed_at END,
	page_url=excluded.page_url, task_id=excluded.task_id, task_selector=excluded.task_selector, interaction_type=excluded.interaction_type, parent_workflow_id=excluded.parent_workflow_id,
	frame_url=excluded.frame_url, frame_id=excluded.frame_id, shadow_host=excluded.shadow_host, body_complete=excluded.body_complete, body_completeness_known=excluded.body_completeness_known, completeness_status=excluded.completeness_status, resource_type=excluded.resource_type, document_url=excluded.document_url, initiator_type=excluded.initiator_type
`,
		req.ID, req.AuthSessionID, req.URL, req.Method, string(headersJSON), req.Body, req.SourceType,
		req.Depth, req.NormalizedURL, req.CreatedAt, string(fieldsJSON), string(formJSON),
		string(spaJSON), string(shadowJSON), string(paramsJSON), string(cookiesJSON), string(responseJSON),
		req.BodyType, string(jsonFormatJSON), req.CallStack, req.ScriptURL, req.Line, req.Column, req.CDPRequestID, req.LifecycleState, req.FailureReason, req.RequestTimestamp, req.ResponseTimestamp, req.CompletedAt,
		req.PageURL, req.TaskID, req.TaskSelector, req.InteractionType, req.ParentWorkflowID,
		req.FrameURL, req.FrameID, req.ShadowHost, req.BodyComplete, req.BodyCompletenessKnown,
		req.CompletenessStatus, req.ResourceType, req.DocumentURL, req.InitiatorType,
	)
	if err != nil {
		return err
	}
	return s.IndexRequest(req)
}

// DeleteRequestByURL removes a stale record
func (s *RequestStore) DeleteRequestByURL(url string) error {
	_, err := s.db.Exec(`DELETE FROM discovered_requests WHERE url = ?`, url)
	return err
}

func (s *RequestStore) Count() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM discovered_requests`).Scan(&n)
	return n, err
}

func (s *RequestStore) SaveCoverageGap(candidateType, method, expression, source, route string, confidence float64, reason, capability string) error {
	_, err := s.db.Exec(`INSERT INTO coverage_gaps(candidate_type,method,url_or_expression,source,associated_route,confidence,reason_unconfirmed,required_capability,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, candidateType, method, expression, source, route, confidence, reason, capability, time.Now().UTC())
	return err
}

func (s *RequestStore) SaveWorkflowYield(task *workflowTask, status string, elapsed time.Duration) error {
	if task == nil {
		return nil
	}
	endpoints, schemas, params, routes := []string{}, []string{}, []string{}, []string{}
	query := `SELECT DISTINCT i.endpoint_identity,i.id,p.parameter_path,d.page_url FROM discovered_requests d LEFT JOIN api_inventory_observations o ON o.request_id=d.id LEFT JOIN api_endpoint_inventory i ON i.id=o.inventory_id LEFT JOIN request_parameters p ON p.request_id=d.id`
	rows, _ := s.db.Query(query)
	if rows != nil {
		for rows.Next() {
			var e, sh, p, r string
			_ = rows.Scan(&e, &sh, &p, &r)
			if e != "" {
				endpoints = appendUnique(endpoints, e)
			}
			if sh != "" {
				schemas = appendUnique(schemas, sh)
			}
			if p != "" {
				params = appendUnique(params, p)
			}
			if r != "" {
				routes = appendUnique(routes, EndpointTemplate(r))
			}
		}
		rows.Close()
	}
	if status == "__BASELINE__" {
		be, _ := json.Marshal(endpoints)
		bs, _ := json.Marshal(schemas)
		bp, _ := json.Marshal(params)
		br, _ := json.Marshal(routes)
		_, err := s.db.Exec(`INSERT OR REPLACE INTO workflow_yield(task_id,page_url,route_template,interaction_type,semantic_action,record_identity,status,baseline_endpoints,baseline_schemas,baseline_parameters,baseline_routes) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, task.ID, task.PageURL, EndpointTemplate(task.PageURL), string(task.Category), task.SemanticType, task.RecordIdentity, status, string(be), string(bs), string(bp), string(br))
		return err
	}
	var beJSON, bsJSON, bpJSON, brJSON string
	_ = s.db.QueryRow(`SELECT baseline_endpoints,baseline_schemas,baseline_parameters,baseline_routes FROM workflow_yield WHERE task_id=?`, task.ID).Scan(&beJSON, &bsJSON, &bpJSON, &brJSON)
	var be, bs, bp, br []string
	_ = json.Unmarshal([]byte(beJSON), &be)
	_ = json.Unmarshal([]byte(bsJSON), &bs)
	_ = json.Unmarshal([]byte(bpJSON), &bp)
	_ = json.Unmarshal([]byte(brJSON), &br)
	diff := func(now, old []string) int {
		m := map[string]bool{}
		for _, x := range old {
			m[x] = true
		}
		n := 0
		for _, x := range now {
			if !m[x] {
				n++
			}
		}
		return n
	}
	var app, framework int
	_ = s.db.QueryRow(`SELECT COUNT(DISTINCT d.id) FROM discovered_requests d JOIN api_inventory_observations o ON o.request_id=d.id JOIN api_endpoint_inventory i ON i.id=o.inventory_id WHERE d.task_id=? AND i.classification IN ('APPLICATION','GRAPHQL','PARAMETERIZED_NAVIGATION')`, task.ID).Scan(&app)
	_ = s.db.QueryRow(`SELECT COUNT(DISTINCT d.id) FROM discovered_requests d JOIN api_inventory_observations o ON o.request_id=d.id JOIN api_endpoint_inventory i ON i.id=o.inventory_id WHERE d.task_id=? AND i.classification IN ('FRAMEWORK','DEVELOPMENT','PREFLIGHT')`, task.ID).Scan(&framework)
	finalStatus := status
	if app == 0 && framework > 0 {
		finalStatus = "FRAMEWORK_ONLY"
	}
	if app == 0 && framework == 0 && diff(routes, br) > 0 {
		finalStatus = "NEW_WORKFLOW_STATE"
	}
	if finalStatus == "NEW_ENDPOINT" && diff(endpoints, be) == 0 {
		if diff(schemas, bs) > 0 {
			finalStatus = "NEW_SCHEMA"
		} else if diff(params, bp) > 0 {
			finalStatus = "NEW_PARAMETERS"
		} else if app > 0 {
			finalStatus = "KNOWN_APPLICATION_REQUEST"
		} else {
			finalStatus = "NO_YIELD"
		}
	}
	_, err := s.db.Exec(`UPDATE workflow_yield SET status=?,record_identity=?,new_endpoint_count=?,new_schema_count=?,new_parameter_count=?,application_request_count=?,framework_request_count=?,new_route_count=?,elapsed_ms=?,failure_reason=? WHERE task_id=?`, finalStatus, task.RecordIdentity, diff(endpoints, be), diff(schemas, bs), diff(params, bp), app, framework, diff(routes, br), elapsed.Milliseconds(), task.FailureReason, task.ID)
	return err
}
