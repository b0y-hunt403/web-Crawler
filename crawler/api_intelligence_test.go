package crawler

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func observed(method, rawURL, body, contentType string) *DiscoveredRequest {
	return &DiscoveredRequest{ID: CalculateFingerprint(method, rawURL, body, contentType), Method: method, URL: rawURL, Body: body, BodyType: bodyTypeFromContentType(contentType), Headers: map[string]string{"Content-Type": contentType}, SourceType: "cdp_observed", LifecycleState: "completed", CreatedAt: time.Now(), BodyComplete: true, BodyCompletenessKnown: true, Response: &ResponseMetadata{StatusCode: 200, ContentType: "application/json"}}
}

func TestEndpointTemplatePreservesStaticSegments(t *testing.T) {
	tests := map[string]string{
		"https://example.test/client/assets/d0d70490-1763-44a5-b363-f573a56f505d": "/client/assets/{uuid}",
		"https://example.test/projects/123/issues/456":                            "/projects/{int}/issues/{int}",
		"https://example.test/discovery/cve/CVE-2026-4816":                        "/discovery/cve/{cve}",
	}
	for input, want := range tests {
		if got := EndpointTemplate(input); got != want {
			t.Errorf("%s: got %s want %s", input, got, want)
		}
	}
}

func TestClassificationIsExclusiveAndFrameworkExcluded(t *testing.T) {
	tests := []struct {
		method, url string
		want        RequestClassification
	}{{"OPTIONS", "https://x.test/api", "PREFLIGHT"}, {"GET", "https://x.test/_next/app.js", "FRAMEWORK"}, {"GET", "https://x.test/a?_rsc=abc", "FRAMEWORK"}, {"POST", "https://x.test/refresh-token", "AUTH_SESSION"}, {"POST", "https://x.test/graphql", "GRAPHQL"}, {"POST", "https://x.test/products", "APPLICATION"}}
	for _, tt := range tests {
		r := observed(tt.method, tt.url, `{"q":"x"}`, "application/json")
		if got := ClassifyObservedRequest(r); got != tt.want {
			t.Errorf("%s got %s want %s", tt.url, got, tt.want)
		}
	}
}

func TestSchemaFingerprintIgnoresValuesAndExtractsNestedPaths(t *testing.T) {
	a := AnalyzeRequest(observed("POST", "https://x.test/products?q=first", `{"vendor":"A","profile":{"email":"a@x"},"items":[{"id":1}]}`, "application/json"))
	b := AnalyzeRequest(observed("POST", "https://x.test/products?q=second", `{"vendor":"B","profile":{"email":"b@x"},"items":[{"id":2}]}`, "application/json"))
	if a.SchemaHash != b.SchemaHash {
		t.Fatalf("volatile values changed schema: %s != %s", a.SchemaHash, b.SchemaHash)
	}
	joined := strings.Join(schemaParameters(a.Parameters), ",")
	for _, want := range []string{"query.q:string", "json.vendor:string", "json.profile.email:string", "json.items[0].id:integer"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s in %s", want, joined)
		}
	}
}

func TestInventoryCollapsesDuplicateSchemasButRetainsRawRows(t *testing.T) {
	store, err := NewRequestStore(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for i, body := range []string{`{"vendor":"A"}`, `{"vendor":"B"}`} {
		r := observed("POST", "https://x.test/products", body, "application/json")
		r.ID += string(rune('a' + i))
		if err := store.SaveRequest(r); err != nil {
			t.Fatal(err)
		}
	}
	assertCount(t, store.db, "SELECT COUNT(*) FROM discovered_requests", 2)
	assertCount(t, store.db, "SELECT COUNT(*) FROM api_endpoint_inventory", 1)
	assertCount(t, store.db, "SELECT observation_count FROM api_endpoint_inventory", 2)
}

func TestIncompleteBodyRetainedButNotScannerEligible(t *testing.T) {
	store, err := NewRequestStore(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	r := observed("POST", "https://x.test/products", `{"required_id":""}`, "application/json")
	r.BodyComplete = false
	if err := store.SaveRequest(r); err != nil {
		t.Fatal(err)
	}
	assertCount(t, store.db, "SELECT COUNT(*) FROM discovered_requests", 1)
	assertCount(t, store.db, "SELECT COUNT(*) FROM api_endpoint_inventory WHERE sqlmap_eligible=1", 0)
	var reasons string
	if err := store.db.QueryRow("SELECT exclusion_reasons FROM api_endpoint_inventory").Scan(&reasons); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reasons, "request_body_incomplete") {
		t.Fatalf("missing incomplete reason: %s", reasons)
	}
}

func TestCuratedExportsDoNotTurnJSONPostIntoDalfoxURL(t *testing.T) {
	store, err := NewRequestStore(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	post := observed("POST", "https://x.test/products", `{"name":"marker"}`, "application/json")
	get := observed("GET", "https://x.test/search?q=marker", "", "text/plain")
	if err := store.SaveRequest(post); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRequest(get); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "exports")
	os.Unsetenv("RAPTOR_EXPORT_PRIVATE_REPLAY")
	os.Setenv("RAPTOR_EXPORT_MUTATIONS", "true")
	defer os.Unsetenv("RAPTOR_EXPORT_MUTATIONS")
	if err := ExportReplayArtifacts(store, dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "safe", "dalfox", "urls.txt"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "/search?q=marker") {
		t.Fatalf("GET missing: %s", text)
	}
	if strings.Contains(text, "/products") {
		t.Fatalf("JSON POST fabricated as GET: %s", text)
	}
	index, err := os.ReadFile(filepath.Join(dir, "safe", "sqlmap", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var entries []map[string]interface{}
	if json.Unmarshal(index, &entries) != nil || len(entries) != 2 {
		t.Fatalf("unexpected SQLMap index: %s", index)
	}
}

func assertCount(t *testing.T, db *sql.DB, query string, want int) {
	t.Helper()
	var got int
	if err := db.QueryRow(query).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s: got %d want %d", query, got, want)
	}
}

func TestLifecycleIdentityOriginBodiesAndStatuses(t *testing.T) {
	s, err := NewRequestStore(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := observed("POST", "http://host:38415/api/items?q=x", ``, "application/json")
	base.CDPRequestID = "cdp-1"
	base.Body = ""
	base.Response = nil
	base.LifecycleState = "observed"
	if err = s.SaveRequest(base); err != nil {
		t.Fatal(err)
	}
	final := observed("POST", "http://host:38415/api/items?q=x", `{"name":"x"}`, "application/json")
	final.ID = base.ID
	final.CDPRequestID = "cdp-1"
	final.Response = &ResponseMetadata{StatusCode: 400}
	final.LifecycleState = "completed"
	if err = s.SaveRequest(final); err != nil {
		t.Fatal(err)
	}
	for _, code := range []int{401, 200} {
		r := observed("POST", "http://host:38415/api/items?q=x", `{"name":"x"}`, "application/json")
		r.ID = base.ID
		r.CDPRequestID = "cdp-1"
		r.Response = &ResponseMetadata{StatusCode: code}
		r.LifecycleState = "completed"
		if err = s.SaveRequest(r); err != nil {
			t.Fatal(err)
		}
	}
	assertCount(t, s.db, "SELECT COUNT(*) FROM api_inventory_observations", 1)
	assertCount(t, s.db, "SELECT COUNT(*) FROM api_endpoint_inventory", 1)
	assertCount(t, s.db, "SELECT distinct_body_count FROM api_endpoint_inventory", 1)
	var origin, statuses string
	if err = s.db.QueryRow("SELECT origin,status_codes FROM api_endpoint_inventory").Scan(&origin, &statuses); err != nil {
		t.Fatal(err)
	}
	if origin != "http://host:38415" || !strings.Contains(statuses, "400") || !strings.Contains(statuses, "401") || !strings.Contains(statuses, "200") {
		t.Fatalf("origin/status evidence %s %s", origin, statuses)
	}
	other := observed("POST", "http://host:49253/api/items?q=x", `{"name":"x"}`, "application/json")
	other.CDPRequestID = "cdp-2"
	if err = s.SaveRequest(other); err != nil {
		t.Fatal(err)
	}
	assertCount(t, s.db, "SELECT COUNT(*) FROM api_endpoint_inventory", 2)
}

func TestSensitiveNamesAndBodylessParameterizedNavigation(t *testing.T) {
	for _, p := range []string{"query.password", "json.password", "form.csrf", "graphql.variables.accessToken"} {
		if param("json", p, "string", "x", true).ScannerEligible {
			t.Fatalf("sensitive parameter eligible: %s", p)
		}
	}
	r := observed("GET", "https://x.test/search?q=hello", "", "text/html")
	r.ResourceType = "Document"
	a := AnalyzeRequest(r)
	if !a.DalfoxEligible || !a.SQLMapEligible {
		t.Fatalf("parameterized navigation not eligible: %+v", a)
	}
	mutation := observed("PUT", "https://x.test/items?id=1", "", "application/json")
	if got, _ := replayability(mutation, AnalyzeRequest(mutation)); got == "INCOMPLETE" {
		t.Fatalf("bodyless parameterized request incorrectly incomplete")
	}
}

func TestRepresentativeQualityPrefersSuccessfulCompleteRequest(t *testing.T) {
	s, err := NewRequestStore(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	first := observed("POST", "https://x.test/items", `{"name":"a"}`, "application/json")
	first.CDPRequestID = "q1"
	first.Response = &ResponseMetadata{StatusCode: 400}
	first.LifecycleState = "completed"
	if err = s.SaveRequest(first); err != nil {
		t.Fatal(err)
	}
	second := observed("POST", "https://x.test/items", `{"name":"b"}`, "application/json")
	second.CDPRequestID = "q2"
	second.Response = &ResponseMetadata{StatusCode: 200}
	second.LifecycleState = "completed"
	if err = s.SaveRequest(second); err != nil {
		t.Fatal(err)
	}
	var rep string
	if err = s.db.QueryRow("SELECT representative_request_id FROM api_endpoint_inventory WHERE method='POST'").Scan(&rep); err != nil {
		t.Fatal(err)
	}
	if rep != second.ID {
		t.Fatalf("representative=%s want %s", rep, second.ID)
	}
}

func TestMovedRequestLeavesNoDerivedOrphans(t *testing.T) {
	s, err := NewRequestStore(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := observed("POST", "https://x.test/items", ``, "application/json")
	r.CDPRequestID = "move"
	r.LifecycleState = "observed"
	if err = s.SaveRequest(r); err != nil {
		t.Fatal(err)
	}
	r.Body = `{"name":"x"}`
	r.LifecycleState = "completed"
	r.Response = &ResponseMetadata{StatusCode: 200}
	if err = s.SaveRequest(r); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"SELECT COUNT(*) FROM api_inventory_observations o LEFT JOIN api_endpoint_inventory i ON i.id=o.inventory_id WHERE i.id IS NULL", "SELECT COUNT(*) FROM api_inventory_request_bodies b LEFT JOIN api_endpoint_inventory i ON i.id=b.inventory_id WHERE i.id IS NULL", "SELECT COUNT(*) FROM api_inventory_request_statuses s LEFT JOIN api_endpoint_inventory i ON i.id=s.inventory_id WHERE i.id IS NULL", "SELECT COUNT(*) FROM request_parameters p LEFT JOIN discovered_requests d ON d.id=p.request_id WHERE d.id IS NULL", "SELECT COUNT(*) FROM scanner_candidates c LEFT JOIN discovered_requests d ON d.id=c.request_id WHERE d.id IS NULL"} {
		assertCount(t, s.db, q, 0)
	}
	assertCount(t, s.db, "SELECT COUNT(*) FROM api_endpoint_inventory i LEFT JOIN discovered_requests d ON d.id=i.representative_request_id WHERE d.id IS NULL", 0)
}

func TestWorkflowYieldGlobalSetDifferencesAndDistinctRequestCount(t *testing.T) {
	s, err := NewRequestStore(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	known := observed("POST", "https://x.test/items", `{"name":"a"}`, "application/json")
	known.TaskID = "other-task"
	if err = s.SaveRequest(known); err != nil {
		t.Fatal(err)
	}
	task := &workflowTask{ID: "task-known", PageURL: "https://x.test/work", Category: workflowControl, SemanticType: "save", RecordIdentity: "r1"}
	if err = s.SaveWorkflowYield(task, "__BASELINE__", 0); err != nil {
		t.Fatal(err)
	}
	request := observed("POST", "https://x.test/items", `{"name":"b","extra":1,"p1":"x","p2":"x","p3":"x"}`, "application/json")
	request.TaskID = task.ID
	if err = s.SaveRequest(request); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveWorkflowYield(task, "NEW_ENDPOINT", 12*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	var status string
	var app, newEndpoint, newSchema int
	if err = s.db.QueryRow("SELECT status,application_request_count,new_endpoint_count,new_schema_count FROM workflow_yield WHERE task_id=?", task.ID).Scan(&status, &app, &newEndpoint, &newSchema); err != nil {
		t.Fatal(err)
	}
	if status != "NEW_SCHEMA" || app != 1 || newEndpoint != 0 || newSchema != 1 {
		t.Fatalf("yield status=%s app=%d endpoint=%d schema=%d", status, app, newEndpoint, newSchema)
	}
}
