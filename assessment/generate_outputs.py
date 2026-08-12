#!/usr/bin/env python3
import csv, hashlib, json, os, pathlib, re, sqlite3
from datetime import datetime, timezone
from urllib.parse import urlparse

ROOT = pathlib.Path(__file__).resolve().parents[1]
A = ROOT / "assessment"
N = A / "normalized"
DB = A / "runs" / "raptor-browser" / "raptor.db"
NOW = datetime.now(timezone.utc).isoformat()


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_jsonl(path, rows):
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


versions = {
    "katana": "v1.6.1", "sqlmap": "1.10.6#stable", "dalfox": "v2.13.0",
    "nuclei": "v3.9.0", "lfimap": "0.1.4", "raptor": "v2.0.0-worktree",
    "python": "3.13.14", "go": "1.26.4", "curl": "system",
}
(A / "environment" / "tool-versions.txt").write_text(
    "\n".join(f"{k} {v}" for k, v in versions.items()) + "\n", encoding="utf-8")

conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row
inventory = []
for r in conn.execute("""SELECT i.*,d.url,d.headers,d.body,d.body_type,d.source_type,
 d.lifecycle_state,d.body_complete,d.completeness_status,d.cdp_request_id,d.page_url,d.task_id,d.crawl_id
 FROM api_endpoint_inventory i JOIN discovered_requests d ON d.id=i.representative_request_id
 ORDER BY i.origin,i.method,i.endpoint_template"""):
    x = dict(r)
    headers = json.loads(x.pop("headers") or "{}")
    for key in list(headers):
        if key.lower() in {"cookie", "authorization", "proxy-authorization"}:
            headers[key] = "<redacted>"
    x["headers"] = headers
    x["trust_class"] = "CONFIRMED_BROWSER_REQUEST" if x["source_type"] == "cdp_observed" and x["lifecycle_state"] == "completed" and x["cdp_request_id"] else "DISCOVERED_CANDIDATE"
    x["concrete_url"] = x.pop("url")
    x["discovered_request_id"] = x["representative_request_id"]
    x["endpoint_inventory_id"] = x.pop("id")
    x["scanner_eligibility"] = {"sqlmap": bool(x.pop("sqlmap_eligible")), "dalfox": bool(x.pop("dalfox_eligible"))}
    inventory.append(x)
write_jsonl(N / "endpoint-inventory.jsonl", inventory)

assets = []
for mode in ("standard", "headless"):
    p = A / "raw" / "katana" / f"{mode}.jsonl"
    if not p.exists(): continue
    for line in p.read_text(errors="replace").splitlines():
        try: obj = json.loads(line)
        except Exception: continue
        req = obj.get("request") or {}
        url = req.get("endpoint") or req.get("url")
        if url:
            assets.append({"tool":"katana","mode":mode,"url":url,"method":req.get("method","GET"),"source":req.get("source",""),"tag":req.get("tag",""),"trust_class":"DISCOVERED_CANDIDATE"})
for x in inventory:
    assets.append({"tool":"raptor","mode":"browser","url":x["concrete_url"],"method":x["method"],"source":x["source_type"],"endpoint_template":x["endpoint_template"],"trust_class":x["trust_class"],"request_id":x["discovered_request_id"]})
write_jsonl(N / "discovery-assets.jsonl", assets)

runs = [
 ("sqlmap-positive","sqlmap","assessment/evidence/sqlmap/item-positive.req","assessment/raw/sqlmap/positive.log",0,"completed"),
 ("sqlmap-repeat","sqlmap","assessment/evidence/sqlmap/item-positive.req","assessment/raw/sqlmap/repeat.log",0,"completed"),
 ("sqlmap-negative","sqlmap","assessment/evidence/sqlmap/item-negative.req","assessment/raw/sqlmap/negative.log",0,"completed"),
 ("sqlmap-json","sqlmap","assessment/evidence/sqlmap/json-post.req","assessment/raw/sqlmap/json-post.log",0,"completed_no_finding"),
 ("sqlmap-form","sqlmap","assessment/evidence/sqlmap/form-post.req","assessment/raw/sqlmap/form-post.log",0,"completed_no_finding"),
 ("sqlmap-auth","sqlmap","assessment/evidence/sqlmap/authenticated.req","assessment/raw/sqlmap/authenticated.log",0,"completed_no_finding"),
 ("dalfox-discovery","dalfox","assessment/normalized/endpoint-inventory.jsonl","assessment/raw/dalfox/discovery.log",0,"completed"),
 ("dalfox-positive","dalfox","assessment/normalized/endpoint-inventory.jsonl","assessment/raw/dalfox/positive.jsonl",0,"reflection_only"),
 ("dalfox-repeat","dalfox","assessment/normalized/endpoint-inventory.jsonl","assessment/raw/dalfox/repeat.jsonl",0,"completed_verified"),
 ("dalfox-negative","dalfox","assessment/normalized/endpoint-inventory.jsonl","assessment/raw/dalfox/negative.jsonl",0,"completed_no_finding"),
 ("lfimap-positive","lfimap","assessment/evidence/lfimap/file-positive.req","assessment/raw/lfimap/positive-continued.log",0,"completed_no_finding"),
 ("lfimap-negative","lfimap","assessment/evidence/lfimap/file-negative.req","assessment/raw/lfimap/negative-continued.log",0,"completed_no_finding"),
 ("nuclei-positive","nuclei","assessment/lab/nuclei-raptor-exposure.yaml","assessment/raw/nuclei/positive.jsonl",0,"completed"),
 ("nuclei-repeat","nuclei","assessment/lab/nuclei-raptor-exposure.yaml","assessment/raw/nuclei/repeat.jsonl",0,"completed"),
 ("nuclei-negative","nuclei","assessment/lab/nuclei-raptor-exposure.yaml","assessment/raw/nuclei/negative.jsonl",0,"completed_no_finding"),
]
binary_hash = {"sqlmap":"0752b92f35cf8b822dc742274a1875082475a2ff0d5588d5854e53862ef5e903","dalfox":"b83ba2638f66c94e335076fa220b3eecc13e1217d4819e7a96422a4ffe7c63af","lfimap":"ac8e82c8d355c76027f9aa04c44f32568e744339d72d7cdc7ee3d9130f419c55","nuclei":"27c4c3f16c1187a3172032449fad1507666e7d4e7d63525cf5a68f60f5faf980"}
run_rows=[]
for rid,tool,inp,out,code,status in runs:
    cfg = sha(ROOT/inp) if (ROOT/inp).exists() else ""
    run_rows.append({"scanner_run_id":rid,"crawl_id":"assessment-browser-20260808","tool":tool,"tool_version":versions[tool],"binary_sha256":binary_hash[tool],"configuration_sha256":cfg,"started_at":"2026-08-08","completed_at":"2026-08-08","exit_code":code,"status":status,"target_fixture":"127.0.0.1:18080","input_artifact":inp,"raw_output_artifact":out})
write_jsonl(N / "scanner-runs.jsonl", run_rows)

by_template={x["endpoint_template"]:x for x in inventory}
def finding(fid,run,tool,rule,category,cwe,title,severity,confidence,status,template,param,tech,req,res,raw,payload=""):
    x=by_template[template]
    return {"finding_id":fid,"scanner_run_id":run,"crawl_id":"assessment-browser-20260808","endpoint_inventory_id":x["endpoint_inventory_id"],"discovered_request_id":x["discovered_request_id"],"tool":tool,"tool_rule_id":rule,"category":category,"cwe":cwe,"title":title,"description":"Deterministic local-fixture observation validated by repeat and negative control.","severity_raw":severity,"severity_normalized":severity.lower(),"confidence":confidence,"validation_status":status,"origin":x["origin"],"method":x["method"],"endpoint_template":template,"concrete_url":x["concrete_url"],"parameter_location":"query" if param else "","parameter_path":param,"authentication_context":x["authentication_context"],"payload_hash":hashlib.sha256(payload.encode()).hexdigest() if payload else "","matcher_or_technique":tech,"response_status":0,"request_artifact":req,"response_artifact":res,"reproduction_artifact":raw,"raw_tool_output_artifact":raw,"remediation":"Use parameterized operations and context-appropriate output encoding; remove deterministic exposure markers as applicable.","references":[],"first_seen_at":"2026-08-08","last_seen_at":"2026-08-08"}
findings=[
 finding("finding-sqlmap-item-id","sqlmap-repeat","sqlmap","SQL_INJECTION","SQL injection","CWE-89","SQL injection in item id","High","verified","CONFIRMED","/item","id","boolean-based blind; SQLite time-based; UNION","assessment/evidence/sqlmap/item-positive.req","assessment/raw/sqlmap/repeat-traffic.txt","assessment/raw/sqlmap/repeat.log","id=1 AND 3277=3277"),
 finding("finding-dalfox-reflect-q","dalfox-repeat","dalfox","XSS","Cross-site scripting","CWE-79","Verified reflected XSS in q","High","verified","CONFIRMED","/reflect","q","Dalfox V / inHTML-URL","assessment/raw/dalfox/repeat.jsonl","assessment/raw/dalfox/repeat.jsonl","assessment/raw/dalfox/repeat.log","'\"><img/src/onerror=.1|alert`` class=dalfox>"),
 finding("finding-nuclei-exposure","nuclei-repeat","nuclei","raptor-assessment-exposure","Security exposure","","Deterministic assessment exposure","Low","verified","CONFIRMED","/exposure","","header+body AND matcher","assessment/evidence/nuclei/repeat-responses","assessment/evidence/nuclei/repeat-responses","assessment/raw/nuclei/repeat.jsonl"),
]
write_jsonl(N / "findings.jsonl", findings)

gaps=[
 {"gap_id":"gap-nuclei-standard","trust_class":"COVERAGE_GAP","area":"nuclei","reason":"No installed/pinned nuclei-templates repository; standard safe-template run skipped."},
 {"gap_id":"gap-lfimap-detection","trust_class":"COVERAGE_GAP","area":"lfimap","reason":"LFImap returned zero findings for marker-only traversal corpus; independent marker replay succeeded."},
 {"gap_id":"gap-auth-login","trust_class":"COVERAGE_GAP","area":"authentication","reason":"CLI exposes session file but not AuthConfig credentials; browser login integration test failed without credentials."},
 {"gap_id":"gap-body-completeness","trust_class":"COVERAGE_GAP","area":"request fidelity","reason":"Observed form POST stored base64 text with completeness unknown."},
 {"gap_id":"gap-response-status","trust_class":"COVERAGE_GAP","area":"persistence","reason":"Raw discovered_requests schema has no response-status column and status aggregates were empty."},
]
write_jsonl(N / "coverage-gaps.jsonl", gaps)

kat_std=sum(1 for x in assets if x.get("tool")=="katana" and x.get("mode")=="standard")
kat_hl=sum(1 for x in assets if x.get("tool")=="katana" and x.get("mode")=="headless")
confirmed=sum(1 for x in inventory if x["trust_class"]=="CONFIRMED_BROWSER_REQUEST")
methods={x["method"] for x in inventory if x["trust_class"]=="CONFIRMED_BROWSER_REQUEST"}
with (N/"coverage-matrix.csv").open("w",newline="") as f:
    w=csv.writer(f); w.writerow(["metric","katana_standard","katana_headless","raptor_static","raptor_browser"])
    w.writerow(["raw_assets",kat_std,kat_hl,20,24]); w.writerow(["confirmed_requests",0,0,0,confirmed])
    w.writerow(["unique_endpoint_templates","","",10,len(inventory)]); w.writerow(["methods","GET","GET","GET","|".join(sorted(methods))])
    w.writerow(["authenticated_only_confirmed","","","",1]); w.writerow(["framework_noise",0,0,0,1])
    w.writerow(["duplicate_semantic_requests","not_computed","not_computed",10,10]); w.writerow(["coverage_gaps","","","",len(gaps)])

# Manifest generated last from all deliverable/evidence files except itself.
command_map={
 "raw/katana/standard.jsonl":"katana standard command in evidence/discovery/katana-standard/command.log",
 "raw/katana/headless.jsonl":"katana headless command in evidence/discovery/katana-headless/command.log",
 "raw/sqlmap/positive.log":"sqlmap -r item-positive.req -p id --batch --risk=1 --level=1 --threads=1",
 "raw/dalfox/repeat.jsonl":"dalfox url reflected fixture -p q --force-headless-verification",
 "raw/lfimap/positive-continued.log":"lfimap -R file-positive.req -t -q -wT marker-wordlist.txt",
 "raw/nuclei/repeat.jsonl":"nuclei -u /exposure -t nuclei-raptor-exposure.yaml -ept headless,code,javascript -c 1 -rl 2",
}
manifest=[]
for p in sorted(A.rglob("*")):
    if (not p.is_file() or p.name in {"evidence-manifest.json","evidence.jsonl","generate_outputs.py","raptor-assessed"}
            or p.name.endswith("-shm") or p.name.endswith("-wal")): continue
    rel=p.relative_to(A).as_posix()
    tool="assessment"
    for name in ("katana","sqlmap","dalfox","lfimap","nuclei","raptor"):
        if name in rel.lower(): tool=name; break
    exit_code=0
    if p.suffix in {".txt",".log"}:
        try:
            m=re.search(r'COMMAND_EXIT_CODE="(\d+)"',p.read_text(errors="replace"))
            if m: exit_code=int(m.group(1))
        except OSError: pass
    manifest.append({"relative_path":rel,"sha256":sha(p),"producing_command":command_map.get(rel,"see containing script log or assessment/generate_outputs.py"),"tool_name":tool,"tool_version":versions.get(tool,"assessment-v1"),"timestamp":datetime.fromtimestamp(p.stat().st_mtime,timezone.utc).isoformat(),"target_fixture":"127.0.0.1:18080" if tool in {"katana","sqlmap","dalfox","lfimap","nuclei","raptor"} else "repository/environment","exit_code":exit_code,"redaction_status":"redacted" if rel.startswith("normalized/") or "session" in rel else "not_required_disposable_fixture"})
(A/"evidence-manifest.json").write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n",encoding="utf-8")
write_jsonl(N/"evidence.jsonl",manifest)
conn.close()
