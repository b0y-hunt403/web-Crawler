#!/usr/bin/env python3
"""Deterministic localhost-only assessment lab. Never bind externally."""
import hashlib
import json
import sqlite3
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

HOST = "127.0.0.1"
PORT = 18080
MARKER = "RAPTOR_ASSESSMENT_MARKER_7f4c8b9e"
SESSION = "assessment-session"


class Lab(BaseHTTPRequestHandler):
    server_version = "RaptorAssessmentLab/1.0"

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.log_date_time_string(), fmt % args), flush=True)

    def body(self):
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length) if length else b""

    def send(self, code, body, content_type="text/html; charset=utf-8", headers=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def authed(self):
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        return jar.get("lab_session") and jar["lab_session"].value == SESSION

    def do_GET(self):
        parsed = urlparse(self.path)
        q = parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path == "/":
            self.send(200, """<!doctype html><title>Raptor Lab</title>
<a href='/item?id=1'>SQL GET</a><a href='/safe-item?id=1'>SQL control</a>
<a href='/reflect?q=hello'>XSS</a><a href='/escaped?q=hello'>XSS control</a>
<a href='/file?path=marker.txt'>LFI</a><a href='/safe-file?path=marker.txt'>LFI control</a>
<a href='/exposure'>Nuclei exposure</a><a href='/no-exposure'>Nuclei control</a>
<a href='/login'>Login</a><script src='/app.js'></script>
<form action='/form-search' method='post'><input name='term' value='alpha'><button>Search</button></form>""")
        elif parsed.path == "/app.js":
            self.send(200, "fetch('/api/profile?id=7'); const route='/js-only?from=bundle';", "application/javascript")
        elif parsed.path in ("/item", "/safe-item"):
            value = q.get("id", ["1"])[0]
            db = sqlite3.connect(":memory:")
            db.execute("create table items(id integer, name text)")
            db.executemany("insert into items values(?,?)", [(1, "alpha"), (2, "beta")])
            try:
                if parsed.path == "/item":
                    rows = db.execute("select name from items where id=" + value).fetchall()
                else:
                    rows = db.execute("select name from items where id=?", (value,)).fetchall()
                self.send(200, json.dumps(rows), "application/json")
            except sqlite3.Error as exc:
                self.send(500, "SQLite error: " + str(exc), "text/plain")
        elif parsed.path == "/reflect":
            self.send(200, "<div>" + q.get("q", [""])[0] + "</div>")
        elif parsed.path == "/escaped":
            import html
            self.send(200, "<div>" + html.escape(q.get("q", [""])[0]) + "</div>")
        elif parsed.path in ("/file", "/safe-file"):
            requested = unquote(q.get("path", [""])[0])
            if parsed.path == "/file" and (requested.endswith("marker.txt") or "marker.txt" in requested):
                self.send(200, MARKER, "text/plain")
            else:
                self.send(404, "not found", "text/plain")
        elif parsed.path == "/exposure":
            self.send(200, "deterministic exposure", "text/plain", {"X-Raptor-Exposure": "assessment-2026"})
        elif parsed.path == "/no-exposure":
            self.send(200, "negative control", "text/plain")
        elif parsed.path == "/login":
            self.send(200, "<form method='post' action='/login'><input name='username'><input name='password' type='password'><button>Login</button></form>")
        elif parsed.path == "/protected":
            self.send(200 if self.authed() else 401, "protected-ok" if self.authed() else "unauthorized", "text/plain")
        elif parsed.path.startswith("/api/profile") or parsed.path.startswith("/js-only"):
            self.send(200, json.dumps({"ok": True}), "application/json")
        else:
            self.send(404, "not found", "text/plain")

    def do_POST(self):
        parsed = urlparse(self.path)
        raw = self.body()
        if parsed.path == "/login":
            form = parse_qs(raw.decode())
            if form.get("username") == ["lab"] and form.get("password") == ["lab-pass"]:
                self.send(302, b"", headers={"Set-Cookie": "lab_session=%s; HttpOnly; SameSite=Lax" % SESSION, "Location": "/protected"})
            else:
                self.send(401, "invalid", "text/plain")
        elif parsed.path == "/api/json":
            try:
                data = json.loads(raw or b"{}")
                value = str(data.get("id", "1"))
                if "'" in value or '"' in value:
                    self.send(500, "SQLite JSON query error near quote", "text/plain")
                else:
                    self.send(200, json.dumps({"id": value, "ok": True}), "application/json")
            except ValueError:
                self.send(400, "bad json", "text/plain")
        elif parsed.path == "/form-search":
            form = parse_qs(raw.decode())
            self.send(200, json.dumps({"term": form.get("term", [""])[0]}), "application/json")
        else:
            self.send(404, "not found", "text/plain")

    do_PUT = do_POST
    do_PATCH = do_POST


if __name__ == "__main__":
    print(json.dumps({"host": HOST, "port": PORT, "marker_sha256": hashlib.sha256(MARKER.encode()).hexdigest()}), flush=True)
    ThreadingHTTPServer((HOST, PORT), Lab).serve_forever()
