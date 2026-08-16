# Sprint 1 redaction policy

Routine request logs contain method, redacted URL, resource/content type, body
length and hashed request identifiers. Runtime hook and WebSocket hook logs do
not print their original payloads. Sensitive query values and browser
`/devtools/browser/` URLs are replaced or hashed. Blocked-request logs contain
only a rule and request-id hash. Existing safe-export redaction remains in
force; no private evidence path was changed.
