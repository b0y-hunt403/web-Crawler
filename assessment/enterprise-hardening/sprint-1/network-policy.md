# Sprint 1 network policy

Fetch interception now evaluates `DecideNetworkPolicy` before invoking either
`fetch.ContinueRequest` or `fetch.FailRequest`. Read-only methods are allowed;
DELETE is blocked unless destructive actions are enabled; POST/PUT/PATCH are
blocked when mutations are disabled, except for an active authentication POST
and an explicit GraphQL query classification. Blocked observations are emitted
as `cdp_policy_blocked` with lifecycle `blocked_by_policy` and are excluded from
scanner eligibility.

The deterministic fixture test confirms that only the approved authentication
POST reaches its server; background mutation requests are not sent.
