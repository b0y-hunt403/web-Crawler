# Sprint 1 end-to-end result

Run-scoped policy is stored in CrawlerConfig and API FeedRequest options. Fetch
interception performs policy evaluation before ContinueRequest, and successful
FailRequest enforcement is persisted as blocked evidence. The Chromium fixture
executed against 127.0.0.1 and generated SQLite-derived evidence files.
