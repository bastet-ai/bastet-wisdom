# HackerOne Data Collection Playbook

Last updated: 2025-09-01

## Goals
- Aggregate program payouts for a given month or window via API
- Snapshot program policy/scope content for high-value targets

## Part 1: Payout Aggregation (API-first)

### Endpoint
- `GET https://api.hackerone.com/v1/hackers/hacktivity`

### Auth
- HTTP Basic: `username:token` (H1_USERNAME, H1_API_TOKEN)

### Filters
- Preferred filter by award activity month:
```
latest_disclosable_action:Activities::BountyAwarded latest_disclosable_activity_at:[YYYY-MM-01 TO YYYY-(MM+1)-01) total_awarded_amount:>0
```
- Send both `querystring` and `filter[query]` params
- Include relationships to resolve names:
```
include=program,award&fields[program]=name,handle
```

### Field resolution
- Amount: try `total_awarded_amount`, `total_awarded_amount_in_usd`, `awarded_amount`, `bounty_amount`, else use `award.attributes.amount_in_usd`
- Program: prefer `relationships.program.data.attributes.name` or `handle`; else resolve from `included`

### Pagination
- Follow `links.next` (full URL); support `page[cursor]` extraction fallback

### Fallback Mode
- If filtered returns empty, fetch unfiltered pages and filter locally by month and amount>0

### Outputs
- Raw JSON: `logs/tool_outputs/h1_api_payouts_YYYY-MM_<ts>_raw.json`
- Aggregated CSV: `logs/findings/h1_api_payouts_YYYY-MM_<ts>_agg.csv`

## Part 2: Policy/Scope Snapshot (Playwright)

### Why
- Policy/scope text isn’t returned by the Hacker API; scrape program page

### Runtime
- Non-headless during debugging (`--no-headless`), use slow-mo, explicit waits, retries, and minimum content length

### Selectors
- Try in order:
  - `section:has(h2:has-text("Scope"))`
  - `section:has(h2:has-text("Program Rules"))`
  - `section:has(h2:has-text("Policy"))`
  - `section[aria-label*="Scope" i]`
  - Fallback: `main`

### Hydration
- Wait for `main`, scroll to bottom and back to top, backoff between retries

### Acceptance
- Require `min_chars` (e.g., 1200) before saving; keep longest non-empty otherwise

### Wiki Update
- For each high-value program, update `targets/docs/programs/<program>/scope.md`:
  - Add `Program Policy URL`
  - Date-stamp snapshot
  - Paste captured text

## Tools
- `tools/hackerone_top/api_client.py`
- `tools/hackerone_top/aggregate_last6.py`
- `tools/scope_fetcher/fetch_scopes.py`

## Lessons Learned
- API is authoritative for payouts; webpages may hide amounts or load async
- Relationship resolution improves program naming
- Scraping requires retries and content-length checks for reliable results
- Always persist raw data alongside aggregations for traceability
