# Crawler integration note (recon / web-walkthrough phase)

**Status:** design note, not implemented. The UI task did not require a crawler;
this records how the crawler logic from
[`Thunderk3g/seo`](https://github.com/Thunderk3g/seo) would map onto Vantage's
**web pipeline recon/mapping phase** if/when we build our own surface-discovery
step (e.g. to feed the Burp/ZAP crawl or to inventory a web app's URL surface).

## What we'd reuse from the `seo` crawler

That platform mirrors Googlebot's model. The reusable logic for Vantage:

| `seo` concept | Vantage use in the recon phase |
|---|---|
| **Two-phase fetch** (raw HTML + links, then deferred JS render) | Discover the static URL surface fast, then render JS-heavy SPA routes so the auth-context crawls don't miss client-rendered endpoints. |
| **Discovered pool → crawl queue** (sitemaps, internal links, canonicals, redirects) | Build the in-scope URL frontier for an approved web asset before handing it to Burp/ZAP. |
| **Priority scoring** (sitemap signals, inbound links, depth, freshness) | Order the frontier so high-value routes (auth, payment, claims) are mapped first under a crawl budget. |
| **Host health / adaptive throttling** (latency, 5xx, timeouts) | Be gentle on production insurance systems — back off automatically, respect change windows. |
| **robots.txt / crawl-delay / concurrency** | Politeness limits on owned-but-production assets. |

## Hard boundaries (unchanged)

- **Scope first.** The crawler only ever runs against an approved web asset
  inside a valid scope-authorization token; every fetched URL is intersected
  with the asset's host/base-URL allowlist (same `assert_targets_in_scope`
  guard the adapters use). Off-scope hosts discovered via links/redirects are
  recorded as out-of-scope and **never fetched**.
- **Discovery only.** It enumerates the URL surface and metadata. It does not
  submit forms with payloads, brute-force, or exploit. Active testing remains
  Burp/ZAP's audit step, and validation stays human-gated.
- **No GSC/indexing claims** — irrelevant here; we only want the crawl-frontier
  and politeness logic, not the search-console emulation.

## Where it would live

`orchestrator/adapters/` — a new `webcrawl_adapter.py` implementing the standard
`ScannerAdapter` contract (`preflight`/`launch`/`wait`/`fetch_raw`/`parse`),
invoked from the web pipeline's **MAPPING** phase ahead of the Burp/ZAP crawl,
emitting discovered URLs as `CanonicalFinding`s of severity `Info` (inventory
facts), exactly like the Nmap adapter does for open services.
