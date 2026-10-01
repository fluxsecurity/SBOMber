This script refreshes advisory fixtures used for offline testing and inspection.

Usage:

```bash
# from repository root
go run ./scripts/update_advisories.go
```

It will fetch the CISA KEV catalog and EPSS scores for CVEs found in the KEV feed and write JSON fixtures to `testdata/advisories/kev.json` and `testdata/advisories/epss.json`.

Notes:
- The script performs network requests; ensure you have an Internet connection.
- GHSA advisories require GitHub API access; this script currently does not bulk-fetch GHSA advisories.
