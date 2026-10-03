# web-recon-toolkit

Small, dependency-free Node.js tools for passive web reconnaissance using **public
Certificate Transparency (CT) logs** and other open data. No `npm install` — they use
Node's built-in `fetch` (Node 18+).

Everything here is OSINT over **public records** (published TLS certificates, the npm
registry, OSV.dev). Intended for brand monitoring, typosquat / phishing discovery,
attack-surface mapping, and version/vuln auditing of sites you are authorized to assess.

---

## Tools

### 1. `find-domains.mjs` — keyword → every registered domain using it

Give it a name or keyword and it enumerates every registered domain that contains it,
collapsing the thousands of subdomain certificates down to unique **registrable domains**
(eTLD+1). Great for discovering brand abuse and typosquats.

```bash
node find-domains.mjs tesla                      # all domains containing "tesla"
node find-domains.mjs tesla --in-name            # keyword must be in the base domain
node find-domains.mjs tesla --tld com,io,ai      # restrict to these TLDs
node find-domains.mjs "paypal-login" --out squats.csv
node find-domains.mjs tesla --json               # machine-readable
```

| Flag | Meaning |
|------|---------|
| `--in-name` | Keep only domains where the keyword is in the registrable name, not just a subdomain |
| `--tld a,b,c` | Restrict to the listed TLDs |
| `--out <file>` | Also write results to CSV |
| `--json` | JSON output |

### 2. `new-domains.mjs` — watch for newly appearing domains

Watches CT logs for brand-new certificates matching a keyword — a near-real-time signal
that a new site has just gone live. Polling mode prints only domains it hasn't seen before.

```bash
node new-domains.mjs --watch mybrand               # one-shot
node new-domains.mjs --watch mybrand --poll 300    # re-check every 300s, show only NEW
node new-domains.mjs --watch "login-mybrand"       # typosquat hunting
node new-domains.mjs --watch mybrand.com --json
```

### 3. `czds-pull.mjs` — new registrations from ICANN CZDS zone files (+ WHOIS/RDAP)

The authoritative complement to CT-log discovery: it catches domains the moment they are
**registered**, before any TLS certificate exists. It authenticates to ICANN's Centralized
Zone Data Service, downloads the daily gTLD zone files you're approved for, and **diffs
today's set of delegated domains against the previous snapshot** — the domains that newly
appear are new registrations (and ones that vanish are expirations). It can confirm creation
dates via RDAP (modern WHOIS), and doubles as a one-off WHOIS date checker.

**One-time setup:** create an account at [czds.icann.org](https://czds.icann.org), request
access to the TLDs you need (approved per registry), then set credentials as env vars:

```bash
export CZDS_USERNAME=you@example.com
export CZDS_PASSWORD=…
# PowerShell: $env:CZDS_USERNAME="you@example.com"; $env:CZDS_PASSWORD="…"
```

```bash
node czds-pull.mjs --list                 # zones you're approved for
node czds-pull.mjs                         # pull all approved zones, diff, list new regs
node czds-pull.mjs --tld xyz,top           # only these zones
node czds-pull.mjs --match shop            # only new domains containing a keyword
node czds-pull.mjs --confirm               # RDAP-confirm creation dates of the new domains
node czds-pull.mjs --out new-regs.csv      # also write a CSV
node czds-pull.mjs --whois example.com     # just an RDAP creation-date lookup (no CZDS needed)
```

Credentials are read **only** from environment variables — never hardcode them. The first
run on a zone just saves a baseline snapshot (nothing to diff yet); run again on a later day
to see new registrations. Snapshots are stored under `.czds-state/` (git-ignored). Note that
some zones (e.g. `.com`) are very large; filter with `--tld` and ensure adequate disk/RAM.

### 4. `nextjs-version.mjs` — exact Next.js version + vuln check

Fingerprints a live site's **exact** Next.js version from its client bundle, then enriches
it: how far behind the latest npm release it is, and known CVEs for that exact version via
[OSV.dev](https://osv.dev).

```bash
node nextjs-version.mjs https://example.com
node nextjs-version.mjs example.com --json
```

A Bash equivalent, `nextjs-version.sh`, is included for shell-only environments.

---

## Data sources & reliability

- **[crt.sh](https://crt.sh)** — primary CT-log search (supports wildcard keyword matching).
  It is a free, shared service and occasionally returns `502`/`503`; the domain tools retry
  with backoff.
- **[SSLMate CertSpotter](https://sslmate.com/certspotter/)** — automatic fallback when
  crt.sh is unavailable. It searches a *specific domain* (plus subdomains), so the fallback
  only applies when the keyword is a full domain (e.g. `mybrand.com`).
- **[ICANN CZDS](https://czds.icann.org)** — daily gTLD zone files (requires a free account
  and per-TLD approval); the authoritative source for brand-new registrations.
- **[RDAP](https://rdap.org)** — structured modern WHOIS, for creation/expiration dates.
- **npm registry** and **OSV.dev** — for the Next.js version/vulnerability enrichment.

The domain tools approximate eTLD+1 with a compact built-in public-suffix set covering the
common country combinations (`co.uk`, `com.au`, …). It is not the full Public Suffix List,
but handles the vast majority of real-world domains.

---

## Requirements

- Node.js 18 or newer (uses built-in `fetch`). No external dependencies.

## Legal / ethical use

These tools only read public data. Use them for your own assets, authorized security
assessments, CTFs, and research. Respect the free services' capacity — keep `--poll`
intervals reasonable (the tools floor polling at 120s).
