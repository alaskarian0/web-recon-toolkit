#!/usr/bin/env node
/**
 * new-domains.mjs — discover newly registered / newly live websites.
 *
 * Uses PUBLIC Certificate Transparency (CT) logs via the free crt.sh service.
 * Almost every new site gets a TLS certificate the moment it goes live, and
 * those certs are logged publicly within minutes. This is the fastest free,
 * legal signal for "a new website just appeared".
 *
 * Two modes:
 *   1) Keyword watch  — find brand-new certs whose domain matches a keyword
 *                       (brand monitoring, typosquat / phishing detection).
 *   2) Recent dump    — pull the most recent certs for a TLD-ish query.
 *
 * Usage:
 *   node new-domains.mjs --watch mybrand           # one-shot search
 *   node new-domains.mjs --watch mybrand --poll 300 # re-check every 300s, only show NEW
 *   node new-domains.mjs --watch "login-mybrand"   # typosquat hunting
 *   node new-domains.mjs --watch mybrand --json
 *
 * Needs: Node 18+ (built-in fetch). No npm install required.
 *
 * Note: crt.sh is a shared free service — be polite. Keep --poll >= 120s.
 */

const args = process.argv.slice(2);
const getArg = (flag) => {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
};
const JSON_OUT = args.includes('--json');
const keyword = getArg('--watch');
const pollSecs = Number(getArg('--poll') || 0);
const UA = 'Mozilla/5.0 (new-domains-ct-probe)';

if (!keyword) {
  console.error(`usage: node new-domains.mjs --watch <keyword> [--poll <seconds>] [--json]

  --watch <keyword>   substring to match in certificate domain names
                      (your brand, a product name, or a typosquat pattern)
  --poll  <seconds>   keep running; re-check on this interval and print only
                      domains not seen before (min recommended: 120)
  --json              machine-readable output

examples:
  node new-domains.mjs --watch mybrand
  node new-domains.mjs --watch mybrand --poll 300
  node new-domains.mjs --watch "secure-login" --json`);
  process.exit(1);
}

const C = JSON_OUT ? new Proxy({}, { get: () => '' }) : {
  grn: '\x1b[32m', yel: '\x1b[33m', cyn: '\x1b[36m', dim: '\x1b[2m', b: '\x1b[1m', x: '\x1b[0m',
};
const log = (...a) => { if (!JSON_OUT) console.log(...a); };

const sleep = (ms) => new Promise((res) => setTimeout(res, ms));

// Primary: crt.sh JSON API. %25 is a URL-encoded SQL wildcard (%), so "%kw%"
// matches the keyword ANYWHERE in the cert's domain names — good for loose
// keyword / typosquat hunting. crt.sh is free but flaky, so retry on 5xx/429.
async function fetchFromCrtSh(kw, attempts = 3) {
  const u = `https://crt.sh/?q=%25${encodeURIComponent(kw)}%25&output=json`;
  for (let i = 0; i < attempts; i++) {
    const r = await fetch(u, { headers: { 'User-Agent': UA } });
    if (r.ok) {
      const text = await r.text();
      if (!text.trim()) return [];
      // crt.sh fields → our normalizer's expected shape.
      return JSON.parse(text).map((row) => ({
        name_value: row.name_value,
        not_before: row.not_before,
        entry_timestamp: row.entry_timestamp,
        issuer_name: row.issuer_name,
      }));
    }
    if (![429, 500, 502, 503, 504].includes(r.status)) throw new Error(`crt.sh returned HTTP ${r.status}`);
    if (i < attempts - 1) await sleep(1500 * (i + 1)); // linear backoff: 1.5s, 3s
  }
  throw new Error('crt.sh unavailable after retries');
}

// Fallback: SSLMate CertSpotter free API. Searches a SPECIFIC domain (plus its
// subdomains), so it only applies when the keyword is itself a domain name.
async function fetchFromCertSpotter(domain) {
  const u = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}`
    + `&include_subdomains=true&expand=dns_names&expand=issuer`;
  const r = await fetch(u, { headers: { 'User-Agent': UA } });
  if (!r.ok) throw new Error(`CertSpotter returned HTTP ${r.status}`);
  const arr = await r.json();
  return arr.map((row) => ({
    name_value: (row.dns_names || []).join('\n'),
    not_before: row.not_before,
    entry_timestamp: row.not_before,
    issuer_name: row.issuer?.name || '',
  }));
}

const looksLikeDomain = (s) => /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(s);

// Try crt.sh first; on failure fall back to CertSpotter when the keyword is a
// domain. Returns rows plus which source actually answered.
async function fetchCerts(kw) {
  try {
    return { rows: await fetchFromCrtSh(kw), source: 'crt.sh' };
  } catch (e) {
    if (looksLikeDomain(kw)) {
      const rows = await fetchFromCertSpotter(kw);
      return { rows, source: 'certspotter (crt.sh down)' };
    }
    throw new Error(`${e.message}. (Tip: CertSpotter fallback only works when --watch is a full domain, e.g. mybrand.com)`);
  }
}

// Normalize crt.sh rows into one record per unique domain, keeping the
// earliest "not before" date we see for it (≈ when the cert/site appeared).
function normalize(rows) {
  const byDomain = new Map();
  for (const row of rows) {
    const names = String(row.name_value || '').split('\n');
    for (const raw of names) {
      const name = raw.trim().toLowerCase().replace(/^\*\./, ''); // drop wildcard prefix
      if (!name || name.includes(' ')) continue;
      const seen = row.not_before || row.entry_timestamp || '';
      const prev = byDomain.get(name);
      if (!prev || (seen && seen < prev.firstSeen)) {
        byDomain.set(name, { domain: name, firstSeen: seen, issuer: row.issuer_name || '' });
      }
    }
  }
  return [...byDomain.values()].sort((a, b) => (b.firstSeen || '').localeCompare(a.firstSeen || ''));
}

const seen = new Set();

async function runOnce(firstRun) {
  let rows, source;
  try {
    ({ rows, source } = await fetchCerts(keyword));
  } catch (e) {
    if (JSON_OUT) console.log(JSON.stringify({ error: String(e) }));
    else log(`${C.yel}warn: ${e.message}${pollSecs ? ' (will retry next poll)' : ''}${C.x}`);
    return;
  }

  const all = normalize(rows);
  const fresh = all.filter((d) => !seen.has(d.domain));
  for (const d of all) seen.add(d.domain);

  if (JSON_OUT) {
    console.log(JSON.stringify({ keyword, source, checkedAt: new Date().toISOString(), total: all.length, new: fresh }, null, 2));
    return;
  }

  if (firstRun) {
    log(`${C.dim}─${'─'.repeat(55)}${C.x}`);
    log(`${C.b}CT-log domain watch — keyword: "${keyword}"${C.x}`);
    log(`${C.dim}source: ${source} · ${new Date().toLocaleString()}${C.x}`);
    log(`${C.dim}─${'─'.repeat(55)}${C.x}`);
    log(`${C.b}${all.length}${C.x} known domain(s) matching. Newest first:\n`);
    for (const d of all.slice(0, 40)) {
      log(`  ${C.cyn}${d.domain}${C.x}  ${C.dim}${(d.firstSeen || '').slice(0, 10)}${C.x}`);
    }
    if (all.length > 40) log(`  ${C.dim}… and ${all.length - 40} more${C.x}`);
    if (pollSecs) log(`\n${C.dim}Polling every ${pollSecs}s — only NEW domains will print below.${C.x}`);
  } else if (fresh.length) {
    log(`\n${C.grn}${C.b}[${new Date().toLocaleTimeString()}] ${fresh.length} NEW domain(s):${C.x}`);
    for (const d of fresh) {
      log(`  ${C.grn}★ ${d.domain}${C.x}  ${C.dim}${(d.firstSeen || '').slice(0, 10)} · ${d.issuer.slice(0, 40)}${C.x}`);
    }
  }
}

(async () => {
  await runOnce(true);
  if (pollSecs >= 1) {
    const interval = Math.max(pollSecs, 120) * 1000; // floor at 120s to be polite to crt.sh
    setInterval(() => runOnce(false).catch(() => {}), interval);
  }
})();
