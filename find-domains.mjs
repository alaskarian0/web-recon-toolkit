#!/usr/bin/env node
/**
 * find-domains.mjs — given a name/keyword, discover every registered domain
 * that contains it.
 *
 * Source: public Certificate Transparency (CT) logs via crt.sh, with an
 * SSLMate CertSpotter fallback. Almost every live domain has issued a TLS
 * certificate, and those certs are logged publicly — so searching CT is a
 * practical way to enumerate real, existing domains matching a keyword.
 * (This is OSINT on public records: brand monitoring, typosquat / phishing
 * discovery, attack-surface recon.)
 *
 * It collapses the many subdomain certs down to unique REGISTRABLE domains
 * (eTLD+1), so "a.tesla.com" and "b.tesla.com" both become "tesla.com".
 *
 * Usage:
 *   node find-domains.mjs tesla
 *   node find-domains.mjs tesla --in-name          # keyword must be in the base domain
 *   node find-domains.mjs tesla --tld com,io,ai    # only these TLDs
 *   node find-domains.mjs tesla --out results.csv  # also write a CSV
 *   node find-domains.mjs tesla --json             # machine-readable
 *
 * Needs: Node 18+ (built-in fetch). No npm install required.
 */

import { writeFileSync } from 'node:fs';

const argv = process.argv.slice(2);
const flag = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};
const has = (name) => argv.includes(name);

// first positional arg that isn't a flag or the value of --tld/--out
const positional = (() => {
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) { if (['--tld', '--out'].includes(a)) i++; continue; }
    return a;
  }
})();
const kw = positional;

const JSON_OUT = has('--json');
const IN_NAME = has('--in-name');
const tldFilter = (flag('--tld') || '').split(',').map((t) => t.trim().toLowerCase().replace(/^\./, '')).filter(Boolean);
const outFile = flag('--out');
const UA = 'Mozilla/5.0 (find-domains-ct)';

if (!kw) {
  console.error(`usage: node find-domains.mjs <keyword> [options]

  <keyword>        name/word to search for in domain names
  --in-name        only keep domains where the keyword is in the registrable
                   name itself (e.g. my-tesla.com), not just a subdomain
  --tld a,b,c      restrict to these top-level domains (e.g. com,io,ai)
  --out <file>     also write results to a CSV file
  --json           machine-readable JSON output

examples:
  node find-domains.mjs tesla
  node find-domains.mjs tesla --in-name --tld com,net,io
  node find-domains.mjs "paypal-login" --out squats.csv`);
  process.exit(1);
}

const C = JSON_OUT ? new Proxy({}, { get: () => '' }) : {
  grn: '\x1b[32m', yel: '\x1b[33m', cyn: '\x1b[36m', dim: '\x1b[2m', b: '\x1b[1m', x: '\x1b[0m',
};
const log = (...a) => { if (!JSON_OUT) console.log(...a); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ---------- data sources ---------- */

async function fromCrtSh(q, attempts = 3) {
  const u = `https://crt.sh/?q=%25${encodeURIComponent(q)}%25&output=json`;
  for (let i = 0; i < attempts; i++) {
    const r = await fetch(u, { headers: { 'User-Agent': UA } });
    if (r.ok) {
      const t = await r.text();
      if (!t.trim()) return [];
      return JSON.parse(t).map((row) => ({ names: String(row.name_value || ''), seen: row.not_before || '' }));
    }
    if (![429, 500, 502, 503, 504].includes(r.status)) throw new Error(`crt.sh HTTP ${r.status}`);
    if (i < attempts - 1) await sleep(1500 * (i + 1));
  }
  throw new Error('crt.sh unavailable after retries');
}

async function fromCertSpotter(domain) {
  const u = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}`
    + `&include_subdomains=true&expand=dns_names`;
  const r = await fetch(u, { headers: { 'User-Agent': UA } });
  if (!r.ok) throw new Error(`CertSpotter HTTP ${r.status}`);
  return (await r.json()).map((row) => ({ names: (row.dns_names || []).join('\n'), seen: row.not_before || '' }));
}

const looksLikeDomain = (s) => /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(s);

async function gather(q) {
  try {
    return { rows: await fromCrtSh(q), source: 'crt.sh' };
  } catch (e) {
    if (looksLikeDomain(q)) return { rows: await fromCertSpotter(q), source: 'certspotter (crt.sh down)' };
    throw new Error(`${e.message} — CertSpotter fallback needs a full domain as the keyword (e.g. mybrand.com)`);
  }
}

/* ---------- registrable-domain (eTLD+1) extraction ---------- */
// Compact multi-label public-suffix set covers the common country combos so we
// collapse to the right base domain. Not exhaustive like the full PSL, but
// handles the vast majority of real-world cases.
const MULTI_SUFFIX = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'ltd.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'net.nz', 'org.nz',
  'co.za', 'org.za',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'co.in', 'net.in', 'org.in', 'gov.in',
  'co.jp', 'or.jp', 'ne.jp', 'go.jp',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'com.mx', 'com.tr', 'com.sg', 'com.hk', 'com.tw', 'com.ar', 'com.sa', 'com.eg',
  'co.id', 'co.kr', 'co.il', 'com.ua', 'com.pk', 'com.ng',
]);

function registrable(host) {
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  const last2 = parts.slice(-2).join('.');
  const last3 = parts.slice(-3).join('.');
  if (MULTI_SUFFIX.has(last2)) return last3;
  return last2;
}

const tldOf = (domain) => domain.split('.').pop();

/* ---------- run ---------- */

(async () => {
  let rows, source;
  try {
    ({ rows, source } = await gather(kw));
  } catch (e) {
    if (JSON_OUT) console.log(JSON.stringify({ error: String(e) }));
    else console.error(`${C.yel}error: ${e.message}${C.x}`);
    process.exit(2);
  }

  const kwl = kw.toLowerCase();
  const map = new Map(); // base domain -> { domain, tld, subdomains:Set, firstSeen, lastSeen }

  for (const { names, seen } of rows) {
    for (const raw of names.split('\n')) {
      const host = raw.trim().toLowerCase().replace(/^\*\./, '');
      if (!host || host.includes(' ') || !host.includes('.')) continue;
      if (!host.includes(kwl)) continue;
      const base = registrable(host);
      if (IN_NAME && !base.toLowerCase().includes(kwl)) continue; // keyword must be in the base name
      if (tldFilter.length && !tldFilter.includes(tldOf(base))) continue;

      let rec = map.get(base);
      if (!rec) { rec = { domain: base, tld: tldOf(base), subdomains: new Set(), firstSeen: seen, lastSeen: seen }; map.set(base, rec); }
      if (host !== base) rec.subdomains.add(host);
      if (seen && (!rec.firstSeen || seen < rec.firstSeen)) rec.firstSeen = seen;
      if (seen && seen > rec.lastSeen) rec.lastSeen = seen;
    }
  }

  const results = [...map.values()]
    .map((r) => ({ domain: r.domain, tld: r.tld, subdomains: r.subdomains.size, firstSeen: (r.firstSeen || '').slice(0, 10), lastSeen: (r.lastSeen || '').slice(0, 10) }))
    .sort((a, b) => a.domain.localeCompare(b.domain));

  if (outFile) {
    const csv = ['domain,tld,subdomains,first_seen,last_seen',
      ...results.map((r) => `${r.domain},${r.tld},${r.subdomains},${r.firstSeen},${r.lastSeen}`)].join('\n');
    writeFileSync(outFile, csv);
  }

  if (JSON_OUT) {
    console.log(JSON.stringify({ keyword: kw, source, count: results.length, inNameOnly: IN_NAME, tldFilter, results }, null, 2));
    return;
  }

  log(`${C.dim}${'─'.repeat(60)}${C.x}`);
  log(`${C.b}Domain discovery — keyword: "${kw}"${C.x}`);
  log(`${C.dim}source: ${source}${IN_NAME ? ' · base-name matches only' : ''}${tldFilter.length ? ' · TLDs: ' + tldFilter.join(',') : ''}${C.x}`);
  log(`${C.dim}${'─'.repeat(60)}${C.x}`);
  log(`${C.b}${results.length}${C.x} unique registrable domain(s) found:\n`);
  for (const r of results) {
    const subs = r.subdomains ? `${C.dim} (+${r.subdomains} sub)${C.x}` : '';
    log(`  ${C.cyn}${r.domain.padEnd(34)}${C.x}${subs}  ${C.dim}${r.firstSeen}${C.x}`);
  }
  if (outFile) log(`\n${C.grn}CSV written → ${outFile}${C.x}`);
  log(`${C.dim}${'─'.repeat(60)}${C.x}`);
})();
