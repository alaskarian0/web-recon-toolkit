#!/usr/bin/env node
/**
 * czds-pull.mjs — find NEW domain registrations from ICANN CZDS zone files,
 * with RDAP (modern WHOIS) creation-date confirmation.
 *
 * How it works
 * ------------
 * ICANN's Centralized Zone Data Service (CZDS) gives approved users the daily
 * DNS zone file for each gTLD. A domain is "registered" when it appears as a
 * delegation (an NS record) in the zone. By snapshotting the set of delegated
 * domains and diffing today's pull against the last one, the domains that newly
 * appear are new registrations (and ones that vanish are expirations/deletions).
 *
 * This is the authoritative complement to CT-log discovery: it catches domains
 * the moment they are registered, before any TLS certificate exists.
 *
 * Setup (one time)
 * ----------------
 *   1. Create an account at https://czds.icann.org and request access to the
 *      TLDs you need (each is approved by the registry operator).
 *   2. Export your credentials as environment variables (never hardcode them):
 *        PowerShell:  $env:CZDS_USERNAME="you@example.com"; $env:CZDS_PASSWORD="…"
 *        bash:        export CZDS_USERNAME=you@example.com CZDS_PASSWORD=…
 *
 * Usage
 * -----
 *   node czds-pull.mjs --list                 # show the zones you're approved for
 *   node czds-pull.mjs                         # pull all approved zones, diff, list new regs
 *   node czds-pull.mjs --tld xyz,top           # only these zones
 *   node czds-pull.mjs --match shop            # only new domains containing a keyword
 *   node czds-pull.mjs --confirm               # RDAP-confirm creation dates of new domains
 *   node czds-pull.mjs --out new-regs.csv      # also write a CSV
 *   node czds-pull.mjs --json                  # machine-readable
 *   node czds-pull.mjs --whois example.com     # just an RDAP creation-date lookup, no CZDS
 *
 * First run on a zone only saves a baseline snapshot (there is nothing to diff
 * against yet) — run again on a later day to see new registrations.
 *
 * Needs: Node 18+ (built-in fetch). No npm install required.
 */

import { createGunzip } from 'node:zlib';
import { Readable } from 'node:stream';
import { createWriteStream, existsSync, mkdirSync, renameSync, createReadStream } from 'node:fs';
import { writeFileSync } from 'node:fs';
import readline from 'node:readline';
import path from 'node:path';

/* ---------------- args ---------------- */
const argv = process.argv.slice(2);
const flag = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
const has = (n) => argv.includes(n);

const JSON_OUT = has('--json');
const LIST_ONLY = has('--list');
const CONFIRM = has('--confirm');
const whoisTarget = flag('--whois');
const tldFilter = (flag('--tld') || '').split(',').map((t) => t.trim().toLowerCase().replace(/^\./, '')).filter(Boolean);
const match = (flag('--match') || '').toLowerCase();
const outFile = flag('--out');
const stateDir = flag('--state') || path.resolve('.czds-state');

const AUTH_URL = process.env.CZDS_AUTH_URL || 'https://account-api.icann.org/api/authenticate';
const API_BASE = process.env.CZDS_API_BASE || 'https://czds-api.icann.org';
const UA = 'Mozilla/5.0 (czds-pull)';

const RDAP_CONFIRM_LIMIT = 500;   // cap RDAP lookups per run to stay polite
const RDAP_CONCURRENCY = 4;

const C = JSON_OUT ? new Proxy({}, { get: () => '' }) : {
  grn: '\x1b[32m', yel: '\x1b[33m', red: '\x1b[31m', cyn: '\x1b[36m', dim: '\x1b[2m', b: '\x1b[1m', x: '\x1b[0m',
};
const log = (...a) => { if (!JSON_OUT) console.log(...a); };
const warn = (m) => { if (!JSON_OUT) console.error(`${C.yel}${m}${C.x}`); };
const die = (m) => { if (JSON_OUT) console.log(JSON.stringify({ error: m })); else console.error(`${C.red}error: ${m}${C.x}`); process.exit(2); };

/* ---------------- RDAP (modern WHOIS) ---------------- */
// rdap.org bootstraps to the authoritative RDAP server for the TLD and returns
// structured JSON. We pull the "registration" event date.
async function rdapCreated(domain) {
  try {
    const r = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { headers: { 'User-Agent': UA, Accept: 'application/rdap+json' }, redirect: 'follow' });
    if (!r.ok) return { domain, created: null, status: r.status };
    const j = await r.json();
    const ev = (j.events || []).find((e) => e.eventAction === 'registration');
    const exp = (j.events || []).find((e) => e.eventAction === 'expiration');
    return { domain, created: ev?.eventDate || null, expires: exp?.eventDate || null, registrar: (j.entities || []).find((e) => (e.roles || []).includes('registrar'))?.vcardArray?.[1]?.find((f) => f[0] === 'fn')?.[3] || null };
  } catch (e) { return { domain, created: null, error: String(e) }; }
}

// Confirm a batch of domains with bounded concurrency.
async function rdapBatch(domains) {
  const out = [];
  let idx = 0;
  const worker = async () => {
    while (idx < domains.length) {
      const d = domains[idx++];
      out.push(await rdapCreated(d));
    }
  };
  await Promise.all(Array.from({ length: Math.min(RDAP_CONCURRENCY, domains.length) }, worker));
  return out;
}

/* ---------------- CZDS auth + links ---------------- */
async function authenticate(username, password) {
  const r = await fetch(AUTH_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'User-Agent': UA },
    body: JSON.stringify({ username, password }),
  });
  if (r.status === 401) throw new Error('CZDS authentication failed (401) — check CZDS_USERNAME / CZDS_PASSWORD');
  if (!r.ok) throw new Error(`CZDS auth HTTP ${r.status}`);
  const j = await r.json();
  if (!j.accessToken) throw new Error('CZDS auth returned no accessToken');
  return j.accessToken;
}

async function listLinks(token) {
  const r = await fetch(`${API_BASE}/czds/downloads/links`, { headers: { Authorization: `Bearer ${token}`, 'User-Agent': UA } });
  if (!r.ok) throw new Error(`CZDS links HTTP ${r.status}`);
  const links = await r.json();
  return links.map((url) => ({ url, tld: path.basename(new URL(url).pathname).replace(/\.zone$/i, '').toLowerCase() }));
}

/* ---------------- zone download + diff ---------------- */
// Owner name of an NS delegation = a registered domain. CZDS gTLD zones are
// machine-generated with an explicit owner on each line, sorted by owner.
const NS_LINE = /^(\S+?)\.?\s+(?:\d+\s+)?in\s+ns\s/i;

function loadSnapshot(file) {
  return new Promise((resolve) => {
    const set = new Set();
    if (!existsSync(file)) return resolve(null); // no baseline yet
    const rl = readline.createInterface({ input: createReadStream(file), crlfDelay: Infinity });
    rl.on('line', (l) => { if (l) set.add(l); });
    rl.on('close', () => resolve(set));
  });
}

async function processZone(link, token) {
  if (!existsSync(stateDir)) mkdirSync(stateDir, { recursive: true });
  const snapFile = path.join(stateDir, `${link.tld}.snapshot`);
  const tmpFile = `${snapFile}.tmp`;

  const prev = await loadSnapshot(snapFile);      // Set or null (first run)
  const writeStream = createWriteStream(tmpFile);
  const newDomains = [];
  let lastOwner = '';
  let total = 0;

  const res = await fetch(link.url, { headers: { Authorization: `Bearer ${token}`, 'User-Agent': UA } });
  if (!res.ok) throw new Error(`download ${link.tld} HTTP ${res.status}`);

  const gunzip = createGunzip();
  Readable.fromWeb(res.body).pipe(gunzip);
  const rl = readline.createInterface({ input: gunzip, crlfDelay: Infinity });

  for await (const line of rl) {
    if (!line || line[0] === ';' || line[0] === '$') continue;
    const m = NS_LINE.exec(line);
    if (!m) continue;
    const owner = m[1].toLowerCase();
    if (owner === lastOwner || owner === link.tld) continue; // dedupe adjacent NS lines + skip apex
    lastOwner = owner;
    total++;
    writeStream.write(owner + '\n');
    if (prev) {
      if (prev.has(owner)) prev.delete(owner);
      else newDomains.push(owner);
    }
  }
  await new Promise((r) => writeStream.end(r));
  renameSync(tmpFile, snapFile); // commit new baseline

  return {
    tld: link.tld,
    total,
    baseline: prev === null,
    newDomains,
    droppedCount: prev ? prev.size : 0,
  };
}

/* ---------------- main ---------------- */
(async () => {
  // Standalone WHOIS/RDAP mode — no CZDS credentials needed.
  if (whoisTarget) {
    const info = await rdapCreated(whoisTarget.toLowerCase().replace(/^\*\./, ''));
    if (JSON_OUT) return void console.log(JSON.stringify(info, null, 2));
    log(`${C.b}RDAP lookup — ${info.domain}${C.x}`);
    log(`  created  : ${info.created ? C.grn + info.created + C.x : C.yel + '(not available' + (info.status ? ', HTTP ' + info.status : '') + ')' + C.x}`);
    if (info.expires) log(`  expires  : ${info.expires}`);
    if (info.registrar) log(`  registrar: ${info.registrar}`);
    return;
  }

  const username = process.env.CZDS_USERNAME;
  const password = process.env.CZDS_PASSWORD;
  if (!username || !password) die('set CZDS_USERNAME and CZDS_PASSWORD environment variables (see header of this file). For a quick WHOIS lookup without CZDS, use --whois <domain>.');

  let token, links;
  try {
    token = await authenticate(username, password);
    links = await listLinks(token);
  } catch (e) { die(e.message); }

  if (tldFilter.length) links = links.filter((l) => tldFilter.includes(l.tld));

  if (LIST_ONLY) {
    if (JSON_OUT) return void console.log(JSON.stringify({ approvedZones: links.map((l) => l.tld) }, null, 2));
    log(`${C.b}Approved zones (${links.length}):${C.x}`);
    for (const l of links) log(`  ${C.cyn}${l.tld}${C.x}`);
    return;
  }

  if (!links.length) die(tldFilter.length ? 'none of the requested TLDs are in your approved list (try --list)' : 'no approved zones found (request access at czds.icann.org, then --list)');

  const report = [];
  for (const link of links) {
    warn(`• pulling .${link.tld} …`);
    try {
      const res = await processZone(link, token);
      report.push(res);
    } catch (e) {
      warn(`  failed .${link.tld}: ${e.message}`);
      report.push({ tld: link.tld, error: e.message });
    }
  }

  // Collect + filter new domains across all zones.
  let allNew = [];
  for (const r of report) {
    if (!r.newDomains) continue;
    for (const d of r.newDomains) {
      if (match && !d.includes(match)) continue;
      allNew.push(d);
    }
  }
  allNew.sort();

  // Optional RDAP confirmation of creation dates.
  let confirmed = null;
  if (CONFIRM && allNew.length) {
    const batch = allNew.slice(0, RDAP_CONFIRM_LIMIT);
    if (allNew.length > RDAP_CONFIRM_LIMIT) warn(`  confirming first ${RDAP_CONFIRM_LIMIT} of ${allNew.length} via RDAP`);
    confirmed = await rdapBatch(batch);
  }

  if (outFile) {
    const rows = confirmed
      ? ['domain,created,expires,registrar', ...confirmed.map((c) => `${c.domain},${c.created || ''},${c.expires || ''},${(c.registrar || '').replace(/,/g, ' ')}`)]
      : ['domain', ...allNew];
    writeFileSync(outFile, rows.join('\n'));
  }

  if (JSON_OUT) {
    return void console.log(JSON.stringify({
      zones: report.map((r) => ({ tld: r.tld, total: r.total ?? null, baseline: r.baseline ?? null, newCount: r.newDomains?.length ?? null, dropped: r.droppedCount ?? null, error: r.error })),
      match: match || null,
      newRegistrations: confirmed || allNew,
    }, null, 2));
  }

  log(`${C.dim}${'─'.repeat(60)}${C.x}`);
  log(`${C.b}CZDS new-registration pull${C.x}  ${C.dim}${new Date().toLocaleString()}${C.x}`);
  log(`${C.dim}${'─'.repeat(60)}${C.x}`);
  for (const r of report) {
    if (r.error) { log(`  .${r.tld.padEnd(10)} ${C.red}error: ${r.error}${C.x}`); continue; }
    if (r.baseline) { log(`  .${r.tld.padEnd(10)} ${C.yel}baseline saved${C.x} ${C.dim}(${r.total} domains) — run again later to see new regs${C.x}`); continue; }
    log(`  .${r.tld.padEnd(10)} ${C.grn}+${r.newDomains.length} new${C.x}, ${C.dim}-${r.droppedCount} dropped, ${r.total} total${C.x}`);
  }

  const shown = match ? ` matching "${match}"` : '';
  log(`\n${C.b}${allNew.length}${C.x} new registration(s)${shown}:`);
  if (confirmed) {
    for (const c of confirmed) log(`  ${C.cyn}${c.domain.padEnd(34)}${C.x} ${C.dim}${c.created ? 'created ' + c.created.slice(0, 10) : 'created ?'}${C.x}`);
  } else {
    for (const d of allNew.slice(0, 200)) log(`  ${C.cyn}${d}${C.x}`);
    if (allNew.length > 200) log(`  ${C.dim}… and ${allNew.length - 200} more (use --out to capture all)${C.x}`);
  }
  if (outFile) log(`\n${C.grn}written → ${outFile}${C.x}`);
  log(`${C.dim}${'─'.repeat(60)}${C.x}`);
})();
