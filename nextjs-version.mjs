#!/usr/bin/env node
/**
 * nextjs-version.mjs — powerful, exact Next.js version detector + vulnerability check.
 *
 * Detects the EXACT Next.js version of a live site from the client bundle, then
 * enriches it online:
 *   • npm registry  → latest version, release date, how far behind
 *   • OSV.dev       → known CVEs affecting that EXACT version (+ the fixed version)
 *
 * Usage:   node nextjs-version.mjs https://example.com [--json]
 * Needs:   Node 18+ (uses built-in fetch). No npm install required.
 */

const UA = 'Mozilla/5.0 (nextjs-version-probe)';
const args = process.argv.slice(2);
const JSON_OUT = args.includes('--json');
let url = args.find((a) => !a.startsWith('--'));
if (!url) { console.error('usage: node nextjs-version.mjs <https://site> [--json]'); process.exit(1); }
if (!/^https?:\/\//.test(url)) url = 'https://' + url;
url = url.replace(/\/+$/, '');

const C = JSON_OUT ? new Proxy({}, { get: () => '' }) : {
  red: '\x1b[31m', grn: '\x1b[32m', yel: '\x1b[33m', cyn: '\x1b[36m', dim: '\x1b[2m', b: '\x1b[1m', x: '\x1b[0m',
};
const log = (...a) => { if (!JSON_OUT) console.log(...a); };
const hr = () => log(C.dim + '─'.repeat(56) + C.x);

async function get(u, { head = false } = {}) {
  try {
    const r = await fetch(u, { method: head ? 'HEAD' : 'GET', headers: { 'User-Agent': UA }, redirect: 'follow' });
    const headers = Object.fromEntries(r.headers.entries());
    const text = head ? '' : await r.text();
    return { ok: r.ok, status: r.status, headers, text };
  } catch (e) { return { ok: false, status: 0, headers: {}, text: '', error: String(e) }; }
}

const SEMVER = '\\d+\\.\\d+\\.\\d+(?:-[\\w.]+)?';

// Pull every detection signal out of one chunk's body. Returns {next, react, map}.
function scanBody(body) {
  const out = {};
  // 1) Gold signal: Next inlines window.next = { version:"x" } in the client runtime.
  let m = body.match(new RegExp('window\\.next\\s*=\\s*\\{[^}]*?version:\\s*"(' + SEMVER + ')"'));
  if (m) out.next = { version: m[1], method: 'window.next.version (exact)' };
  // 2) version:"x",appDir:  (same object, different minifier order)
  if (!out.next) { m = body.match(new RegExp('version:"(' + SEMVER + ')",appDir')); if (m) out.next = { version: m[1], method: 'version+appDir (exact)' }; }
  // 3) __NEXT_VERSION constant (DefinePlugin inlines the literal)
  if (!out.next) { m = body.match(new RegExp('__NEXT_VERSION["\\s:=]{1,4}"?(' + SEMVER + ')')); if (m) out.next = { version: m[1], method: '__NEXT_VERSION (exact)' }; }
  // React (react-dom exposes its version). Direct markers first, then a semver
  // that appears in a chunk carrying a React fingerprint (minified builds).
  m = body.match(new RegExp('react-dom[^0-9]{0,12}(' + SEMVER + ')')) || body.match(new RegExp('reactVersion["\\s:=]{1,4}"?(' + SEMVER + ')'));
  if (!m && /SECRET_INTERNALS|Scheduler|react\.dev|hydrateRoot|createRoot/.test(body)) {
    m = body.match(new RegExp('version["\\s:=]{1,3}"?(1[789]\\.\\d+\\.\\d+|2[0-9]\\.\\d+\\.\\d+)'));
  }
  if (m) out.react = m[1];
  return out;
}

async function npmInfo(version) {
  const r = await get('https://registry.npmjs.org/next');
  if (!r.ok) return null;
  let j; try { j = JSON.parse(r.text); } catch { return null; }
  const latest = j['dist-tags']?.latest;
  const stable = Object.keys(j.versions || {}).filter((v) => !/-/.test(v));
  const cmp = (a, b) => a.split('.').map(Number).reduce((acc, n, i) => acc || n - b.split('.').map(Number)[i], 0);
  stable.sort(cmp);
  const idx = version ? stable.indexOf(version) : -1;
  return {
    latest,
    releasedAt: version ? j.time?.[version] : undefined,
    latestReleasedAt: latest ? j.time?.[latest] : undefined,
    behind: idx >= 0 ? stable.length - 1 - idx : undefined,
    newerExamples: idx >= 0 ? stable.slice(idx + 1).slice(-3) : [],
  };
}

async function osvVulns(version) {
  if (!version) return null;
  try {
    const r = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package: { ecosystem: 'npm', name: 'next' }, version }),
    });
    if (!r.ok) return null;
    const j = await r.json();
    return (j.vulns || []).map((v) => {
      let fixed;
      for (const a of v.affected || []) for (const rg of a.ranges || []) for (const ev of rg.events || []) if (ev.fixed) fixed = ev.fixed;
      const sev = (v.severity?.[0]?.score) || (v.database_specific?.severity) || '';
      return { id: v.aliases?.find((x) => x.startsWith('CVE')) || v.id, summary: v.summary || '', fixed, severity: sev };
    });
  } catch { return null; }
}

(async () => {
  const root = await get(url + '/');
  const powered = root.headers['x-powered-by'] || '';
  const vary = root.headers['vary'] || '';
  const isNext = /next/i.test(powered) || /_next\//.test(root.text) || /rsc|next-router/i.test(vary);

  // Collect chunk URLs from HTML + Link header.
  const chunkSet = new Set();
  for (const src of [root.text, root.headers['link'] || '']) {
    for (const mm of src.matchAll(/\/_next\/static\/[^\s"'<>]+?\.js/g)) chunkSet.add(mm[0].replace(/\\u002F/g, '/'));
  }
  const chunks = [...chunkSet];

  // Scan chunks in parallel (cap concurrency).
  let found = {};
  const queue = [...chunks];
  const worker = async () => {
    while (queue.length && !found.next) {
      const c = queue.shift();
      const b = await get(url + c);
      if (!b.ok) continue;
      const s = scanBody(b.text);
      if (s.next && !found.next) found.next = s.next;
      if (s.react && !found.react) found.react = s.react;
    }
  };
  await Promise.all(Array.from({ length: Math.min(6, chunks.length) }, worker));
  // make sure react is scanned even if next was found early
  if (!found.react) { for (const c of chunks) { const b = await get(url + c); const s = scanBody(b.text); if (s.react) { found.react = s.react; break; } } }

  // Source-map fallback for exact version.
  if (!found.next) {
    for (const c of chunks) {
      const mp = await get(url + c + '.map');
      if (mp.ok && /next\/dist/.test(mp.text)) {
        const m = mp.text.match(new RegExp('next[@/][^"]*?(' + SEMVER + ')'));
        if (m) { found.next = { version: m[1], method: 'source map (exact)' }; break; }
      }
    }
  }

  // Header-based major hint when exact failed.
  let majorHint;
  if (!found.next) {
    if (/next-router-segment-prefetch/i.test(vary)) majorHint = '15+ (segment-prefetch header)';
    else if (/next-router-prefetch/i.test(vary)) majorHint = '13/14 (App Router)';
    else if (/__NEXT_DATA__/.test(root.text)) majorHint = '12/13 (Pages Router)';
    else if (isNext) majorHint = 'unknown (Next.js confirmed)';
  }

  const version = found.next?.version;
  const [npm, vulns] = await Promise.all([npmInfo(version), osvVulns(version)]);

  if (JSON_OUT) {
    console.log(JSON.stringify({ url, isNext, version: version || null, detection: found.next?.method || null, react: found.react || null, majorHint: majorHint || null, npm, vulns }, null, 2));
    return;
  }

  hr(); log(`${C.b}Next.js fingerprint — ${url}${C.x}`); hr();
  log(`Is Next.js      : ${isNext ? C.grn + 'yes' + C.x : C.red + 'no' + C.x}`);
  if (!isNext) { hr(); return; }
  log(`Server          : ${root.headers['server'] || '(none)'}`);
  log(`X-Powered-By    : ${powered || '(hidden)'}`);
  log(`Chunks scanned  : ${chunks.length}`);
  log(`Bundled React   : ${found.react || '(not found)'}`);
  if (version) {
    log(`${C.b}${C.grn}EXACT Next.js   : ${version}${C.x}  ${C.dim}(${found.next.method})${C.x}`);
  } else {
    log(`${C.yel}Next.js version : ${majorHint || 'unknown'} (exact not externally exposed)${C.x}`);
  }

  if (npm) {
    hr(); log(`${C.b}npm registry${C.x}`);
    log(`Latest stable   : ${npm.latest}${npm.latestReleasedAt ? C.dim + '  (' + npm.latestReleasedAt.slice(0, 10) + ')' + C.x : ''}`);
    if (npm.releasedAt) log(`Detected release: ${npm.releasedAt.slice(0, 10)}`);
    if (npm.behind != null) log(`Releases behind : ${npm.behind === 0 ? C.grn + '0 (up to date)' + C.x : C.yel + npm.behind + C.x}${npm.newerExamples.length ? C.dim + '  e.g. ' + npm.newerExamples.join(', ') + C.x : ''}`);
  }

  if (version) {
    hr(); log(`${C.b}Known vulnerabilities (OSV.dev) for ${version}${C.x}`);
    if (vulns == null) log(`${C.dim}(could not reach OSV.dev)${C.x}`);
    else if (vulns.length === 0) log(`${C.grn}None recorded for this exact version.${C.x}`);
    else for (const v of vulns) log(`${C.red}• ${v.id}${C.x}${v.severity ? ' [' + v.severity + ']' : ''} — ${v.summary || '(no summary)'}${v.fixed ? C.dim + '  → fixed in ' + v.fixed + C.x : ''}`);
  }
  hr();
})();
