#!/usr/bin/env bash
# nextjs-version.sh — best-effort Next.js fingerprint + version detection for a live site.
#
# Next.js does NOT publish its version in headers, so an exact number can rarely be
# proven from outside. This script gathers every external signal and gives a best
# guess (often the exact MAJOR, sometimes the full version via source maps).
#
# Usage:  ./nextjs-version.sh https://example.com
# Needs:  curl, grep, sed  (sha256sum/shasum optional, node optional for richer parse)

set -uo pipefail
URL="${1:-}"
if [ -z "$URL" ]; then echo "usage: $0 <https://site>"; exit 1; fi
URL="${URL%/}"
UA="Mozilla/5.0 (nextjs-version-probe)"
say() { printf '%s\n' "$*"; }
hr()  { printf '%s\n' "----------------------------------------"; }

# ---------- 1. Headers ----------
HEAD="$(curl -sSIL -A "$UA" "$URL/" 2>/dev/null)"
hr; say "TARGET: $URL"; hr
POWERED="$(printf '%s' "$HEAD" | grep -i '^x-powered-by:' | tr -d '\r' | sed 's/.*: //')"
SERVER="$(printf '%s' "$HEAD"  | grep -i '^server:'       | tr -d '\r' | sed 's/.*: //' | head -1)"
VARY="$(printf '%s' "$HEAD"    | grep -i '^vary:'         | tr -d '\r')"
say "Server header   : ${SERVER:-(none)}"
say "X-Powered-By    : ${POWERED:-(none)}"

IS_NEXT=0
printf '%s' "$POWERED" | grep -qi 'next' && IS_NEXT=1
printf '%s' "$HEAD"    | grep -qi '/_next/' && IS_NEXT=1
printf '%s' "$VARY"    | grep -qi 'rsc\|next-router' && IS_NEXT=1

# ---------- 2. HTML ----------
HTML="$(curl -sSL -A "$UA" "$URL/" 2>/dev/null)"
printf '%s' "$HTML" | grep -qi '/_next/' && IS_NEXT=1
HAS_NEXT_DATA=0; printf '%s' "$HTML" | grep -q '__NEXT_DATA__' && HAS_NEXT_DATA=1

if [ "$IS_NEXT" -eq 0 ]; then
  hr; say "RESULT: This site does NOT appear to be Next.js."; hr; exit 0
fi

# ---------- 3. Router type + major-version hints ----------
ROUTER="App Router (RSC)"
[ "$HAS_NEXT_DATA" -eq 1 ] && ROUTER="Pages Router"
say "Router          : $ROUTER"

MAJOR_HINT="13+ (App Router)"
if printf '%s' "$HEAD$VARY" | grep -qi 'next-router-segment-prefetch'; then
  MAJOR_HINT="15+ (segment-prefetch header present)"
elif printf '%s' "$HEAD$VARY" | grep -qi 'next-router-prefetch'; then
  MAJOR_HINT="13/14 (router prefetch, no segment-prefetch)"
fi
[ "$HAS_NEXT_DATA" -eq 1 ] && MAJOR_HINT="12/13 (Pages Router / __NEXT_DATA__)"
say "Version hint    : Next.js $MAJOR_HINT"

# ---------- 4. Collect /_next/static chunk URLs ----------
mapfile -t CHUNKS < <(
  { printf '%s' "$HTML" | grep -oE '/_next/static/[^"'"'"' ]+\.js';
    printf '%s' "$HEAD" | grep -oiE '/_next/static/[^">]+\.js'; } \
  | sed 's/\\u002F/\//g' | sort -u
)
say "Chunks found    : ${#CHUNKS[@]}"

# ---------- 5. Bundled React version (strong Next-major signal) ----------
REACT_VER=""
for c in "${CHUNKS[@]}"; do
  case "$c" in *framework*|*main-*|*main-app*|*react*) ;; *) continue;; esac
  BODY="$(curl -sSL -A "$UA" "$URL$c" 2>/dev/null)"
  v="$(printf '%s' "$BODY" | grep -oE 'react-dom[^0-9]{0,8}[0-9]+\.[0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
  [ -z "$v" ] && v="$(printf '%s' "$BODY" | grep -oE '"(1[789]|2[0-9])\.[0-9]+\.[0-9]+"' | tr -d '"' | head -1)"
  if [ -n "$v" ]; then REACT_VER="$v"; break; fi
done
say "Bundled React   : ${REACT_VER:-(not found)}"

NEXT_FROM_REACT=""
case "$REACT_VER" in
  19.*) NEXT_FROM_REACT="15.x or 16.x (ships React 19)";;
  18.*) NEXT_FROM_REACT="13.x or 14.x (ships React 18)";;
  17.*) NEXT_FROM_REACT="12.x (ships React 17)";;
esac
[ -n "$NEXT_FROM_REACT" ] && say "→ implies Next   : $NEXT_FROM_REACT"

# ---------- 6. Source maps (can reveal the EXACT version) ----------
EXACT=""
for c in "${CHUNKS[@]}"; do
  MAP="$(curl -sSL -A "$UA" "$URL$c.map" 2>/dev/null)"
  printf '%s' "$MAP" | grep -q 'next/dist' || continue
  e="$(printf '%s' "$MAP" | grep -oE 'next[/@][^"]*[0-9]+\.[0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
  if [ -n "$e" ]; then EXACT="$e"; say "Source map leak : $c.map  (exposes next/dist paths)"; break; fi
done

# ---------- 7. Chunk hash (for comparison against a hash DB) ----------
HASHER=""; command -v sha256sum >/dev/null && HASHER=sha256sum
[ -z "$HASHER" ] && command -v shasum >/dev/null && HASHER="shasum -a 256"
if [ -n "$HASHER" ]; then
  for c in "${CHUNKS[@]}"; do
    case "$c" in *framework*|*main-app*|*webpack*) ;; *) continue;; esac
    h="$(curl -sSL -A "$UA" "$URL$c" 2>/dev/null | $HASHER | cut -d' ' -f1)"
    say "sha256 $c : $h"
  done
fi

# ---------- 8. Verdict ----------
hr
if [ -n "$EXACT" ]; then
  say "VERSION (exact, from source map): Next.js $EXACT"
else
  say "VERSION (best effort): Next.js $MAJOR_HINT"
  [ -n "$NEXT_FROM_REACT" ] && say "  cross-check via React: $NEXT_FROM_REACT"
  say "  Exact patch not externally exposed (expected). To confirm precisely:"
  say "   - repo:   grep '\"next\"' package.json  /  cat package-lock.json | grep -A2 '\"next\"'"
  say "   - server: npx next --version   (in the app dir)"
fi
hr
