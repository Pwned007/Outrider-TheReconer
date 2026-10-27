#!/usr/bin/env bash
#
# outrider.sh - Outrider: external attack-surface recon with PORT DISCOVERY + BLOCK-AWARE scanning.
#   v2 adds: (a) a port-discovery phase (CDN-aware, nmap evasion fallback) that finds
#   web services on non-standard ports and feeds them into the pipeline, and (b) a
#   throttled, batched, block-aware nuclei stage with a baseline oracle + back-off.
#
# PHASES
#   1. passive subdomains   crt.sh + subfinder (+ optional dnsdumpster API)
#   2. wayback collection   waybackurls / gau / CDX API
#   3. wayback triage       uro dedup -> param buckets -> juicy-file + JS harvest
#   4. github secrets       trufflehog verified-only (needs GITHUB_TOKEN)
#   5. scope filter         GATE: only in-scope hosts are actively probed
#   6. live + fingerprint   httpx (status/title/server/tech/favicon) on 80/443
#   6b. PORT DISCOVERY      resolve -> unique IPs -> skip CDN -> naabu (or nmap w/ evasion
#                           if filtered) -> httpx the new web ports -> merge into live set
#   7. live juicy/JS check + JS endpoint/secret analysis (in-scope only)
#   8. CVE                  BLOCK-AWARE nuclei: baseline oracle, throttled, batched, back-off
#   9. ANALYSIS             score + prioritize findings -> report call-outs
#
# USAGE
#   ./outrider.sh example.com [-o out] [--scope f] [--no-github] [--no-nuclei] [--nuclei-full]
#                [--no-ports] [--ports <csv|topN|web>] [--evasion] [--stealth] [--nuclei-batch N]
#                [--nuclei-full] [--no-cvemap] [--no-nmap-vuln]
#     --no-ports      skip port discovery (just 80/443)
#     --ports SPEC    'web' (curated web ports, default), 'topN' (e.g. top1000), or a CSV list
#     --evasion       if naabu finds nothing (firewall filtering), retry with nmap evasive flags
#     --stealth       very low rate + larger back-off for nuclei (quietest; slowest)
#     --nuclei-batch  hosts per nuclei batch between block-checks (default 40)
#     --nuclei-full   broad template set instead of tech-aware automatic-scan
#     --no-cvemap     skip the version->CVE (NVD) lookup phase
#     --no-nmap-vuln  skip the automatic nmap NSE vuln checks on non-web ports
#     --no-wpscan     don't auto-run wpscan on detected WordPress sites (just flag them)
#
# SCOPE SAFETY  only inscope.txt is actively probed. default in-scope = *.<target>.
#               CDN IPs are not port-scanned. confirm authorization before running.
#
# REQUIRES curl, jq.  RECOMMENDED subfinder, httpx, nuclei, naabu, dnsx, nmap,
#          waybackurls/gau, uro, trufflehog.  Runs on Linux / WSL / Kali.

set -o pipefail

TARGET=""; OUTDIR=""; SCOPE_FILE=""; DO_GITHUB=1; DO_NUCLEI=1
HTTPX_RL=150; NUCLEI_RL=100; NUCLEI_MODE=fast
DO_PORTS=1; PORTSPEC=web; EVASION=0; STEALTH=0; NUCLEI_BATCH=40; DO_CVEMAP=1; DO_NMAPVULN=1; DO_WPSCAN=1

die(){ echo "[!] $*" >&2; exit 1; }
log(){ echo -e "[*] $*" >&2; }
ok(){  echo -e "[+] $*" >&2; }
warn(){ echo -e "[!] $*" >&2; }
have(){ command -v "$1" >/dev/null 2>&1; }
esc(){ sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g'; }

# Commercial-grade OUTRIDER banner (stderr; auto-plain when not a TTY so pipes stay clean).
print_banner(){
  if [ ! -t 2 ]; then
    printf '%s\n' "OUTRIDER v2.0 - external attack-surface recon & scanning framework" \
                  "author: Syed Sadam Hussain Shah" >&2
    return
  fi
  local R='\033[0m' B='\033[1m' D='\033[2m'
  # vertical cyan->deep-blue gradient down the logo
  local g1='\033[38;5;51m' g2='\033[38;5;45m' g3='\033[38;5;39m' g4='\033[38;5;33m' g5='\033[38;5;27m' g6='\033[38;5;21m'
  local ACC='\033[38;5;213m' WHT='\033[1;97m' RULE='\033[38;5;240m'
  local BADGE='\033[48;5;39m\033[1;30m'   # blue chip, dark text — version "badge"
  local RL='  \033[38;5;240m────────────────────────────────────────────────────────────────\033[0m'
  printf '%b\n' "" \
"${g1}   ██████╗ ██╗   ██╗████████╗██████╗ ██╗██████╗ ███████╗██████╗ ${R}" \
"${g2}  ██╔═══██╗██║   ██║╚══██╔══╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗${R}" \
"${g3}  ██║   ██║██║   ██║   ██║   ██████╔╝██║██║  ██║█████╗  ██████╔╝${R}" \
"${g4}  ██║   ██║██║   ██║   ██║   ██╔══██╗██║██║  ██║██╔══╝  ██╔══██╗${R}" \
"${g5}  ╚██████╔╝╚██████╔╝   ██║   ██║  ██║██║██████╔╝███████╗██║  ██║${R}" \
"${g6}   ╚═════╝  ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝${R}" \
"$RL" \
"  ${B}⚡ EXTERNAL ATTACK-SURFACE RECON & SCANNING FRAMEWORK${R}   ${BADGE} v2.0 ${R}" \
"  ${ACC}◈ AUTHOR${R}   ${WHT}Syed Sadam Hussain Shah${R}" \
"  ${ACC}◈ STACK${R}    ${D}subdomains · wayback · ports · js-secrets · nuclei · nvd-cve · wpscan · nmap-nse${R}" \
"$RL" \
"" >&2
}

while [ $# -gt 0 ]; do
  case "$1" in
    -o)          OUTDIR="$2"; shift 2;;
    --scope)     SCOPE_FILE="$2"; shift 2;;
    --no-github) DO_GITHUB=0; shift;;
    --no-nuclei) DO_NUCLEI=0; shift;;
    --nuclei-full) NUCLEI_MODE=full; shift;;
    --no-ports)  DO_PORTS=0; shift;;
    --ports)     PORTSPEC="$2"; shift 2;;
    --evasion)   EVASION=1; shift;;
    --stealth)   STEALTH=1; shift;;
    --nuclei-batch) NUCLEI_BATCH="$2"; shift 2;;
    --no-cvemap) DO_CVEMAP=0; shift;;
    --no-nmap-vuln) DO_NMAPVULN=0; shift;;
    --no-wpscan) DO_WPSCAN=0; shift;;
    -h|--help)   grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    -*)          die "unknown flag: $1";;
    *)           TARGET="$1"; shift;;
  esac
done

[ -n "$TARGET" ] || die "no target. usage: ./outrider.sh example.com [-o outdir] [--scope scope.txt]"
TARGET="${TARGET#http://}"; TARGET="${TARGET#https://}"; TARGET="${TARGET%%/*}"
[ -n "$OUTDIR" ] || OUTDIR="outrider-${TARGET}-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR" || die "cannot create $OUTDIR"

print_banner

# stealth: quietest nuclei (very low rate, big back-off). Set before deps so logged once.
if [ "$STEALTH" -eq 1 ]; then NUCLEI_RL=15; fi

command -v curl >/dev/null || die "curl is required"
command -v jq   >/dev/null || die "jq is required (apt install jq)"
for t in subfinder nuclei naabu dnsx cdncheck nmap waybackurls gau uro trufflehog; do
  have "$t" || warn "optional tool missing: $t (that phase degrades/skips)"
done

# Resolve ProjectDiscovery httpx. Kali ships it as 'httpx-toolkit' because the
# plain 'httpx' command is usually the unrelated Python HTTP client, which
# rejects our flags and silently yields no results. Verify with -version.
resolve_httpx(){
  local c
  for c in httpx-toolkit httpx; do
    command -v "$c" >/dev/null 2>&1 || continue
    if "$c" -version >/dev/null 2>&1; then echo "$c"; return 0; fi
  done
  return 1
}
HTTPX="$(resolve_httpx || true)"
if [ -n "$HTTPX" ]; then
  ok "httpx binary: $HTTPX"
elif command -v httpx >/dev/null 2>&1; then
  warn "a 'httpx' command exists but is NOT ProjectDiscovery httpx (likely the Python"
  warn "  HTTP client). Install PD httpx:  apt install httpx-toolkit   (Kali)"
  warn "  or:  go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
  warn "  Falling back to curl liveness (no fingerprint/tech detection)."
else
  warn "httpx not found — live/fingerprint falls back to curl (no tech detection)."
fi

ALLHOSTS="$OUTDIR/allhosts.txt"; INSCOPE="$OUTDIR/inscope.txt"; OUTSCOPE="$OUTDIR/outofscope.txt"
LIVE="$OUTDIR/livehosts.txt"; HTTPXJSON="$OUTDIR/httpx.json"; TECH="$OUTDIR/techstack.txt"
NUCLEI="$OUTDIR/nuclei.jsonl"; GHSECRETS="$OUTDIR/github_secrets.txt"
WAYBACK="$OUTDIR/wayback.txt"; URLSCLEAN="$OUTDIR/urls_clean.txt"; PARAMS="$OUTDIR/params.txt"
JUICY="$OUTDIR/juicy_files.txt"; JUICYLIVE="$OUTDIR/juicy_live.txt"
JSFILES="$OUTDIR/jsfiles.txt"; JSLIVE="$OUTDIR/js_live.txt"
JS_ENDPOINTS="$OUTDIR/js_endpoints.txt"; JS_SECRETS="$OUTDIR/js_secrets.txt"
IPS="$OUTDIR/ips.txt"; CDN_IPS="$OUTDIR/cdn_ips.txt"; SCAN_IPS="$OUTDIR/scan_ips.txt"
PORTS="$OUTDIR/ports.txt"; WEBSVC="$OUTDIR/web_services.txt"; NUCLEI_TARGETS="$OUTDIR/nuclei_targets.txt"
VERSION_CVES="$OUTDIR/version_cves.txt"; NSE_VULN="$OUTDIR/nmap_vuln.txt"
WP_SITES="$OUTDIR/wp_sites.txt"; WPSCAN_OUT="$OUTDIR/wpscan.txt"
HIGHINT="$OUTDIR/high_interest_hosts.txt"; ANALYSIS="$OUTDIR/analysis.txt"; REPORT="$OUTDIR/report.html"
BK="$OUTDIR/buckets"; mkdir -p "$BK"
: > "$ALLHOSTS"

# param-name signatures per vuln class (gf-style)
RE_SQLI='id|pid|uid|userid|user|cat|category|item|product|prod|order|sort|col|column|field|search|q|query|where|select|from|num|key|type|name'
RE_LFI='file|path|page|doc|document|folder|root|pg|style|pdf|template|lang|dir|download|read|load|view|include|inc|conf|config|filename|filepath'
RE_SSRF='url|uri|link|redirect|redirect_uri|next|data|dest|destination|domain|callback|return|returnurl|host|port|to|out|image|imageurl|img|proxy|fetch|site|html|feed|open|window|continue'
RE_REDIRECT='redirect|redir|url|next|return|returnurl|return_url|returnto|goto|go|dest|destination|continue|rurl|out|target|link|checkout_url|redirect_uri|login_url|image_url'
RE_RCE='cmd|exec|command|execute|ping|query|jump|code|reg|do|func|arg|option|load|process|step|read|feature|exe|module|payload|run|print|daemon|cli|ip'
RE_SSTI='template|preview|activity|content|lang|message|tpl|twig|render'
RE_JUICY='\.(bak|old|backup|sql|db|sqlite|zip|tar|gz|tgz|rar|7z|config|conf|env|ini|log|json|xml|yml|yaml|git|svn|pem|key|crt|p12|pfx|dump|sql\.gz|war|jar)(\?|$)'
RE_INTEREST='admin|adm|dev|develop|staging|stage|stg|test|uat|qa|preprod|internal|intra|vpn|jenkins|gitlab|git|bitbucket|jira|confluence|grafana|kibana|elastic|prometheus|backup|bak|old|legacy|beta|portal|sso|auth|oauth|idp|ftp|sftp|db|database|mysql|postgres|mongo|redis|phpmyadmin|pma|api|gateway|dashboard|monitor|status|debug|demo|sandbox|corp|vault|nexus|sonar|harbor|registry|k8s|kube|rancher'

# Known third-party/library and CMS-core JS to skip during analysis — these never hold
# the target's own endpoints or secrets, just flood the report (jQuery, WP core, etc.).
RE_JS_SKIP='/wp-includes/|(^|/)(jquery([.-]|$)|jquery-migrate|jquery[.-]?ui|ui/(jquery\.)?widget|modernizr|respond|selectivizr|bootstrap|popper|angular|react|react-dom|vue|lodash|underscore|moment|swiper|slick|owl\.carousel|video-?js|touchswipe|smartstartslider|wp-embed|wp-emoji|comment-reply|mathjax|fontawesome|font-awesome|polyfill|googletagmanager|google-analytics|gtm\.js|recaptcha|hotjar|intercom)'

# secretfinder-style patterns: "label|ERE". Case-sensitive prefixes stay exact; the
# generic assignment pattern is matched case-insensitively in analyze_js.
SECRET_PATTERNS=(
  "AWS Access Key|AKIA[0-9A-Z]{16}"
  "Google API Key|AIza[0-9A-Za-z_-]{35}"
  "Google OAuth Token|ya29\.[0-9A-Za-z_-]{20,}"
  "GitHub Token|gh[pousr]_[0-9A-Za-z]{36,}"
  "Slack Token|xox[baprs]-[0-9A-Za-z-]{10,48}"
  "Slack Webhook|https://hooks\.slack\.com/services/[A-Za-z0-9/]+"
  "Stripe Secret Key|[sr]k_live_[0-9a-zA-Z]{20,}"
  "Stripe Pub Key|pk_live_[0-9a-zA-Z]{20,}"
  "SendGrid Key|SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}"
  "Twilio Key SID|SK[0-9a-fA-F]{32}"
  "Mailgun Key|key-[0-9a-zA-Z]{32}"
  "JWT|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
  "Private Key Block|-----BEGIN [A-Z ]*PRIVATE KEY-----"
  "Firebase URL|[a-z0-9.-]+\.firebaseio\.com"
)
# generic 'key = "value"' assignment (noisier; case-insensitive key names)
# NOTE: value MUST be a quoted string literal (["']...["']) — this rejects code that
# merely references a variable (apiKey:n.account_key / secret=this._globalSecret), which
# otherwise produced false-positive "secrets".
SECRET_GENERIC="(api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|passwd|password)[\"' ]*[:=] *[\"'][0-9a-zA-Z/_.+=~-]{8,}[\"']"

# ---------- 1. passive subdomains ----------
# crt.sh over its JSON endpoint is slow and rate-limits non-browser clients, so for a
# large domain a single short curl often times out or returns an HTML error page that
# jq can't parse. Retry with a long timeout + browser UA, validate the body is JSON,
# and report the real count instead of a misleading "empty".
crtsh_fetch(){
  local body attempt
  for attempt in 1 2 3; do
    body=$(curl -s --max-time 120 -A "Mozilla/5.0 (recon.sh)" -H "Accept: application/json" \
             "https://crt.sh/?q=%25.${TARGET}&output=json" 2>/dev/null)
    # a valid response is a JSON array starting with '['
    case "$(printf '%s' "$body" | head -c1)" in
      "[") printf '%s' "$body"; return 0 ;;
    esac
    warn "crt.sh attempt $attempt: no JSON (slow/rate-limited) — retrying in 4s"
    sleep 4
  done
  return 1
}
passive_subdomains(){
  log "passive: crt.sh"
  local json before after
  before=$(wc -l < "$ALLHOSTS" 2>/dev/null | tr -d ' ')
  if json=$(crtsh_fetch); then
    printf '%s' "$json" \
      | jq -r '.[]?.common_name, (.[]?.name_value|split("\n")[]?)' 2>/dev/null \
      | sed 's/^\*\.//' | tr '[:upper:]' '[:lower:]' | grep -E "\.?${TARGET//./\\.}$" >> "$ALLHOSTS" || true
    sort -u -o "$ALLHOSTS" "$ALLHOSTS"
    after=$(wc -l < "$ALLHOSTS" 2>/dev/null | tr -d ' ')
    ok "crt.sh: +$((after - before)) hosts"
  else
    warn "crt.sh: no usable response after 3 tries (it's often slow/rate-limited over curl)."
    warn "  not fatal — subfinder also queries crt.sh. To check by hand: curl 'https://crt.sh/?q=%25.${TARGET}&output=json'"
  fi
  if have subfinder; then
    log "passive: subfinder"
    subfinder -d "$TARGET" -all -silent 2>/dev/null >> "$ALLHOSTS" || true
  fi
  if [ -n "${DNSDUMPSTER_API_KEY:-}" ]; then
    log "passive: dnsdumpster API"
    curl -s --max-time 60 -H "X-API-Key: ${DNSDUMPSTER_API_KEY}" \
      "https://api.dnsdumpster.com/domain/${TARGET}" | jq -r '.. | .host? // empty' 2>/dev/null >> "$ALLHOSTS" || true
  fi
  sort -u -o "$ALLHOSTS" "$ALLHOSTS"
  ok "passive: $(wc -l < "$ALLHOSTS"|tr -d ' ') hosts"
}

# ---------- 2. wayback collection ----------
# Pull archived URLs from the Internet Archive. The CDX API rate-limits by IP, so a
# single request (what waybackurls/gau do under the hood) can come back near-empty on
# a bad day. We validate the yield and, if it's thin, supplement directly from the CDX
# wildcard endpoint (which also covers *.domain subdomains that waybackurls misses).
cdx_fetch(){
  local attempt body
  # matchType=domain returns the apex AND all subdomains (the canonical form); the old
  # leading-wildcard 'url=*.domain/*' only matched subdomains and missed the apex,
  # which is why it came back empty. -L follows IA's http->https redirect.
  local url="https://web.archive.org/cdx/search/cdx?url=${TARGET}&matchType=domain&fl=original&collapse=urlkey&output=text&limit=50000"
  for attempt in 1 2 3; do
    body=$(curl -sL --max-time 120 -A "Mozilla/5.0 (recon.sh)" "$url" 2>/dev/null)
    if [ -n "$body" ] && printf '%s' "$body" | grep -qi "${TARGET}"; then printf '%s\n' "$body"; return 0; fi
    warn "wayback CDX attempt $attempt: empty/throttled — retrying in 6s"; sleep 6
  done
  return 1
}
wayback(){
  : > "$WAYBACK"; : > "$OUTDIR/wayback.err"
  # waybackurls (Internet Archive) + gau (IA + CommonCrawl + URLScan + OTX). IA rate-limits
  # by IP and bare waybackurls has no retries, so we RETRY the whole collection with backoff
  # (IA throttles usually clear within a minute) and stop early once results stop growing.
  local tries=${WAYBACK_TRIES:-3} attempt=0 prev=-1 n
  while [ "$attempt" -lt "$tries" ]; do
    attempt=$((attempt+1))
    [ "$attempt" -eq 1 ] && log "wayback: waybackurls + gau (IA + CommonCrawl + URLScan + OTX)"
    if have waybackurls; then echo "$TARGET" | waybackurls 2>>"$OUTDIR/wayback.err" >> "$WAYBACK" || true; fi
    if have gau;         then gau --subs --retries 3 --threads 5 --timeout 60 "$TARGET" 2>>"$OUTDIR/wayback.err" >> "$WAYBACK" || true; fi
    sort -u -o "$WAYBACK" "$WAYBACK"; n=$(cnt "$WAYBACK")
    [ "$n" -ge 50 ] && break                       # enough data
    [ "$n" -eq "$prev" ] && [ "$n" -gt 0 ] && break  # stable (genuinely small archive), don't spin
    if [ "$attempt" -lt "$tries" ]; then
      local s=$((attempt*15))
      warn "wayback: only $n URL(s) — Internet Archive likely throttling; retry $attempt/$((tries-1)) in ${s}s"
      sleep "$s"
    fi
    prev=$n
  done
  # robust CDX backstop (our curl: browser UA + retries) if still thin
  if [ "$(cnt "$WAYBACK")" -lt 50 ]; then
    log "wayback: CDX API backstop"
    if ! cdx_fetch >> "$WAYBACK"; then
      warn "wayback: still thin — your IP is likely IA-rate-limited (the Wayback *UI* uses a"
      warn "  different endpoint, so it can still show data). Fixes: wait ~15 min, use a VPN/"
      warn "  different IP, or raise retries with WAYBACK_TRIES=5. See $OUTDIR/wayback.err for errors."
    fi
    sort -u -o "$WAYBACK" "$WAYBACK"
  fi
  if [ -s "$WAYBACK" ]; then
    grep -oiE 'https?://[^/"]+' "$WAYBACK" | sed -E 's#https?://##;s/:.*//' | tr '[:upper:]' '[:lower:]' \
      | grep -E "\.?${TARGET//./\\.}$" >> "$ALLHOSTS" || true
    sort -u -o "$ALLHOSTS" "$ALLHOSTS"
  fi
  ok "wayback: $(cnt "$WAYBACK") URLs"
}

# ---------- 3. wayback triage (offline) ----------
bucket(){ grep -iE "[?&]($1)=" "$PARAMS" 2>/dev/null | sort -u > "$BK/$2.txt"; }
wayback_triage(){
  [ -s "$WAYBACK" ] || { warn "triage: no wayback data"; return; }
  if have uro; then log "triage: uro dedup"; uro -i "$WAYBACK" 2>/dev/null > "$URLSCLEAN" || uro < "$WAYBACK" > "$URLSCLEAN" 2>/dev/null || cp "$WAYBACK" "$URLSCLEAN"
  else log "triage: no uro, basic dedup"; grep -ivE '\.(png|jpe?g|gif|svg|css|woff2?|ttf|ico|map|webp)(\?|$)' "$WAYBACK" | sort -u > "$URLSCLEAN"; fi
  grep -E '\?[^=]+=' "$URLSCLEAN" | sort -u > "$PARAMS" || true
  bucket "$RE_SQLI" sqli; bucket "$RE_LFI" lfi; bucket "$RE_SSRF" ssrf
  bucket "$RE_REDIRECT" redirect; bucket "$RE_RCE" rce; bucket "$RE_SSTI" ssti
  grep -iE "$RE_JUICY" "$URLSCLEAN" | sort -u > "$JUICY" || true
  grep -iE '\.js(\?|$)' "$URLSCLEAN" | sort -u > "$JSFILES" || true
  ok "triage: $(wc -l < "$PARAMS" 2>/dev/null|tr -d ' ') param-URLs, $(wc -l < "$JUICY" 2>/dev/null|tr -d ' ') juicy, $(wc -l < "$JSFILES" 2>/dev/null|tr -d ' ') JS"
}

# ---------- 4. github secrets ----------
github_secrets(){
  [ "$DO_GITHUB" -eq 1 ] || { log "github: skipped"; return; }
  have trufflehog || { warn "github: trufflehog missing"; return; }
  [ -n "${GITHUB_TOKEN:-}" ] || { warn "github: GITHUB_TOKEN not set, skipping"; return; }
  local org="${GITHUB_ORG:-$TARGET}"; org="${org%%.*}"
  log "github: trufflehog org=$org"
  trufflehog github --org="$org" --only-verified --json 2>/dev/null > "$GHSECRETS.raw" || true
  if [ -s "$GHSECRETS.raw" ]; then
    jq -r '"["+(.DetectorName//"?")+"] "+(.SourceMetadata.Data.Github.repository//"?")+" :: "+(.SourceMetadata.Data.Github.file//"?")' "$GHSECRETS.raw" 2>/dev/null | sort -u > "$GHSECRETS" || true
  fi
  [ -s "$GHSECRETS" ] || echo "(no verified secrets found)" > "$GHSECRETS"
  ok "github: done"
}

# ---------- 5. scope filter ----------
scope_filter(){
  : > "$INSCOPE"; : > "$OUTSCOPE"
  while read -r h; do
    [ -n "$h" ] || continue; local keep=0
    if [ -n "$SCOPE_FILE" ] && [ -f "$SCOPE_FILE" ]; then
      while read -r s; do [ -n "$s" ] && [[ "$h" == *"$s" ]] && keep=1; done < "$SCOPE_FILE"
    else [[ "$h" == "$TARGET" || "$h" == *".$TARGET" ]] && keep=1; fi
    if [ "$keep" -eq 1 ]; then echo "$h" >> "$INSCOPE"; else echo "$h" >> "$OUTSCOPE"; fi
  done < "$ALLHOSTS"
  sort -u -o "$INSCOPE" "$INSCOPE"; sort -u -o "$OUTSCOPE" "$OUTSCOPE"
  ok "scope: $(wc -l < "$INSCOPE"|tr -d ' ') in / $(wc -l < "$OUTSCOPE"|tr -d ' ') out"
  [ -s "$INSCOPE" ] || { warn "scope: nothing in scope"; return 1; }
}

# keep only URLs whose host is in inscope.txt
filter_inscope_urls(){ awk -F/ 'NR==FNR{s[$0]=1;next}{h=$3;sub(/:.*/,"",h); if(h in s) print}' "$INSCOPE" -; }

# ---------- 6. live + fingerprint ----------
live_and_fingerprint(){
  if [ -z "$HTTPX" ]; then
    warn "no ProjectDiscovery httpx — curl liveness, no fingerprint"
    while read -r h; do for s in https http; do c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$s://$h"); [ "$c" != "000" ] && { echo "$s://$h"; break; }; done; done < "$INSCOPE" | sort -u > "$LIVE"
    : > "$HTTPXJSON"; ok "live: $(wc -l < "$LIVE"|tr -d ' ') (curl)"; return
  fi
  log "live+fingerprint: $HTTPX (rate ${HTTPX_RL}/s)"
  "$HTTPX" -l "$INSCOPE" -json -silent -no-color -status-code -title -web-server -tech-detect -favicon -follow-redirects -rate-limit "$HTTPX_RL" -timeout 10 > "$HTTPXJSON" 2>"$OUTDIR/httpx.err" || true
  jq -r '.url' "$HTTPXJSON" 2>/dev/null | sort -u > "$LIVE"
  jq -r '.url + " | " + (.webserver//"-") + " | " + ((.tech//[])|join(", ")|if .=="" then "-" else . end) + " | " + (.title//"-")' "$HTTPXJSON" 2>/dev/null > "$TECH" || true
  grep -iE "://([^/]*($RE_INTEREST))" "$LIVE" | sort -u > "$HIGHINT" || true
  # If httpx produced nothing despite in-scope hosts, surface why instead of hiding it.
  if [ ! -s "$HTTPXJSON" ] && [ -s "$INSCOPE" ]; then
    warn "httpx returned no results for $(wc -l < "$INSCOPE"|tr -d ' ') in-scope host(s)."
    [ -s "$OUTDIR/httpx.err" ] && warn "httpx stderr (first lines): $(head -n 2 "$OUTDIR/httpx.err" | tr '\n' ' ')"
    warn "check network egress and that '$HTTPX' is ProjectDiscovery httpx (-version)."
  fi
  ok "live: $(wc -l < "$LIVE"|tr -d ' ') live, $(wc -l < "$HIGHINT" 2>/dev/null|tr -d ' ') high-interest"
}

# ---------- 6b. PORT DISCOVERY (CDN-aware; nmap evasion fallback) ----------
# Resolve in-scope hosts to unique IPs, drop CDN IPs (scanning the edge is pointless and
# risky), scan the rest for open ports, then httpx any new web ports and merge them into
# the live set so they get fingerprinted + CVE-scanned like everything else.
# parse nmap -oG output on stdin -> "ip:port" for each OPEN port. Isolates the tab-
# delimited Host: and Ports: fields so the IP can't bleed into the port number.
_nmap_open(){
  awk -F'\t' '{
    ip=""
    for(i=1;i<=NF;i++){
      if($i ~ /^Host:/){ split($i,h," "); ip=h[2] }
      else if($i ~ /^[ ]*Ports:/){ s=$i; sub(/^[ ]*Ports: /,"",s); n=split(s,b,",")
        for(j=1;j<=n;j++) if(b[j] ~ /\/open\//){ split(b[j],c,"/"); gsub(/[^0-9]/,"",c[1]); if(ip!="" && c[1]!="") print ip":"c[1] } }
    }
  }'
}
_portspec_ports(){
  # translate PORTSPEC into a port argument for naabu/nmap
  case "$PORTSPEC" in
    web) echo "80,443,8080,8443,8000,8008,8081,8088,8181,8443,8888,3000,5000,7001,7002,8090,9000,9090,9200,9443,10000,4443,4567,5601,8161,15672";;
    top*) echo "";;  # handled via -top-ports
    *) echo "$PORTSPEC";;  # explicit CSV
  esac
}
port_discovery(){
  [ "$DO_PORTS" -eq 1 ] || { log "ports: skipped (--no-ports)"; return; }
  [ -s "$INSCOPE" ] || return
  # 1) resolve in-scope hostnames -> IPs
  log "ports: resolving in-scope hosts to IPs"
  if have dnsx; then dnsx -l "$INSCOPE" -a -resp-only -silent 2>/dev/null | sort -u > "$IPS" || true
  else
    : > "$IPS"
    while read -r h; do
      getent hosts "$h" 2>/dev/null | awk '{print $1}' >> "$IPS" || true
    done < "$INSCOPE"
    sort -u -o "$IPS" "$IPS"
  fi
  grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$IPS" | sort -u > "$IPS.tmp" && mv "$IPS.tmp" "$IPS"
  [ -s "$IPS" ] || { warn "ports: could not resolve any IPs — skipping port scan"; return; }

  # 2) drop CDN/WAF IPs — scanning the edge is noise AND trips the provider's WAF (which is
  #    what blocked an earlier run). Three detectors, unioned, because httpx -cdn alone
  #    under-detected Cloudflare/CloudFront here:
  #    (a) cdncheck (maintained CDN/WAF ranges — best for AWS CloudFront, Akamai, Fastly),
  #    (b) a built-in prefix net for the big fixed ranges (Cloudflare, Fastly),
  #    (c) httpx -cdn as a backstop.
  : > "$CDN_IPS"
  if have cdncheck; then
    cdncheck -cdn -waf -silent < "$IPS" 2>/dev/null | awk '{print $1}' >> "$CDN_IPS" || true
  fi
  # Built-in prefix net for the big fixed ranges (so cdncheck isn't mandatory):
  #  Cloudflare (104.16/12, 172.64/13, 162.158, 141.101, 108.162, 173.245, 103.21-22, 190.93, 188.114, 197.234),
  #  Fastly (151.101/16), and major AWS CloudFront blocks (108.138-139, 108.156-159, 13.32-35,
  #  13.224-227, 18.160-175, 52.84, 52.222, 54.182/192/230/239, 99.84, 143.204, 204.246, 205.251, 3.160/13, 65.8-9).
  grep -E '^(104\.(1[6-9]|2[0-9]|3[01])\.|172\.(6[4-9]|7[01])\.|151\.101\.|173\.245\.|103\.2[12]\.|141\.101\.|108\.(162|13[89]|15[6-9])\.|190\.93\.|188\.114\.|197\.234\.|162\.158\.|13\.(3[2-5]|22[4-7])\.|18\.1(6[0-9]|7[0-5])\.|52\.(84|222)\.|54\.(182|19[02]|230|239)\.|99\.84\.|143\.204\.|204\.246\.|205\.251\.|3\.16[0-7]\.|65\.[89]\.)' "$IPS" >> "$CDN_IPS" 2>/dev/null || true
  if [ -n "$HTTPX" ]; then
    "$HTTPX" -l "$INSCOPE" -cdn -a -json -silent 2>/dev/null \
      | jq -r 'select(.cdn==true) | (.a[]? // empty)' 2>/dev/null >> "$CDN_IPS" || true
  fi
  sort -u -o "$CDN_IPS" "$CDN_IPS" 2>/dev/null || true
  if [ -s "$CDN_IPS" ]; then grep -vxF -f "$CDN_IPS" "$IPS" | sort -u > "$SCAN_IPS" || cp "$IPS" "$SCAN_IPS"
  else cp "$IPS" "$SCAN_IPS"; fi
  ok "ports: $(cnt "$IPS") IP(s) resolved, $(cnt "$CDN_IPS") CDN IP(s) excluded, $(cnt "$SCAN_IPS") to scan"
  [ -s "$SCAN_IPS" ] || { warn "ports: all IPs are CDN — nothing to port-scan"; return; }

  # 3) scan ports (naabu preferred; nmap fallback). Polite rate.
  : > "$PORTS"
  local parg; parg="$(_portspec_ports)"
  if have naabu; then
    log "ports: naabu (${PORTSPEC}) on $(cnt "$SCAN_IPS") IP(s)"
    if [ -n "$parg" ]; then
      naabu -list "$SCAN_IPS" -p "$parg" -silent -rate 300 2>/dev/null | sort -u > "$PORTS" || true
    else
      naabu -list "$SCAN_IPS" -top-ports "${PORTSPEC#top}" -silent -rate 300 2>/dev/null | sort -u > "$PORTS" || true
    fi
  elif have nmap; then
    log "ports: nmap on $(cnt "$SCAN_IPS") IP(s)"
    local nmapp; nmapp="${parg:-1-1000}"
    nmap -Pn -n -T3 -p "$nmapp" -oG - -iL "$SCAN_IPS" 2>/dev/null | _nmap_open | sort -u > "$PORTS" || true
  else
    warn "ports: neither naabu nor nmap installed — skipping"; return
  fi

  # 3b) evasion fallback: naabu found nothing AND --evasion AND nmap present -> the
  # firewall may be dropping SYNs; retry with nmap evasive flags (see nmap-evasion-probe.sh).
  if [ ! -s "$PORTS" ] && [ "$EVASION" -eq 1 ] && have nmap; then
    warn "ports: no open ports found — retrying with nmap evasion (source-port 53, slow, fragmented)"
    nmap -Pn -n -T2 -g 53 -f --data-length 24 -p "${parg:-80,443,8080,8443,8000,3000,9200}" -oG - -iL "$SCAN_IPS" 2>/dev/null | _nmap_open | sort -u > "$PORTS" || true
    [ -s "$PORTS" ] || warn "ports: evasion scan also found nothing. Run nmap-evasion-probe.sh to calibrate a bypass, then re-run with --ports."
  fi
  ok "ports: $(cnt "$PORTS") open ip:port(s) -> $PORTS"
  [ -s "$PORTS" ] || return

  # 4) which open ports speak HTTP? httpx them and merge new web services into the live set.
  if [ -n "$HTTPX" ]; then
    log "ports: httpx on discovered ports to find web services"
    "$HTTPX" -l "$PORTS" -json -silent -no-color -status-code -title -web-server -tech-detect -favicon \
             -follow-redirects -rate-limit "$HTTPX_RL" -timeout 10 2>/dev/null > "$OUTDIR/httpx_ports.json" || true
    if [ -s "$OUTDIR/httpx_ports.json" ]; then
      jq -r '.url' "$OUTDIR/httpx_ports.json" 2>/dev/null | sort -u > "$WEBSVC" || true
      # merge into the global live set + fingerprint json so downstream phases include them
      cat "$WEBSVC" >> "$LIVE"; sort -u -o "$LIVE" "$LIVE"
      cat "$OUTDIR/httpx_ports.json" >> "$HTTPXJSON"
      jq -r '.url + " | " + (.webserver//"-") + " | " + ((.tech//[])|join(", ")|if .=="" then "-" else . end) + " | " + (.title//"-")' \
        "$OUTDIR/httpx_ports.json" 2>/dev/null >> "$TECH" || true
      grep -iE "://([^/]*($RE_INTEREST))" "$WEBSVC" | sort -u >> "$HIGHINT" 2>/dev/null; sort -u -o "$HIGHINT" "$HIGHINT" 2>/dev/null || true
    fi
  fi
  ok "ports: $(cnt "$WEBSVC") web service(s) on non-standard ports -> merged into live set (now $(cnt "$LIVE") live)"
}

# ---------- 6c. service-level vuln checks on NON-WEB ports (nmap NSE, opt-in) ----------
# Complements nuclei (HTTP-only) by running nmap's 'vuln and safe' scripts against the open
# ports that are NOT web services — catches TLS (Heartbleed/POODLE/ROBOT), SMB, and other
# service vulns nuclei can't see. 'vulners' is excluded to avoid duplicating the NVD phase.
# Inherits CDN exclusion (ports come from the already-CDN-filtered scan set). Opt-in: slow.
nmap_vuln_scan(){
  [ "$DO_NMAPVULN" -eq 1 ] || { log "nmap-vuln: skipped (--no-nmap-vuln)"; return; }
  have nmap || { warn "nmap-vuln: nmap not installed — skipping"; return; }
  [ -s "$PORTS" ] || { warn "nmap-vuln: no discovered ports (run with port discovery) — skipping"; return; }
  # web ip:port set (strip scheme from the httpx-confirmed web services)
  local webset="$OUTDIR/.webset.tmp"; sed -E 's#^https?://##; s#/.*$##' "$WEBSVC" 2>/dev/null | sort -u > "$webset"
  # non-web = discovered ip:port NOT in the web set
  local nonweb="$OUTDIR/.nonweb.tmp"
  grep -vxF -f "$webset" "$PORTS" 2>/dev/null | sort -u > "$nonweb" || cp "$PORTS" "$nonweb"
  rm -f "$webset"
  if [ ! -s "$nonweb" ]; then rm -f "$nonweb"; log "nmap-vuln: all discovered ports are web services — nothing non-web to check"; return; fi
  local nip npts ips_file="$OUTDIR/.nvip.tmp"
  cut -d: -f1 "$nonweb" | sort -u > "$ips_file"
  npts=$(cut -d: -f2 "$nonweb" | sort -un | paste -sd, -)
  nip=$(cnt "$ips_file")
  log "nmap-vuln: NSE 'vuln and safe' on $nip host(s), non-web ports [$npts] (slow; vulners excluded)"
  nmap -Pn -n -sV --script "vuln and safe and not vulners" --script-timeout 90s \
       -p "$npts" -iL "$ips_file" -oN "$NSE_VULN" 2>/dev/null || warn "nmap-vuln: nmap exited non-zero (partial results kept)"
  rm -f "$nonweb" "$ips_file"
  local nvuln; nvuln=$(grep -c 'VULNERABLE' "$NSE_VULN" 2>/dev/null); nvuln=${nvuln:-0}
  ok "nmap-vuln: $nvuln 'VULNERABLE' marker(s) -> $NSE_VULN"
}

# ---------- 6d. WordPress detection (+ optional wpscan) ----------
# Flags WordPress sites from the httpx fingerprint and, when WP is detected, AUTOMATICALLY runs
# wpscan against them (users + vulnerable plugins/themes + version). Always emits a ready-to-run
# wpscan command per site in the report. --no-wpscan skips the active run; WPSCAN_API_TOKEN enables
# the vuln database.
wordpress_phase(){
  [ -s "$HTTPXJSON" ] || return
  jq -r 'select((.tech[]? // "")|test("wordpress";"i")) | .url' "$HTTPXJSON" 2>/dev/null | sort -u > "$WP_SITES" || true
  local nwp; nwp=$(cnt "$WP_SITES")
  [ "$nwp" -gt 0 ] || { log "wordpress: none detected in fingerprint"; return; }
  ok "wordpress: $nwp WordPress site(s) detected -> $WP_SITES"
  if [ "$DO_WPSCAN" -ne 1 ]; then
    log "wordpress: wpscan run skipped (--no-wpscan); ready-to-run command is in the report"
    return
  fi
  have wpscan || { warn "wordpress: wpscan not installed ('gem install wpscan') — WP sites flagged with a ready-to-run command in the report instead"; return; }
  : > "$WPSCAN_OUT"
  local tok=(); [ -n "${WPSCAN_API_TOKEN:-}" ] && tok=(--api-token "$WPSCAN_API_TOKEN")
  [ -n "${WPSCAN_API_TOKEN:-}" ] || warn "wordpress: no WPSCAN_API_TOKEN — enumerating users/plugins/version but NOT the vuln DB"
  local u
  while read -r u; do
    [ -n "$u" ] || continue
    log "wpscan: $u (users + vulnerable plugins/themes + version)"
    { echo "========== $u =========="
      wpscan --url "$u" --enumerate u,vp,vt --random-user-agent --no-banner --no-update \
             --throttle 300 --request-timeout 30 --connect-timeout 20 \
             -f cli-no-color "${tok[@]}" 2>&1
      echo; } >> "$WPSCAN_OUT" || true
  done < "$WP_SITES"
  ok "wpscan: done -> $WPSCAN_OUT ($(cnt "$WPSCAN_OUT") lines)"
}

# ---------- 7. active check of archived juicy/JS files (in-scope only) ----------
check_archived(){
  [ -n "$HTTPX" ] || return
  if [ -s "$JUICY" ]; then
    log "triage: live-checking juicy files (in-scope)"
    filter_inscope_urls < "$JUICY" | "$HTTPX" -silent -no-color -mc 200,401,403,500 -status-code -rate-limit "$HTTPX_RL" -timeout 10 2>/dev/null | sort -u > "$JUICYLIVE" || true
  fi
  if [ -s "$JSFILES" ]; then
    log "triage: live-checking JS files (in-scope)"
    filter_inscope_urls < "$JSFILES" | "$HTTPX" -silent -no-color -mc 200 -rate-limit "$HTTPX_RL" -timeout 10 2>/dev/null | sort -u > "$JSLIVE" || true
  fi
  ok "triage-live: $( [ -f "$JUICYLIVE" ] && wc -l < "$JUICYLIVE"|tr -d ' ' || echo 0) juicy live, $( [ -f "$JSLIVE" ] && wc -l < "$JSLIVE"|tr -d ' ' || echo 0) JS live"
}

# Shannon-entropy gate for GENERIC secret candidates: rejects low-entropy identifiers and
# dictionary-ish values (e.g. "account_name", "this._globalSecret") while keeping high-entropy
# keys/tokens. Requires length >=12, >=8 distinct chars, and entropy >=3.0 bits/char.
_entropy_ok(){
  local s="$1"
  # reject dotted code references (this._x / a.b.c — not real keys; JWTs are caught separately)
  printf '%s' "$s" | grep -qE '^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z0-9_$]+)+$' && return 1
  # reject obvious placeholders
  printf '%s' "$s" | grep -qiE 'your|example|changeme|placeholder|replace|dummy|sample|undefined|null|false|true' && return 1
  awk -v s="$s" 'BEGIN{
    n=length(s); if(n<12) exit 1
    for(i=1;i<=n;i++){ c=substr(s,i,1); f[c]++ }
    u=0; for(c in f) u++
    if(u<8) exit 1
    H=0; for(c in f){ p=f[c]/n; H-=p*(log(p)/log(2)) }
    exit (H>=3.3)?0:1
  }'
}

# ---------- 7b. analyze live JS: endpoints + secrets (built-in LinkFinder/secretfinder) ----------
# Fetches each in-scope live JS file and extracts (a) endpoints/paths and (b) secrets/keys,
# so you don't have to run LinkFinder/secretfinder by hand. Capped by JS_MAX (default 150);
# results stream to disk, so Ctrl+C still leaves partial output for the report.
analyze_js(){
  [ -s "$JSLIVE" ] || return
  local max=${JS_MAX:-150} count=0 skipped=0 url pat label regex hit val nfiles
  local jsbody="$OUTDIR/.jsbody.tmp"
  nfiles=$(cnt "$JSLIVE")
  log "js: analyzing up to $max of $nfiles live JS file(s) for endpoints + secrets (skipping known libraries)"
  : > "$JS_ENDPOINTS"; : > "$JS_SECRETS"
  while read -r url; do
    [ -n "$url" ] || continue
    # skip third-party libraries / CMS core — only the app's own JS is worth analyzing
    if printf '%s' "$url" | grep -qiE "$RE_JS_SKIP"; then skipped=$((skipped+1)); continue; fi
    count=$((count+1)); if [ "$count" -gt "$max" ]; then warn "js: reached JS_MAX=$max app JS files (raise with JS_MAX=N)"; break; fi
    # Fetch to a FILE (not a $() var): avoids the "ignored null byte" warning on binary/
    # UTF-16 content, and --compressed decodes gzip/br so we grep the real JS, not bytes.
    curl -sL --compressed --max-time 8 -A "Mozilla/5.0 (recon.sh)" "$url" -o "$jsbody" 2>/dev/null || true
    [ -s "$jsbody" ] || continue
    # (a) endpoints: absolute URLs + quoted absolute paths (grep -a = binary-safe)
    {
      grep -aoiE 'https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]{6,}' "$jsbody"
      grep -aoE "[\"']/[A-Za-z0-9_./?=&%-]{2,}[\"']" "$jsbody" | tr -d "\"'"
    } 2>/dev/null >> "$JS_ENDPOINTS" || true
    # (b) secrets: labeled high-signal patterns + a generic key=value catch-all
    for pat in "${SECRET_PATTERNS[@]}"; do
      label="${pat%%|*}"; regex="${pat#*|}"
      while IFS= read -r hit; do [ -n "$hit" ] && printf '%s\t%s\t%s\n' "$label" "${hit:0:80}" "$url" >> "$JS_SECRETS"; done \
        < <(grep -aoE "$regex" "$jsbody" 2>/dev/null | sort -u)
    done
    while IFS= read -r hit; do
      [ -n "$hit" ] || continue
      # keep only high-entropy quoted values (rejects identifiers/dictionary words)
      val=$(printf '%s' "$hit" | sed -E "s/.*[:=][[:space:]]*[\"']//; s/[\"'].*$//")
      _entropy_ok "$val" && printf '%s\t%s\t%s\n' "Generic key=value (entropy)" "${hit:0:80}" "$url" >> "$JS_SECRETS"
    done < <(grep -aoiE "$SECRET_GENERIC" "$jsbody" 2>/dev/null | sort -u)
  done < "$JSLIVE"
  rm -f "$jsbody"
  # dedup endpoints and drop static-asset noise
  if [ -s "$JS_ENDPOINTS" ]; then
    grep -ivE '\.(png|jpe?g|gif|svg|css|woff2?|ttf|ico|map|webp|mp4)$' "$JS_ENDPOINTS" | sort -u > "$JS_ENDPOINTS.tmp" && mv "$JS_ENDPOINTS.tmp" "$JS_ENDPOINTS"
  fi
  [ -s "$JS_SECRETS" ] && sort -u -o "$JS_SECRETS" "$JS_SECRETS"
  local analyzed=$(( count > max ? max : count ))
  ok "js: analyzed $analyzed app JS, skipped $skipped library file(s); $(cnt "$JS_ENDPOINTS") endpoints, $(cnt "$JS_SECRETS") potential secret(s)"
}

# reformat nuclei's JSON progress line into a readable one (drops the bogus overflow
# 'percent'); any non-stats line is passed through unchanged.
_nstats(){
  awk '
    /"duration"/ {
      d=r=e=m=""
      if (match($0,/"duration":"[^"]*"/)) { t=substr($0,RSTART,RLENGTH); gsub(/"duration":"|"/,"",t); d=t }
      if (match($0,/"requests":"[^"]*"/)) { t=substr($0,RSTART,RLENGTH); gsub(/"requests":"|"/,"",t); r=t }
      if (match($0,/"errors":"[^"]*"/))   { t=substr($0,RSTART,RLENGTH); gsub(/"errors":"|"/,"",t);   e=t }
      if (match($0,/"matched":"[^"]*"/))  { t=substr($0,RSTART,RLENGTH); gsub(/"matched":"|"/,"",t);  m=t }
      printf "[*]     nuclei: %s elapsed | %s reqs | %s errors | %s matched\n", d, r, e, m; fflush(); next
    }
    { print; fflush() }
  '
}

# Build the nuclei target list = live hosts MINUS CDN/WAF-fronted ones. Scanning a
# CDN/WAF edge only hits the edge (and trips its WAF, blocking us); the reachable origins
# are what's worth scanning. Uses the CDN_IPS set already computed by port_discovery.
NUCLEI_EXCLUDED_CDN=0
build_nuclei_targets(){
  NUCLEI_EXCLUDED_CDN=0
  if [ ! -s "$CDN_IPS" ]; then cp "$LIVE" "$NUCLEI_TARGETS" 2>/dev/null || : > "$NUCLEI_TARGETS"; return; fi
  local hostsfile="$OUTDIR/.live_hosts.tmp" mapf="$OUTDIR/.host_ip.tmp" cdnhosts="$OUTDIR/.cdn_hosts.tmp"
  sed -E 's#^https?://##; s#[/:].*$##' "$LIVE" | sort -u > "$hostsfile"
  : > "$mapf"
  if have dnsx; then
    dnsx -l "$hostsfile" -a -resp -silent 2>/dev/null | sed 's/[][]//g' > "$mapf" || true   # "host ip"
  else
    while read -r h; do getent hosts "$h" 2>/dev/null | awk -v H="$h" '{print H" "$1}'; done < "$hostsfile" > "$mapf"
  fi
  while read -r h ip; do [ -n "$ip" ] && grep -qxF "$ip" "$CDN_IPS" && echo "$h"; done < "$mapf" | sort -u > "$cdnhosts"
  : > "$NUCLEI_TARGETS"
  local url host
  while read -r url; do
    [ -n "$url" ] || continue
    host=$(printf '%s' "$url" | sed -E 's#^https?://##; s#[/:].*$##')
    if grep -qxF "$host" "$cdnhosts" 2>/dev/null \
       || { printf '%s' "$host" | grep -qE '^[0-9.]+$' && grep -qxF "$host" "$CDN_IPS"; }; then
      NUCLEI_EXCLUDED_CDN=$((NUCLEI_EXCLUDED_CDN+1))
    else
      echo "$url" >> "$NUCLEI_TARGETS"
    fi
  done < "$LIVE"
  rm -f "$hostsfile" "$mapf" "$cdnhosts"
}

# ---- block-oracle: detect WAF/rate-limit/IP-block during the scan ----
_oracle_url=""; _oracle_code=""
block_oracle_init(){
  # Prefer a hostname-based URL over a bare IP:port (raw CloudFront/CDN IPs answer 403 to
  # any host and make a weak oracle). Draw from the nuclei target list (CDN already removed).
  local src="${SCANLIST:-$LIVE}"
  _oracle_url=$(grep -ivE '://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:|/|$)' "$src" 2>/dev/null | head -n1)
  [ -n "$_oracle_url" ] || _oracle_url=$(head -n1 "$src" 2>/dev/null)
  [ -n "$_oracle_url" ] || return 0
  _oracle_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -A "Mozilla/5.0" "$_oracle_url" 2>/dev/null)
  log "nuclei: block-oracle baseline $_oracle_url -> HTTP ${_oracle_code:-000}"
}
is_blocked(){
  [ -n "$_oracle_url" ] || return 1              # no oracle -> never report blocked
  local code; code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -A "Mozilla/5.0" "$_oracle_url" 2>/dev/null)
  case "$code" in
    000|429|503) return 0;;                      # connection killed / rate-limited / unavailable
    403) [ "$_oracle_code" != "403" ] && return 0 || return 1;;  # newly 403 = WAF block
    *) return 1;;
  esac
}

# ---------- 8. CVE ----------
cve_scan(){
  [ "$DO_NUCLEI" -eq 1 ] || { log "nuclei: skipped"; return; }
  have nuclei || { warn "nuclei missing"; return; }
  [ -s "$LIVE" ] || { warn "nuclei: no live hosts"; return; }
  : > "$NUCLEI"
  # Drop CDN/WAF-fronted hosts: scanning them only hits the edge WAF and gets us blocked.
  build_nuclei_targets
  SCANLIST="$NUCLEI_TARGETS"
  local nhosts; nhosts=$(cnt "$SCANLIST")
  [ "$NUCLEI_EXCLUDED_CDN" -gt 0 ] && warn "nuclei: excluded $NUCLEI_EXCLUDED_CDN CDN/WAF-fronted host(s) — scanning only reachable origins"
  if [ "$nhosts" -eq 0 ]; then
    warn "nuclei: SKIPPED — all $(cnt "$LIVE") live host(s) are behind a CDN/WAF, so there is no"
    warn "  directly-scannable origin from here. nuclei would only hit the WAF edge."
    warn "  To scan the real origins you need their origin IPs or a client WAF allowlist."
    return
  fi
  # Two depths, selected by --nuclei-full:
  #  fast (default): -automatic-scan — nuclei fingerprints each host and runs only the
  #    templates matching its tech stack. Quick, low-noise, maps CVEs to the stack.
  #  full: curated-broad — every meaningful category (cve/vuln/exposure/misconfig/
  #    default-login/takeover) at low->critical, EXCLUDING dos/intrusive/fuzz and info
  #    noise. Much more coverage, much slower/louder. For exhaustive per-target work,
  #    prefer nuclei-scan.sh (payload capture).
  # Build the base command WITHOUT -l/-o (each batch adds its own). Block-aware: the
  # host list is scanned in batches of $NUCLEI_BATCH; between batches a benign request to
  # a known-good URL checks whether we've been blocked (403/429/503/conn-reset), and if so
  # backs off exponentially — stopping after 3 strikes rather than burning the source IP.
  local base=(nuclei -jsonl -no-color -silent
             -etags dos,intrusive,fuzz -severity low,medium,high,critical
             -rate-limit "$NUCLEI_RL" -timeout 10 -stats -stats-interval 20)
  if [ "$NUCLEI_MODE" = "full" ]; then
    log "nuclei: FULL curated-broad on $nhosts host(s), rate ${NUCLEI_RL}/s, batch $NUCLEI_BATCH, block-aware"
    base+=(-tags cve,vuln,vulnerability,exposure,exposures,misconfig,misconfiguration,default-login,takeover)
  else
    log "nuclei: tech-aware automatic-scan on $nhosts host(s), rate ${NUCLEI_RL}/s, batch $NUCLEI_BATCH, block-aware"
    base+=(-automatic-scan)
  fi
  [ "$STEALTH" -eq 1 ] && log "nuclei: STEALTH mode — very low rate + long back-off"
  log "nuclei: progress every 20s; block-oracle checked between batches; Ctrl+C keeps partial results"

  block_oracle_init
  local batchdir="$OUTDIR/.nbatch"; rm -rf "$batchdir"; mkdir -p "$batchdir"
  split -l "$NUCLEI_BATCH" "$SCANLIST" "$batchdir/b." 2>/dev/null || cp "$SCANLIST" "$batchdir/b.aa"
  local total i=0 consec=0 delay bf bout
  total=$(ls "$batchdir"/b.* 2>/dev/null | wc -l | tr -d ' ')
  if [ "$STEALTH" -eq 1 ]; then delay=30; else delay=5; fi
  for bf in "$batchdir"/b.*; do
    i=$((i+1)); log "nuclei: batch $i/$total ($(cnt "$bf") host(s))"
    bout="$bf.jsonl"; local full=("${base[@]}" -l "$bf" -o "$bout")
    if [ -n "${NUCLEI_MAXTIME:-}" ] && have timeout; then
      timeout "$NUCLEI_MAXTIME" "${full[@]}" 2> >(_nstats >&2) || true
    else
      "${full[@]}" 2> >(_nstats >&2) || true
    fi
    [ -f "$bout" ] && cat "$bout" >> "$NUCLEI"
    if is_blocked; then
      consec=$((consec+1))
      warn "nuclei: block-oracle tripped after batch $i (strike $consec/3) — backing off ${delay}s"
      sleep "$delay"; delay=$((delay*2))
      if [ "$consec" -ge 3 ]; then
        NUCLEI_WAF_STOPPED=1
        warn "===================================================================="
        warn "nuclei STOPPED: target appears WAF/CDN-protected — the block-oracle"
        warn "  ($_oracle_url) kept returning block responses (403/429/503/reset)"
        warn "  across 3 back-offs. Scanning further would only burn the source IP."
        warn "  Fixes: wait, re-run with --stealth, rotate egress (nuclei -proxy /"
        warn "  proxychains), or get the client to allowlist your IP / give origin IPs."
        warn "  Partial results kept in $NUCLEI."
        warn "===================================================================="
        break
      fi
    else
      consec=0; if [ "$STEALTH" -eq 1 ]; then delay=30; else delay=5; fi
    fi
  done
  rm -rf "$batchdir"
  if [ "${NUCLEI_WAF_STOPPED:-0}" -eq 1 ]; then
    ok "nuclei: $(cnt "$NUCLEI") findings (scan STOPPED EARLY — WAF/CDN block) -> $NUCLEI"
  else
    ok "nuclei: $(cnt "$NUCLEI") findings -> $NUCLEI"
  fi
}

# ---------- 8b. version -> CVE mapping (NVD) ----------
# httpx fingerprints versioned tech as "Product:Version" (e.g. "Bootstrap:2.5.0"). This maps
# each unique product+version to KNOWN CVEs from the NVD API — so a detected version is flagged
# with its public CVEs even when no live nuclei template fired. These are CANDIDATES to verify,
# not confirmed hits. NVD rate-limits (~5 req/30s unauth; set NVD_API_KEY for ~50/30s).
_nvd_lookup(){  # $1=product $2=version -> prints "CVE-xxxx|CVSS|severity|desc" lines
  local product="$1" version="$2" url resp hdr=()
  url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$(printf '%s %s' "$product" "$version" | sed 's/ /%20/g')&keywordExactMatch=&resultsPerPage=12"
  [ -n "${NVD_API_KEY:-}" ] && hdr=(-H "apiKey: $NVD_API_KEY")
  resp=$(curl -s --max-time 30 "${hdr[@]}" "$url" 2>/dev/null)
  printf '%s' "$resp" | jq -r '
    .vulnerabilities[]? | .cve |
    (.id) + "|" +
    (( .metrics.cvssMetricV31[0].cvssData.baseScore // .metrics.cvssMetricV30[0].cvssData.baseScore // .metrics.cvssMetricV2[0].cvssData.baseScore // 0)|tostring) + "|" +
    ( .metrics.cvssMetricV31[0].cvssData.baseSeverity // .metrics.cvssMetricV30[0].cvssData.baseSeverity // "UNKNOWN") + "|" +
    ((.descriptions[]? | select(.lang=="en") | .value) // "" | gsub("[\\t\\n]";" ") | .[0:160])' 2>/dev/null | head -12
}
version_cve_map(){
  [ "$DO_CVEMAP" -eq 1 ] || { log "cve-map: skipped (--no-cvemap)"; return; }
  [ -s "$HTTPXJSON" ] || return
  # unique "Product:Version" pairs from the fingerprint (only tech that carries a version)
  local pv; pv=$(jq -r '.tech[]? // empty' "$HTTPXJSON" 2>/dev/null \
                 | grep -E ':[0-9]' | sort -u)
  [ -n "$pv" ] || { log "cve-map: no versioned tech in fingerprint — nothing to map"; return; }
  : > "$VERSION_CVES"
  local npv; npv=$(printf '%s\n' "$pv" | grep -c .)
  local max=${CVEMAP_MAX:-30} delay; [ -n "${NVD_API_KEY:-}" ] && delay=1 || delay=7
  log "cve-map: looking up CVEs for $npv versioned product(s) via NVD (cap $max, ~${delay}s each)"
  [ -n "${NVD_API_KEY:-}" ] || warn "cve-map: no NVD_API_KEY set — NVD is slow/rate-limited; set it to speed up"
  local count=0 item product version hosts line
  while IFS= read -r item; do
    [ -n "$item" ] || continue
    count=$((count+1)); if [ "$count" -gt "$max" ]; then warn "cve-map: reached CVEMAP_MAX=$max (raise with CVEMAP_MAX=N)"; break; fi
    product="${item%%:*}"; version="${item##*:}"
    # which hosts expose this product:version?
    hosts=$(jq -r --arg t "$item" 'select((.tech[]? // "")==$t) | .url' "$HTTPXJSON" 2>/dev/null | sort -u | tr '\n' ' ')
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      printf '%s\t%s\t%s\n' "$item" "$line" "${hosts% }" >> "$VERSION_CVES"
    done < <(_nvd_lookup "$product" "$version")
    sleep "$delay"
  done <<< "$pv"
  ok "cve-map: $(cnt "$VERSION_CVES") version-CVE candidate(s) -> $VERSION_CVES"
}

# grep -c prints "0" AND exits 1 on no match, which would fire a trailing "|| echo 0"
# and yield a two-line "0\n0". Capture stdout instead so the count is one integer.
cnt(){ if [ -f "$1" ]; then local n; n=$(grep -cvE '^[[:space:]]*$|^\(no' "$1" 2>/dev/null); echo "${n:-0}"; else echo 0; fi; }
sev_count(){ if [ -f "$NUCLEI" ]; then local n; n=$(grep -c "\"severity\":\"$1\"" "$NUCLEI" 2>/dev/null); echo "${n:-0}"; else echo 0; fi; }

# normalize a URL/host string to a bare hostname for joining the two data sources
_host_of(){ printf '%s' "$1" | sed -E 's#^https?://##; s#[/:].*$##'; }

# Per-host join: detected tech (httpx) <-> CVEs found on that host (nuclei).
emit_tech_cve(){
  echo '<h2>Tech &rarr; CVE correlation <span class="muted">(CVEs mapped to each host'"'"'s detected stack)</span></h2>'
  if [ ! -s "$HTTPXJSON" ]; then echo '<div class="empty">No fingerprint data (httpx produced nothing).</div>'; return; fi
  declare -A FIND
  if [ -s "$NUCLEI" ]; then
    while IFS=$'\t' read -r host sev label; do
      [ -n "$host" ] || continue
      local r; case "$sev" in critical) r=4;; high) r=3;; medium) r=2;; low) r=1;; *) r=0;; esac
      FIND["$host"]+="${r}|${sev}|${label}"$'\n'
    done < <(jq -r '[((.matched_at//.host//"")|sub("^https?://";"")|sub("[/:].*$";"")),
                     (.info.severity//"info"),
                     (if (.info.classification."cve-id"//[])|length>0 then (.info.classification."cve-id"|join(", "))
                      else (.["template-id"]//"?") end)] | @tsv' "$NUCLEI" 2>/dev/null)
  fi
  echo '<table><tr><th>Host</th><th>Detected tech / server</th><th>CVEs / findings</th></tr>'
  while IFS=$'\t' read -r hostname url tech server; do
    [ -n "$hostname" ] || continue
    local techcell cves
    techcell="$(printf '%s' "${tech:--}" | esc)"
    [ -n "$server" ] && [ "$server" != "-" ] && techcell="$techcell <span class=\"muted\">($(printf '%s' "$server"|esc))</span>"
    cves=""
    if [ -n "${FIND[$hostname]:-}" ]; then
      while IFS='|' read -r _r sev label; do
        [ -n "$label" ] || continue
        cves+="<span class=\"pill ${sev}\">${sev}</span> $(printf '%s' "$label"|esc)<br>"
      done < <(printf '%s' "${FIND[$hostname]}" | awk 'NF' | sort -t'|' -k1,1rn -u)
    fi
    [ -n "$cves" ] || cves='<span class="muted">no findings</span>'
    echo "<tr><td><a href=\"$url\">$(printf '%s' "$hostname"|esc)</a></td><td>${techcell:--}</td><td>${cves}</td></tr>"
  done < <(jq -r '[(.url|sub("^https?://";"")|sub("[/:].*$";"")), .url, ((.tech//[])|join(", ")), (.webserver//"-")] | @tsv' "$HTTPXJSON" 2>/dev/null)
  echo '</table>'
}

# ---------- 9. analysis + report ----------
build_report(){
  log "analysis + report"
  local now; now=$(date '+%Y-%m-%d %H:%M:%S %Z')
  local n_all n_live n_out n_hi n_params n_juicy n_juicylive n_js n_jslive n_gh c_crit c_high c_med c_low
  n_all=$(cnt "$ALLHOSTS"); n_live=$(cnt "$LIVE"); n_out=$(cnt "$OUTSCOPE"); n_hi=$(cnt "$HIGHINT")
  n_params=$(cnt "$PARAMS"); n_juicy=$(cnt "$JUICY"); n_juicylive=$(cnt "$JUICYLIVE")
  n_js=$(cnt "$JSFILES"); n_jslive=$(cnt "$JSLIVE"); n_gh=$(cnt "$GHSECRETS")
  local n_vcve_crit=0 n_vcve_high=0
  if [ -s "$VERSION_CVES" ]; then
    n_vcve_crit=$(grep -c '|CRITICAL|' "$VERSION_CVES" 2>/dev/null); n_vcve_crit=${n_vcve_crit:-0}
    n_vcve_high=$(grep -c '|HIGH|' "$VERSION_CVES" 2>/dev/null); n_vcve_high=${n_vcve_high:-0}
  fi
  local n_nsevuln=0
  [ -s "$NSE_VULN" ] && { n_nsevuln=$(grep -c 'VULNERABLE' "$NSE_VULN" 2>/dev/null); n_nsevuln=${n_nsevuln:-0}; }
  local n_wp; n_wp=$(cnt "$WP_SITES")
  n_jssec=$(cnt "$JS_SECRETS"); n_jsend=$(cnt "$JS_ENDPOINTS")
  c_crit=$(sev_count critical); c_high=$(sev_count high); c_med=$(sev_count medium); c_low=$(sev_count low)
  local b_sqli b_ssrf b_lfi b_rce b_redir b_ssti
  b_sqli=$(cnt "$BK/sqli.txt"); b_ssrf=$(cnt "$BK/ssrf.txt"); b_lfi=$(cnt "$BK/lfi.txt")
  b_rce=$(cnt "$BK/rce.txt"); b_redir=$(cnt "$BK/redirect.txt"); b_ssti=$(cnt "$BK/ssti.txt")

  # plain-text analysis for CLI
  { echo "=== RECON ANALYSIS: $TARGET ($now) ==="
    echo "Attack surface: $n_all discovered, $n_live live in-scope, $n_out out-of-scope (not probed)"
    echo "Priorities:"
    [ "$n_gh" -gt 0 ]        && echo "  [P1] $n_gh leaked secret(s) in public GitHub — validate & rotate"
    [ "$n_jssec" -gt 0 ]     && echo "  [P1] $n_jssec secret(s)/key(s) in live JavaScript — verify now"
    [ "$n_juicylive" -gt 0 ] && echo "  [P1] $n_juicylive archived sensitive file(s) still LIVE — inspect now"
    [ "$c_crit" -gt 0 ]      && echo "  [P1] $c_crit CRITICAL nuclei finding(s)"
    [ "$c_high" -gt 0 ]      && echo "  [P1] $c_high HIGH nuclei finding(s)"
    [ "$n_hi" -gt 0 ]        && echo "  [P2] $n_hi high-interest host(s) (admin/api/dev/staging/etc.)"
    [ "$c_med" -gt 0 ]       && echo "  [P2] $c_med MEDIUM nuclei finding(s)"
    [ "$b_rce" -gt 0 ]       && echo "  [P2] $b_rce RCE-candidate param URL(s)"
    [ "$b_ssrf" -gt 0 ]      && echo "  [P2] $b_ssrf SSRF-candidate param URL(s)"
    [ "$b_sqli" -gt 0 ]      && echo "  [P3] $b_sqli SQLi-candidate param URL(s)"
    [ "$b_lfi" -gt 0 ]       && echo "  [P3] $b_lfi LFI-candidate param URL(s)"
    [ "$b_redir" -gt 0 ]     && echo "  [P3] $b_redir open-redirect-candidate param URL(s)"
  } > "$ANALYSIS"
  cat "$ANALYSIS" >&2

  callout(){ # $1 pri(p1/p2/p3) $2 count $3 text $4 next
    [ "$2" -gt 0 ] || return
    echo "<div class=\"co $1\"><span class=\"tag\">${1^^}</span><b>$2</b> $3<div class=\"next\">$4</div></div>"
  }
  emit_details(){ # $1 title $2 file $3 class
    local n=0; [ -f "$2" ] && n=$(cnt "$2")
    echo "<details class=\"find\"><summary><span class=\"name\">$1</span><span class=\"meta\">$n</span></summary><div class=\"body\"><pre>"
    if [ "$n" -gt 0 ]; then head -n 300 "$2" | esc; [ "$n" -gt 300 ] && echo "... (truncated — full list in $(basename "$2"))"; else echo "(none)"; fi
    echo "</pre></div></details>"
  }

  {
  cat <<HTML
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Recon Report — ${TARGET}</title><style>
:root{--bg:#0f1115;--card:#1a1d24;--line:#2a2f3a;--fg:#e6e8ec;--mut:#8b93a1;--crit:#ff4d4f;--high:#ff8c42;--med:#ffd166;--low:#4dabf7;--ok:#51cf66;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;padding:24px 16px}
h1{font-size:22px;margin:0 0 2px}h2{font-size:16px;margin:28px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
.sub{color:var(--mut);margin-bottom:18px}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin:12px 0 8px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;min-width:96px}
.card .n{font-size:22px;font-weight:700}.card .l{color:var(--mut);font-size:11px}
.co{background:var(--card);border:1px solid var(--line);border-left-width:4px;border-radius:8px;padding:10px 12px;margin:8px 0}
.co.p1{border-left-color:var(--crit)}.co.p2{border-left-color:var(--high)}.co.p3{border-left-color:var(--low)}
.co .tag{display:inline-block;font-size:10px;font-weight:700;padding:1px 7px;border-radius:999px;margin-right:8px;color:#0f1115}
.co.p1 .tag{background:var(--crit)}.co.p2 .tag{background:var(--high)}.co.p3 .tag{background:var(--low)}
.co .next{color:var(--mut);font-size:12px;margin-top:3px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}
th{background:#20242d;color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase}
tr:last-child td{border-bottom:none}
.find{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:8px 0;overflow:hidden}
.find>summary{cursor:pointer;padding:10px 12px;display:flex;justify-content:space-between;gap:10px}
.name{font-weight:600}.meta{color:var(--mut)}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700;color:#0f1115}
.critical{background:var(--crit)}.high{background:var(--high)}.medium{background:var(--med)}.low{background:var(--low)}
pre{background:#0b0d11;border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;max-height:360px;font:12px/1.45 ui-monospace,Consolas,monospace;white-space:pre-wrap;word-break:break-word;margin:0}
code{background:#20242d;padding:1px 5px;border-radius:4px}a{color:var(--low)}.empty{color:var(--mut);font-style:italic;padding:8px}.muted{color:var(--mut)}
</style></head><body>
<h1>Recon Report — ${TARGET}</h1>
<div class="sub">Generated ${now} · all-in-one recon with prioritized analysis · out-of-scope hosts listed but never probed</div>
<div class="cards">
<div class="card"><div class="n">${n_all}</div><div class="l">discovered</div></div>
<div class="card"><div class="n">${n_live}</div><div class="l">live in-scope</div></div>
<div class="card"><div class="n">${n_hi}</div><div class="l">high-interest</div></div>
<div class="card"><div class="n">${n_params}</div><div class="l">param URLs</div></div>
<div class="card"><div class="n" style="color:var(--high)">${n_juicylive}</div><div class="l">juicy LIVE</div></div>
<div class="card"><div class="n" style="color:var(--crit)">$((c_crit+c_high))</div><div class="l">crit+high CVE</div></div>
<div class="card"><div class="n" style="color:var(--high)">${n_gh}</div><div class="l">secrets</div></div>
<div class="card"><div class="n">${n_out}</div><div class="l">out-of-scope</div></div>
</div>
<h2>Attack-surface analysis — what to look at first</h2>
HTML

  out=""
  out+=$(callout p1 "$n_gh" "leaked secret(s) in public GitHub code" "Validate each, test against live auth, report for rotation.")
  out+=$(callout p1 "$n_jssec" "secret(s)/key(s) extracted from live JavaScript" "Verify each — JS-embedded keys are often live API/cloud/3rd-party creds.")
  out+=$(callout p1 "$n_vcve_crit" "CRITICAL CVE(s) for detected software versions (NVD)" "Confirm the version/patch-level, then test the specific CVE.")
  out+=$(callout p2 "$n_vcve_high" "HIGH CVE(s) for detected software versions (NVD)" "Verify applicability against the real build before reporting.")
  out+=$(callout p2 "$n_nsevuln" "service-level VULNERABLE finding(s) on non-web ports (nmap NSE)" "TLS/SMB/service vulns nuclei can't see — confirm each against the service.")
  out+=$(callout p2 "$n_wp" "WordPress site(s) detected" "wpscan runs automatically (users/plugins/vulns) — see the WordPress section for output + a ready-to-run command per site.")
  out+=$(callout p1 "$n_juicylive" "archived sensitive file(s) still returning a live response" "Fetch each — .env/.sql/.bak/.config often contain creds or source.")
  out+=$(callout p1 "$c_crit" "CRITICAL CVE/misconfig finding(s) from nuclei" "Triage immediately; confirm with the deep nuclei-scan for payloads.")
  out+=$(callout p1 "$c_high" "HIGH CVE/misconfig finding(s)" "Confirm and prioritize ahead of manual testing.")
  out+=$(callout p2 "$n_hi" "high-interest live host(s) — admin/api/dev/staging/jenkins/git/etc." "Map these first; non-prod and admin surfaces are the softest targets.")
  out+=$(callout p2 "$c_med" "MEDIUM nuclei finding(s)" "Review after P1 items.")
  out+=$(callout p2 "$b_rce" "RCE-candidate parameter URL(s) from archive" "Manually test for command injection / deserialization.")
  out+=$(callout p2 "$b_ssrf" "SSRF-candidate parameter URL(s)" "Test with an OOB/interactsh payload.")
  out+=$(callout p3 "$b_sqli" "SQLi-candidate parameter URL(s)" "Probe with error/boolean/time payloads or sqlmap (in scope).")
  out+=$(callout p3 "$b_lfi" "LFI/path-candidate parameter URL(s)" "Test path traversal / file disclosure.")
  out+=$(callout p3 "$b_redir" "open-redirect-candidate parameter URL(s)" "Test redirect to external host.")
  out+=$(callout p3 "$n_jsend" "endpoint(s)/path(s) extracted from live JavaScript" "Feed to content discovery / test for access-control & hidden APIs.")
  if [ -n "$out" ]; then echo "$out"; else echo '<div class="empty">No prioritized call-outs — thin surface or tools unavailable.</div>'; fi

  # live hosts + tech
  echo '<h2>Live hosts &amp; tech stack</h2>'
  if [ -s "$HTTPXJSON" ]; then
    echo '<table><tr><th>URL</th><th>Status</th><th>Server</th><th>Tech</th><th>Title</th></tr>'
    jq -r '"<tr><td><a href=\""+(.url)+"\">"+(.url|@html)+"</a></td><td>"+((.status_code//0)|tostring)+"</td><td>"+((.webserver//"-")|@html)+"</td><td>"+(((.tech//[])|join(", "))|if .=="" then "-" else . end|@html)+"</td><td>"+((.title//"-")|@html)+"</td></tr>"' "$HTTPXJSON" 2>/dev/null
    echo '</table>'
  elif [ -s "$LIVE" ]; then echo '<table><tr><th>URL</th></tr>'; while read -r u; do echo "<tr><td><a href=\"$u\">$u</a></td></tr>"; done < "$LIVE"; echo '</table>'
  else echo '<div class="empty">No live hosts.</div>'; fi

  echo '<h2>High-interest hosts</h2>'; emit_details "admin / api / dev / staging / infra surfaces" "$HIGHINT"

  echo '<h2>Open ports &amp; services <span class="muted">(port discovery)</span></h2>'
  if [ -s "$PORTS" ] || [ -s "$WEBSVC" ]; then
    emit_details "Web services on non-standard ports (merged into live set)" "$WEBSVC"
    emit_details "All open ip:port" "$PORTS"
    [ -s "$CDN_IPS" ] && emit_details "CDN IPs (NOT port-scanned)" "$CDN_IPS"
  else
    echo '<div class="empty">No extra ports discovered (or port discovery skipped/unavailable).</div>'
  fi

  if [ -s "$WP_SITES" ]; then
    echo '<h2>WordPress sites <span class="muted">(run wpscan for users/plugins/vulns)</span></h2>'
    echo '<table><tr><th>Site</th><th>Ready-to-run wpscan</th></tr>'
    while read -r u; do
      [ -n "$u" ] || continue
      echo "<tr><td><a href=\"$u\">$(printf '%s' "$u"|esc)</a></td><td><code>wpscan --url $(printf '%s' "$u"|esc) --enumerate u,vp,vt --random-user-agent</code></td></tr>"
    done < "$WP_SITES"
    echo '</table>'
    [ -s "$WPSCAN_OUT" ] && emit_details "wpscan output" "$WPSCAN_OUT"
  fi

  if [ -s "$NSE_VULN" ]; then
    echo '<h2>Service-level vulnerabilities <span class="muted">(nmap NSE, non-web ports)</span></h2>'
    local nv; nv=$(grep -c 'VULNERABLE' "$NSE_VULN" 2>/dev/null); nv=${nv:-0}
    echo "<p class=\"why\">$nv <b>VULNERABLE</b> marker(s). TLS/SMB/service checks (nuclei covers HTTP). Verify each.</p>"
    emit_details "nmap vuln NSE output" "$NSE_VULN"
  fi

  echo '<h2>Wayback triage</h2>'
  emit_details "Archived sensitive files — STILL LIVE" "$JUICYLIVE"
  emit_details "Archived sensitive files — all (historical)" "$JUICY"
  emit_details "Live JS files" "$JSLIVE"

  # --- JavaScript analysis: secrets (table) + endpoints (list) ---
  echo '<h2>JavaScript analysis <span class="muted">(endpoints &amp; secrets from live JS)</span></h2>'
  if [ -s "$JS_SECRETS" ]; then
    echo '<h3 style="margin:8px 0 4px;color:var(--high)">Potential secrets / keys</h3>'
    echo '<table><tr><th>Type</th><th>Match</th><th>Source JS</th></tr>'
    while IFS=$'\t' read -r stype smatch surl; do
      [ -n "$stype" ] || continue
      echo "<tr><td><span class=\"pill high\">$(printf '%s' "$stype"|esc)</span></td><td><code>$(printf '%s' "$smatch"|esc)</code></td><td><a href=\"$surl\">$(printf '%s' "$surl"|esc)</a></td></tr>"
    done < "$JS_SECRETS"
    echo '</table>'
    echo '<p class="why">Regex-extracted — verify each (some may be public keys or false positives).</p>'
  else
    echo '<div class="empty">No secrets matched in live JS.</div>'
  fi
  emit_details "Endpoints &amp; paths extracted from JS" "$JS_ENDPOINTS"
  emit_details "SQLi-candidate parameter URLs" "$BK/sqli.txt"
  emit_details "SSRF-candidate parameter URLs" "$BK/ssrf.txt"
  emit_details "LFI-candidate parameter URLs" "$BK/lfi.txt"
  emit_details "RCE-candidate parameter URLs" "$BK/rce.txt"
  emit_details "Open-redirect-candidate parameter URLs" "$BK/redirect.txt"
  emit_details "SSTI-candidate parameter URLs" "$BK/ssti.txt"

  echo '<h2>CVE &amp; misconfiguration findings</h2>'
  if [ -s "$NUCLEI" ]; then
    echo '<table><tr><th>Severity</th><th>Finding</th><th>Matched</th></tr>'
    jq -rs 'def rank: {critical:4,high:3,medium:2,low:1,info:0}[.]//0; sort_by(.info.severity|rank)|reverse|.[]|"<tr><td><span class=\"pill "+(.info.severity//"info")+"\">"+(.info.severity//"info")+"</span></td><td><b>"+((.info.name//"?")|@html)+"</b><br><code>"+((.["template-id"]//"?")|@html)+"</code></td><td>"+((.matched_at//.host//"-")|@html)+"</td></tr>"' "$NUCLEI" 2>/dev/null
    echo '</table>'
  else echo '<div class="empty">No nuclei findings (run nuclei-scan.sh for deep, payload-capturing scan).</div>'; fi

  emit_tech_cve

  echo '<h2>Known CVEs for detected software versions <span class="muted">(NVD — candidates to verify)</span></h2>'
  if [ -s "$VERSION_CVES" ]; then
    echo '<table><tr><th>Product : Version</th><th>CVE</th><th>CVSS</th><th>Hosts</th><th>Summary</th></tr>'
    # sort by CVSS desc (field2 after splitting the CVE|CVSS|sev|desc column)
    while IFS=$'\t' read -r item cvecol hosts; do
      [ -n "$item" ] || continue
      local cve cvss sev desc rest
      cve="${cvecol%%|*}"; rest="${cvecol#*|}"; cvss="${rest%%|*}"; rest="${rest#*|}"; sev="${rest%%|*}"; desc="${rest#*|}"
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$cvss" "$item" "$cve" "$sev" "$hosts" "$desc"
    done < "$VERSION_CVES" | sort -t$'\t' -k1,1 -rn | while IFS=$'\t' read -r cvss item cve sev hosts desc; do
      local cls=low; case "$sev" in CRITICAL) cls=critical;; HIGH) cls=high;; MEDIUM) cls=medium;; esac
      echo "<tr><td><code>$(printf '%s' "$item"|esc)</code></td><td><a href=\"https://nvd.nist.gov/vuln/detail/${cve}\">${cve}</a></td><td><span class=\"pill ${cls}\">${cvss} ${sev}</span></td><td class=\"muted\">$(printf '%s' "$hosts"|esc)</td><td>$(printf '%s' "$desc"|esc)</td></tr>"
    done
    echo '</table>'
    echo '<p class="why">Matched by product+version keyword against NVD — verify each applies to the actual build (patch levels/backports can differ).</p>'
  else
    echo '<div class="empty">No version→CVE candidates (no versioned tech detected, or lookup skipped/unavailable).</div>'
  fi

  echo '<h2>Leaked secrets (public GitHub)</h2>'
  if [ -s "$GHSECRETS" ] && ! grep -q '^(no' "$GHSECRETS"; then
    echo '<table><tr><th>Hit</th></tr>'; while IFS= read -r l; do echo "<tr><td><code>$(printf '%s' "$l"|esc)</code></td></tr>"; done < "$GHSECRETS"; echo '</table>'
  else echo '<div class="empty">No verified secrets (or scan skipped).</div>'; fi

  echo '<h2>Discovered but out of scope <span class="muted">(not probed)</span></h2>'
  if [ -s "$OUTSCOPE" ]; then emit_details "out-of-scope hosts" "$OUTSCOPE"; else echo '<div class="empty">None.</div>'; fi
  echo '</body></html>'
  } > "$REPORT"
  ok "report -> $REPORT"
}

# ---------- run ----------
# Always produce a report — even on error or Ctrl+C. Whatever was collected so far
# (including partial nuclei findings streamed to disk) is rendered on exit.
_FINISHED=0
finish(){
  [ "$_FINISHED" -eq 1 ] && return 0
  _FINISHED=1
  build_report || warn "report generation hit an error"
  ok "DONE. open $REPORT  (text summary: $ANALYSIS)"
}
trap finish EXIT

log "target=$TARGET  outdir=$OUTDIR"
passive_subdomains
wayback
wayback_triage
github_secrets
if scope_filter; then
  live_and_fingerprint
  port_discovery
  nmap_vuln_scan
  wordpress_phase
  check_archived
  analyze_js
  cve_scan
  version_cve_map
fi
# build_report is invoked by the EXIT trap (finish), so it runs on normal completion,
# on an error, and on Ctrl+C alike.
