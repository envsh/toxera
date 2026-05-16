#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
#  fetch_seeds.sh - Download latest Tor consensus, I2P reseed & Yggdrasil peer seeds
#  Usage:
#    ./fetch_seeds.sh            # download all (default)
#    ./fetch_seeds.sh -all       # download all
#    ./fetch_seeds.sh -i2p       # I2P only
#    ./fetch_seeds.sh -tor       # Tor only
#    ./fetch_seeds.sh -yggdrasil # Yggdrasil only
#    ./fetch_seeds.sh -o DIR     # output directory (default: ./seed_data)
#    ./fetch_seeds.sh -h         # help
# ═══════════════════════════════════════════════════════════════════════════════

readonly VERSION="1.1.0"
readonly SCRIPT="$(basename "$0")"

# ── Defaults ──────────────────────────────────────────────────────────────────
MODE="all"             # all | i2p | tor | yggdrasil
OUTDIR="$(pwd)/seed_data"
TMPDIR=""

# ── I2P Reseed Servers (from I2P source DEFAULT_SSL_SEED_URL, 2026) ──────────
I2P_RESEEDS=(
  "https://reseed.sahil.world"
  "https://i2p.diyarciftci.xyz"
  "https://coconut.incognet.io"
  "https://reseed.stormycloud.org"
  "https://reseed-pl.i2pd.xyz"
  "https://reseed-fr.i2pd.xyz"
  "https://www2.mk16.de"
  "https://reseed2.i2p.net"
  "https://reseed.diva.exchange"
  "https://reseed.i2pgit.org"
  "https://i2p.novg.net"
  "https://i2pseed.creativecowpat.net:8443"
  "https://reseed.onion.im"
)

# ── Tor Directory Authorities ────────────────────────────────────────────────
# nickname  host                  port  orport  country  operator
TOR_AUTHS=(
  "moria1     128.31.0.39          9131  9101    US       MIT"
  "tor26      86.59.21.38          80     443     AT       conova"
  "dizum      194.109.206.212      80     443     NL       SABOTAGE LLC"
  "gabelmoo   131.188.40.189       80     443     DE       DFN-Verein"
  "dannenberg 193.23.244.244       80     443     DE       CCC"
  "maatuska   171.25.193.9         443    25      SE       Föreningen for digitala fri-och rattigheter"
  "longclaw   204.13.164.118       80     443     CA       Koumbit"
  "bastet     204.13.164.118       80     443     US       Riseup"
  "faravahar  109.69.67.51         443    443     US       HE"
)

# ── Yggdrasil ─────────────────────────────────────────────────────────────────
YGGDRASIL_URL="https://publicpeers.neilalexander.dev/publicnodes.json"

# ── Helper Functions ──────────────────────────────────────────────────────────

print_banner() {
  cat <<'EOF'
  ╔══════════════════════════════════════════════════════════════╗
  ║          fetch_seeds.sh  v1.1                               ║
  ║   Download Tor consensus / I2P reseed / Yggdrasil peers     ║
  ╚══════════════════════════════════════════════════════════════╝
EOF
}

usage() {
  cat <<EOF
Usage: $SCRIPT [OPTIONS]

Download latest Tor consensus, I2P reseed (SU3), and/or Yggdrasil peer seed files.

Options:
  -all           Download Tor + I2P + Yggdrasil (default if no -flag given)
  -i2p           Download I2P reseed files only
  -tor           Download Tor consensus files only
  -yggdrasil     Download Yggdrasil public peer list only
  -o DIR         Output directory (default: ./seed_data)
  -h             Show this help message

Examples:
  $SCRIPT                       Download all to ./seed_data/
  $SCRIPT -yggdrasil            Yggdrasil only
  $SCRIPT -tor -o ./tor_data    Tor consensus only to ./tor_data/
  $SCRIPT -i2p -yggdrasil       I2P + Yggdrasil
EOF
  exit 0
}

log_info()  { echo -e "[\e[34mINFO\e[0m] $*"; }
log_ok()    { echo -e "[\e[32m OK \e[0m] $*"; }
log_warn()  { echo -e "[\e[33mWARN\e[0m] $*"; }
log_err()   { echo -e "[\e[31mERR \e[0m] $*" >&2; }

need_cmd() {
  if ! command -v "$1" &>/dev/null; then
    log_err "Missing required command: $1"
    exit 1
  fi
}

cleanup() {
  [[ -n "${TMPDIR:-}" && -d "$TMPDIR" ]] && rm -rf "$TMPDIR"
}

# ── Argument Parsing ─────────────────────────────────────────────────────────

parse_args() {
  local has_flag=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -all)       MODE="all"; has_flag=true ;;
      -i2p)       [[ "$MODE" == "all" ]] && MODE="i2p" || MODE="${MODE}+i2p"; has_flag=true ;;
      -tor)       [[ "$MODE" == "all" ]] && MODE="tor" || MODE="${MODE}+tor"; has_flag=true ;;
      -yggdrasil) [[ "$MODE" == "all" ]] && MODE="yggdrasil" || MODE="${MODE}+yggdrasil"; has_flag=true ;;
      -o)         shift; OUTDIR="$(realpath -m "$1")" ;;
      -h|--help)  usage ;;
      *)          log_err "Unknown option: $1"; usage ;;
    esac
    shift
  done
  # if only one flag given, MODE stays as that flag
  # if multiple flags given, MODE is "i2p+tor+yggdrasil" etc
}

# ── Timestamp ────────────────────────────────────────────────────────────────

ts() {
  date '+%Y-%m-%d_%H%M%S'
}

ts_human() {
  date '+%Y-%m-%d %H:%M:%S UTC'
}

tag() {
  date '+%Y%m%d%H%M%S'
}

# ═══════════════════════════════════════════════════════════════════════════════
#  I2P SECTION
# ═══════════════════════════════════════════════════════════════════════════════

# ── Parse SU3 header and extract metadata ────────────────────────────────────
#  Input: SU3 file path
#  Output: writes summary to stdout
parse_su3() {
  local file="$1"
  local fsize
  fsize=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null)

  # Read magic (6 bytes)
  local magic
  magic=$(dd if="$file" bs=1 count=6 2>/dev/null | od -A n -t x1 | tr -d ' \n')

  if [[ "$magic" != "493250737533" ]]; then
    echo "  Magic: INVALID (expected 49 32 50 73 75 33, got $magic)"
    return 1
  fi
  echo "  Magic: I2Psu3 ✓"

  # Signature type (bytes 8-9, big-endian)
  local sig_type sig_len ver_len signer_id_len content_len
  sig_type=$(dd if="$file" bs=1 skip=8 count=2 2>/dev/null | od -A n -t u2 -N 2 | tr -d ' ')
  sig_len=$(dd if="$file" bs=1 skip=10 count=2 2>/dev/null | od -A n -t u2 -N 2 | tr -d ' ')
  ver_len=$(dd if="$file" bs=1 skip=13 count=1 2>/dev/null | od -A n -t u1 | tr -d ' ')
  signer_id_len=$(dd if="$file" bs=1 skip=15 count=1 2>/dev/null | od -A n -t u1 | tr -d ' ')
  content_len=$(dd if="$file" bs=1 skip=16 count=8 2>/dev/null | od -A n -t u8 -N 8 | tr -d ' ')
  local content_type
  content_type=$(dd if="$file" bs=1 skip=27 count=1 2>/dev/null | od -A n -t u1 | tr -d ' ')

  echo "  Signature Type: $sig_type${sig_type:+" (RSA-4096-SHA512)"}"
  echo "  Signature Length: $sig_len bytes"
  echo "  Version String Length: $ver_len"
  echo "  Signer ID Length: $signer_id_len"
  echo "  Content Length: $content_len bytes"

  case "$content_type" in
    3) echo "  Content Type: reseed ✓" ;;
    1) echo "  Content Type: router update" ;;
    2) echo "  Content Type: plugin" ;;
    *) echo "  Content Type: $content_type (unknown)" ;;
  esac

  echo "  File Size: $fsize bytes"

  # Extract version string
  if [[ "$ver_len" -gt 0 ]]; then
    local ver_str
    ver_str=$(dd if="$file" bs=1 skip=40 count="$ver_len" 2>/dev/null | tr -d '\0')
    echo "  Version Timestamp: $ver_str ($(date -d @"$ver_str" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "unparseable"))"
  fi

  # Extract signer ID
  if [[ "$signer_id_len" -gt 0 ]]; then
    local signer_start=$((40 + ver_len))
    local signer
    signer=$(dd if="$file" bs=1 skip="$signer_start" count="$signer_id_len" 2>/dev/null | tr -d '\0')
    echo "  Signer ID: $signer"
  fi

  # Extract and count routerInfo files from embedded ZIP
  local zip_start=$((40 + ver_len + signer_id_len))
  local zip_size=$content_len

  if [[ "$zip_size" -gt 0 ]]; then
    local tmpzip
    tmpzip=$(mktemp /tmp/i2p_zip_XXXXXX)
    dd if="$file" bs=1 skip="$zip_start" count="$zip_size" of="$tmpzip" 2>/dev/null

    if file "$tmpzip" | grep -qi zip; then
      local router_count
      router_count=$(unzip -l "$tmpzip" 2>/dev/null | grep 'routerInfo-' | wc -l)
      echo "  RouterInfo files in bundle: $router_count"
      unzip -l "$tmpzip" 2>/dev/null | grep 'routerInfo-' | head -5 | while read -r line; do
        echo "    $line"
      done
      if [[ "$router_count" -gt 5 ]]; then
        echo "    ... and $((router_count - 5)) more"
      fi
    else
      echo "  Embedded content: not a valid ZIP (or empty)"
    fi
    rm -f "$tmpzip"
  fi

  return 0
}

# ── Download from one reseed server (try multiple path/TLS variants) ─────────
#  Returns 0 on success, 1 on failure
i2p_download_one() {
  local base_url="$1"
  local outfile="$2"

  local paths=(
    "/i2pseeds.su3?netid=2"
    "/i2pseeds.su3"
    "/"
  )

  local ua="Wget/1.11.4"

  # Two TLS profiles: strict (default) and relaxed (Java 8 compat)
  local -a tls_strict=()
  local -a tls_relaxed=(
    --tlsv1.2 --ciphers "DEFAULT@SECLEVEL=1" -k
  )

  for path in "${paths[@]}"; do
    local url="${base_url}${path}"

    for tls_mode in strict relaxed; do
      local -n tls_flags="tls_${tls_mode}"
      log_info "I2P Trying $url (TLS: $tls_mode) ..."

      local code_size
      code_size=$(curl -sS -o "$outfile" -w "%{http_code}:%{size_download}" \
        --max-time 15 --connect-timeout 10 \
        -A "$ua" "${tls_flags[@]}" "$url" 2>/dev/null || echo "FAILED")

      if [[ "$code_size" == "FAILED" ]]; then
        local debug_out="${TMPDIR}/i2p_debug.txt"
        curl -sS -o /dev/null -w "HTTP %{http_code}, Time %{time_total}s, TLS %{ssl_verify_result}\n" \
          --max-time 10 "${tls_flags[@]}" "$url" > "$debug_out" 2>&1 || true
        log_warn "I2P Connection failed for $url (TLS: $tls_mode) — $(cat "$debug_out" 2>/dev/null || echo 'no debug')"
        continue
      fi

      local http_code="${code_size%%:*}"
      local size="${code_size##*:}"

      if [[ "$http_code" != "200" ]]; then
        log_warn "I2P HTTP $http_code for $url (TLS: $tls_mode)"
        rm -f "$outfile"
        continue
      fi

      if [[ "$size" -lt 1000 ]]; then
        log_warn "I2P Too small ($size bytes) for $url (TLS: $tls_mode)"
        rm -f "$outfile"
        continue
      fi

      # Validate SU3 magic bytes
      local magic
      magic=$(dd if="$outfile" bs=6 count=1 2>/dev/null | od -A n -t u1 | tr -d ' \n')
      if [[ "$magic" != "73508011511751" ]]; then
        rm -f "$outfile"
        continue
      fi

      log_ok "I2P Downloaded ($((size / 1024)) KB from ${base_url}${path})"
      return 0
    done
  done

  return 1
}

# ── I2P Main ─────────────────────────────────────────────────────────────────
i2p_main() {
  local stamp
  stamp=$(tag)
  local su3_file="${OUTDIR}/i2pseeds_${stamp}.su3"
  local report="${OUTDIR}/i2p_seed_${stamp}.txt"

  log_info "=== I2P Reseed Download ==="

  local found=false
  rm -f "$su3_file"

  for server in "${I2P_RESEEDS[@]}"; do
    local tmp="${TMPDIR}/i2p_tmp.su3"
    if i2p_download_one "$server" "$tmp"; then
      mv "$tmp" "$su3_file"
      found=true
      break
    else
      log_warn "I2P Failed: $server"
    fi
    rm -f "$tmp"
  done

  {
    echo "============================================"
    echo " I2P Reseed Seed Report"
    echo " Generated: $(ts_human)"
    echo "============================================"
    echo ""

    if $found; then
      parse_su3 "$su3_file"
      echo ""
      echo "SU3 file saved: $su3_file"

      # Also try additional servers for comparison
      local alt_count=0
      local alt_total_size=0
      for server in "${I2P_RESEEDS[@]}"; do
        local alt_tmp="${TMPDIR}/i2p_alt_${alt_count}.su3"
        if i2p_download_one "$server" "$alt_tmp" 2>/dev/null; then
          alt_count=$((alt_count + 1))
          local sz
          sz=$(stat -c%s "$alt_tmp" 2>/dev/null || stat -f%z "$alt_tmp" 2>/dev/null)
          alt_total_size=$((alt_total_size + sz))
          rm -f "$alt_tmp"
        fi
      done
      echo ""
      echo "Reseed servers reachable: $alt_count / ${#I2P_RESEEDS[@]}"
    else
      echo "ERROR: Could not download from any I2P reseed server."
      echo "All ${#I2P_RESEEDS[@]} servers tried and failed."
      log_err "I2P All servers failed."
    fi
  } >"$report" 2>&1

  if $found; then
    echo ""
    cat "$report"
    log_ok "I2P report saved: $report"
    return 0
  else
    return 1
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  TOR SECTION
# ═══════════════════════════════════════════════════════════════════════════════

# ── Download consensus from one authority ────────────────────────────────────
tor_download_one() {
  local nick="$1" ip="$2" port="$3"
  local outfile="$4"
  local url="http://${ip}:${port}/tor/status-vote/current/consensus"

  log_info "TOR Trying $nick ($ip:$port) ..."

  local code_size
  code_size=$(curl -sS -o "$outfile" -w "%{http_code}:%{size_download}" \
    --max-time 15 --connect-timeout 10 \
    "$url" 2>/dev/null || echo "FAILED")

  if [[ "$code_size" == "FAILED" ]]; then
    return 1
  fi

  local http_code="${code_size%%:*}"
  local size="${code_size##*:}"

  if [[ "$http_code" != "200" ]]; then
    rm -f "$outfile"
    return 1
  fi

  if [[ "$size" -lt 10000 ]]; then
    rm -f "$outfile"
    return 1
  fi

  log_ok "TOR Downloaded ($((size / 1024)) KB from $nick)"
  return 0
}

# ── Parse consensus metadata ─────────────────────────────────────────────────
parse_consensus() {
  local file="$1"

  local valid_after fresh_until consensus_method
  local total_relays=0 running_relays=0 guard_relays=0 exit_relays=0
  local sig_count=0 bw_auths=0

  valid_after=$(grep '^valid-after ' "$file" | head -1 | cut -d' ' -f2-)
  fresh_until=$(grep '^fresh-until ' "$file" | head -1 | cut -d' ' -f2-)
  consensus_method=$(grep '^consensus-method ' "$file" | head -1 | awk '{print $2}')

  # Count relays: each 'r' line is one relay descriptor
  total_relays=$(grep -c '^r ' "$file" 2>/dev/null || echo 0)

  # Count running relays
  running_relays=$(grep -c '^s ' "$file" 2>/dev/null || echo 0)

  # Count specific flags
  guard_relays=$(grep '^s ' "$file" | grep -c 'Guard' 2>/dev/null || echo 0)
  exit_relays=$(grep '^s ' "$file" | grep -c 'Exit' 2>/dev/null || echo 0)

  # Count signatures
  sig_count=$(grep -c '^directory-signature ' "$file" 2>/dev/null || echo 0)

  # Report
  echo "  Valid After: ${valid_after:-N/A}"
  echo "  Fresh Until: ${fresh_until:-N/A}"
  echo "  Consensus Method: ${consensus_method:-N/A}"
  echo "  Total Relays: $total_relays"
  echo "  Running Relays: $running_relays"
  echo "  Guard Relays: $guard_relays"
  echo "  Exit Relays: $exit_relays"
  echo "  Directory Signatures: $sig_count"

  # List signing authorities
  if [[ "$sig_count" -gt 0 ]]; then
    echo "  Signing Authorities:"
    grep '^directory-signature ' "$file" | while read -r _ _ signer _; do
      echo "    - $signer"
    done | sort -u
  fi

  # Clients with bandwidth info
  bw_auths=$(grep -c '^w Bandwidth=' "$file" 2>/dev/null || echo 0)
  echo "  Relays with bandwidth info: $bw_auths"

  # Detect Tor version distribution (from 'v' lines)
  echo "  Tor Version Distribution (top 5):"
  grep '^v ' "$file" 2>/dev/null | awk '{print $2}' | sort | uniq -c | sort -rn | head -5 | while read -r count ver; do
    echo "    $ver : $count relays"
  done
}

# ── Tor Main ─────────────────────────────────────────────────────────────────
tor_main() {
  local stamp
  stamp=$(tag)
  local consensus_file="${OUTDIR}/tor_consensus_${stamp}.txt"
  local best_file="${TMPDIR}/tor_best.txt"
  local report="${OUTDIR}/tor_seed_${stamp}.txt"

  log_info "=== Tor Consensus Download ==="

  local best_count=0 best_nick=""

  for auth in "${TOR_AUTHS[@]}"; do
    local nick ip port
    read -r nick ip port _ <<<"$auth"
    local tmp="${TMPDIR}/tor_${nick}.txt"

    if tor_download_one "$nick" "$ip" "$port" "$tmp"; then
      # Count signatures as quality metric
      local sc
      sc=$(grep -c '^directory-signature ' "$tmp" 2>/dev/null || echo 0)
      if [[ "$sc" -gt "$best_count" ]]; then
        best_count=$sc
        cp "$tmp" "$best_file"
        best_nick=$nick
      fi
    fi
    # Keep all for reference
    cp "$tmp" "${TMPDIR}/tor_${nick}.txt" 2>/dev/null || true
  done

  {
    echo "============================================"
    echo " Tor Consensus Report"
    echo " Generated: $(ts_human)"
    echo "============================================"
    echo ""

    if [[ -s "$best_file" ]]; then
      cp "$best_file" "$consensus_file"
      echo "Best consensus source: $best_nick"
      echo "Directory Signatures: $best_count"
      echo ""
      parse_consensus "$consensus_file"
      echo ""
      echo "Consensus file saved: $consensus_file"

      # Summary per authority
      echo ""
      echo "Directory Authority Status:"
      echo "---------------------------"
      printf "%-16s %-18s %-10s %s\n" "Nickname" "IP:Port" "Signatures" "Status"
      for auth in "${TOR_AUTHS[@]}"; do
        local nick ip port
        read -r nick ip port _ <<<"$auth"
        local afile="${TMPDIR}/tor_${nick}.txt"
        local asc="" astatus=""
        if [[ -f "$afile" ]]; then
          asc=$(grep -c '^directory-signature ' "$afile" 2>/dev/null || echo 0)
          if grep -q '^r ' "$afile" 2>/dev/null; then
            astatus="OK"
          else
            astatus="EMPTY"
          fi
        else
          asc="-" && astatus="UNREACHABLE"
        fi
        printf "%-16s %-18s %-10s %s\n" "$nick" "${ip}:${port}" "$asc" "$astatus"
      done
    else
      echo "ERROR: Could not download consensus from any Tor directory authority."
      echo "All ${#TOR_AUTHS[@]} authorities tried and failed."
      log_err "TOR All authorities failed."
    fi
  } >"$report" 2>&1

  if [[ -s "$best_file" ]]; then
    echo ""
    cat "$report"
    log_ok "TOR report saved: $report"
    return 0
  else
    return 1
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  YGGDRASIL SECTION
# ═══════════════════════════════════════════════════════════════════════════════

# ── Download Yggdrasil JSON ──────────────────────────────────────────────────
yggdrasil_download() {
  local outfile="$1"

  log_info "YGG Downloading public peers list ..."

  local code_size
  code_size=$(curl -sS -o "$outfile" -w "%{http_code}:%{size_download}" \
    --max-time 20 --connect-timeout 10 \
    "$YGGDRASIL_URL" 2>/dev/null || echo "FAILED")

  if [[ "$code_size" == "FAILED" ]]; then
    return 1
  fi

  local http_code="${code_size%%:*}"
  local size="${code_size##*:}"

  if [[ "$http_code" != "200" ]]; then
    rm -f "$outfile"
    return 1
  fi

  if [[ "$size" -lt 100 ]]; then
    rm -f "$outfile"
    return 1
  fi

  log_ok "YGG Downloaded ($((size / 1024)) KB)"
  return 0
}

# ── Parse Yggdrasil JSON ─────────────────────────────────────────────────────
#  Format: { "country_name": { "tcp://ip:port": {"up":true,"key":"..."}, ... }, ... }
#  Uses grep/sed for JSON parsing (no jq required)
yggdrasil_parse() {
  local file="$1"
  local json_raw
  json_raw=$(cat "$file")

  # Extract all URI keys (lines like "tcp://..." or "tls://..." etc at second nesting level)
  local tmp_uris
  tmp_uris=$(mktemp /tmp/ygg_uris_XXXXXX)
  grep -oP '"(tcp|tls|quic|ws|wss)://[^"]*"' "$file" | tr -d '"' | sort -u > "$tmp_uris"
  local total_peers
  total_peers=$(wc -l < "$tmp_uris")

  echo "  Total Peers: $total_peers"
  echo ""

  # Extract country names (top-level keys, excluding transport protocol prefixes)
  local tmp_countries
  tmp_countries=$(mktemp /tmp/ygg_countries_XXXXXX)
  # Country keys are top-level, don't start with transport schemes
  grep -oP '^\s+"[a-z][a-z.\-]*": \{$' "$file" | \
    sed 's/^[[:space:]]*"//;s/": {$//' | \
    grep -vE '^(tcp|tls|quic|ws|wss)://' > "$tmp_countries"
  local country_count
  country_count=$(wc -l < "$tmp_countries")
  echo "  Countries with peers: $country_count"
  echo ""

  # Per country peer count
  echo "  Peers by Country (top 30):"
  local c=0
  while IFS= read -r country; do
    [[ "$c" -ge 30 ]] && break
    # Count transport URIs under this country block
    local count
    count=$(awk -v c="$country" '
      BEGIN { cnt=0; in_block=0 }
      $0 ~ "\"" c "\": \\{" { in_block=1; next }
      in_block && /^  "/ && /: \{/ && !/"(tcp|tls|quic|ws|wss):\// { in_block=0; next }
      in_block && /"(tcp|tls|quic|ws|wss):\/\// { cnt++ }
      END { print cnt+0 }
    ' "$file")
    if [[ "$count" -gt 0 ]]; then
      local display="${country%.md}"
      printf "    %-20s: %s\n" "$display" "$count"
    fi
    c=$((c + 1))
  done < "$tmp_countries"
  if [[ "$country_count" -gt 30 ]]; then
    echo "    ... and $((country_count - 30)) more countries"
  fi

  # Show sample peers (up to 10)
  echo ""
  echo "  Sample Peers (first 10):"
  head -10 "$tmp_uris" | while read -r uri; do
    # Extract key if available
    local key
    key=$(grep -A1 "\"$uri\"" "$file" | grep '"key"' | head -1 | sed 's/.*"key": "\([^"]*\)".*/\1/' | cut -c1-16)
    if [[ -n "$key" ]]; then
      echo "    $uri (key: ${key}...)"
    else
      echo "    $uri"
    fi
  done
  if [[ "$total_peers" -gt 10 ]]; then
    echo "    ... and $((total_peers - 10)) more"
  fi

  rm -f "$tmp_uris" "$tmp_countries"

  # Detect supported transports
  local tcp_count tls_count quic_count ws_count wss_count
  tcp_count=$(grep -c '"tcp://' "$file" 2>/dev/null || echo 0)
  tls_count=$(grep -c '"tls://' "$file" 2>/dev/null || echo 0)
  quic_count=$(grep -c '"quic://' "$file" 2>/dev/null || echo 0)
  ws_count=$(grep -c '"ws://' "$file" 2>/dev/null || echo 0)
  wss_count=$(grep -c '"wss://' "$file" 2>/dev/null || echo 0)
  echo ""
  echo "  Transport Distribution (total entries across all countries):"
  echo "    tcp:// : $tcp_count"
  echo "    tls:// : $tls_count"
  echo "    quic://: $quic_count"
  echo "    ws://  : $ws_count"
  echo "    wss:// : $wss_count"

  return 0
}

# ── Yggdrasil Main ────────────────────────────────────────────────────────────
yggdrasil_main() {
  local stamp
  stamp=$(tag)
  local json_file="${OUTDIR}/yggdrasil_peers_${stamp}.json"
  local report="${OUTDIR}/yggdrasil_seed_${stamp}.txt"

  log_info "=== Yggdrasil Peer Download ==="

  if ! yggdrasil_download "$json_file"; then
    log_err "YGG Failed to download from $YGGDRASIL_URL"

    {
      echo "============================================"
      echo " Yggdrasil Public Peers Report"
      echo " Generated: $(ts_human)"
      echo "============================================"
      echo ""
      echo "ERROR: Failed to download from $YGGDRASIL_URL"
    } >"$report"

    return 1
  fi

  {
    echo "============================================"
    echo " Yggdrasil Public Peers Report"
    echo " Generated: $(ts_human)"
    echo " Source: $YGGDRASIL_URL"
    echo "============================================"
    echo ""

    yggdrasil_parse "$json_file"
    echo ""
    echo "Raw JSON saved: $json_file"
  } >"$report"

  echo ""
  cat "$report"
  log_ok "YGG report saved: $report"
  return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

main() {
  need_cmd curl
  need_cmd dd
  need_cmd od
  need_cmd unzip

  parse_args "$@"

  # Resolve default: if user gave no -flag, default is "all"
  if [[ "$MODE" == "all" ]]; then
    MODE="all"
  fi

  print_banner

  echo "Script:     $SCRIPT v$VERSION"
  echo "Mode:       $MODE"
  echo "Output dir: $OUTDIR"
  echo ""

  mkdir -p "$OUTDIR"
  TMPDIR=$(mktemp -d /tmp/fetch_seeds_XXXXXX)
  trap cleanup EXIT

  local exit_code=0
  local do_i2p=false do_tor=false do_ygg=false

  # Determine which protocols to fetch
  case "$MODE" in
    all)
      do_i2p=true; do_tor=true; do_ygg=true ;;
    i2p)
      do_i2p=true ;;
    tor)
      do_tor=true ;;
    yggdrasil)
      do_ygg=true ;;
    *+*)
      [[ "$MODE" == *i2p* ]]       && do_i2p=true
      [[ "$MODE" == *tor* ]]       && do_tor=true
      [[ "$MODE" == *yggdrasil* ]] && do_ygg=true ;;
  esac

  if $do_i2p; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              I2P Reseed Download                           ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    i2p_main || exit_code=$((exit_code + 1))
  fi

  if $do_tor; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           Tor Consensus Download                           ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    tor_main || exit_code=$((exit_code + 2))
  fi

  if $do_ygg; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         Yggdrasil Public Peers Download                    ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    yggdrasil_main || exit_code=$((exit_code + 4))
  fi

  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║                    Complete                                ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo "Output directory: $OUTDIR"
  ls -lh "$OUTDIR" 2>/dev/null | tail -n +2 | while read -r line; do
    echo "  $line"
  done

  return $exit_code
}

main "$@"
