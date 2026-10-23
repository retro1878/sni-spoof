#!/bin/bash
set -euo pipefail

# ── Colors ──────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[~]${NC} $1"; }
err()  { echo -e "${RED}[!]${NC} $1" >&2; exit 1; }

# ── Settings you may want to edit ───────────────────────────
# When you cut a new release, update DL_URL's tag and EXPECTED_SHA256
# together; scripts/release.sh does this for you.
DL_URL="https://github.com/retro1878/sni-spoof/releases/download/v0.6.0/sni-spoof-linux-amd64"
BIN_PATH="/usr/local/bin/sni-spoof"
CFG_DIR="/etc/sni-spoof"
CFG_V4="${CFG_DIR}/config.json"
CFG_V6="${CFG_DIR}/config-v6.json"
LOG_DIR="/var/log/sni-spoof"
LOG_V4="${LOG_DIR}/sni-spoof.log"
LOG_V6="${LOG_DIR}/sni-spoof-v6.log"
LOG_MAX_SIZE="10M"     # rotate once the log grows past this
LOG_KEEP=5             # how many rotated (compressed) logs to keep
JOURNAL_CAP="200M"     # fallback: cap the journal if we can't use a file

# Fixed per-instance settings. v4 keeps the original port and config path so
# existing installs and scripts are untouched.
UNIT_V4="sni-spoof"
UNIT_V6="sni-spoof-v6"
PORT_V4=40443
PORT_V6=40444

# Defaults used only when a config is created for the first time. An existing
# config is never rewritten.
DEFAULT_V4_IP="104.19.229.21"
DEFAULT_V4_SNI="www.hcaptcha.com"
DEFAULT_V6_SNI="www.hcaptcha.com"

# Binary verbosity. The daemon reads this from the JSON config key LOG_LEVEL
# (not an env var / flag). Valid: error | warn | info | debug.
LOG_LEVEL="info"

# Integrity check. Expected SHA-256 of the binary served by DL_URL. Pinned to
# the sni-spoof-linux-amd64 published with this release. Binaries are built
# with -buildvcs=false and -B gobuildid so the hash is reproducible across
# machines. If you republish a rebuilt binary, update this
# (sha256sum sni-spoof-linux-amd64) or set it empty to disable verification
# (NOT recommended; see the warning it prints).
EXPECTED_SHA256="b3415a7148ac38b974487434ac6c70862290c33d72171bbc6bb9cd1fbd5d8db5"

# ── Flags ───────────────────────────────────────────────────
WANT_V6=0
SHOW_STATUS=0
FORCE=0
CONNECT_IP_ARG=""
FAKE_SNI_ARG=""

usage() {
  cat <<EOF
Usage: $0 [options]

With no options this installs or upgrades the IPv4 instance only, exactly as
before. Existing configs are never rewritten.

  --v6                 install or repair the IPv6 instance (port ${PORT_V6})
  --connect-ip ADDR    upstream for --v6; skips the prompt
  --fake-sni NAME      fake SNI for --v6; skips the prompt
  --status             show both instances and exit
  --force              add --v6 even if the IPv6 connectivity probe fails
  -h, --help           this message
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --v6) WANT_V6=1 ;;
    --status) SHOW_STATUS=1 ;;
    --force) FORCE=1 ;;
    --connect-ip)
      shift; [ $# -gt 0 ] || err "--connect-ip needs a value"; CONNECT_IP_ARG="$1" ;;
    --connect-ip=*) CONNECT_IP_ARG="${1#*=}" ;;
    --fake-sni)
      shift; [ $# -gt 0 ] || err "--fake-sni needs a value"; FAKE_SNI_ARG="$1" ;;
    --fake-sni=*) FAKE_SNI_ARG="${1#*=}" ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; err "unknown option: $1" ;;
  esac
  shift
done

# ── Helpers ─────────────────────────────────────────────────
json_str() {  # json_str FILE KEY
  sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" 2>/dev/null | head -1
}
json_num() {  # json_num FILE KEY
  sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$1" 2>/dev/null | head -1
}

unit_active() { systemctl is-active --quiet "$1" 2>/dev/null; }

port_in_use() {  # port_in_use PORT
  ss -ltn 2>/dev/null | awk 'NR>1 {print $4}' | grep -qE "[:.]$1$"
}

check_v6_egress() {
  # A bare IPv6 HTTP probe is unreliable: some anycast addresses only answer
  # when a SNI is present. Accept either a raw TCP connect or a hostname GET.
  timeout 5 bash -c 'exec 3<>/dev/tcp/2606:4700:4700::1111/443' 2>/dev/null && return 0
  local code
  code="$(curl -6 -sS -o /dev/null -w '%{http_code}' --max-time 8 https://ipv6.google.com/ 2>/dev/null || true)"
  case "$code" in 2*|3*) return 0 ;; esac
  return 1
}

show_status() {
  local state
  printf '%-4s %-28s %-6s %-20s %s\n' INSTANCE CONFIG PORT UNIT STATE
  state="$(unit_active "$UNIT_V4" && echo active || echo inactive)"
  if [ -f "$CFG_V4" ]; then
    printf '%-4s %-28s %-6s %-20s %s  upstream=%s sni=%s\n' \
      v4 "$CFG_V4" "$(json_num "$CFG_V4" LISTEN_PORT)" "$UNIT_V4" "$state" \
      "$(json_str "$CFG_V4" CONNECT_IP)" "$(json_str "$CFG_V4" FAKE_SNI)"
  else
    printf '%-4s %-28s %-6s %-20s %s\n' v4 "$CFG_V4" "-" "$UNIT_V4" "not configured"
  fi

  state="$(unit_active "$UNIT_V6" && echo active || echo inactive)"
  if [ -f "$CFG_V6" ]; then
    printf '%-4s %-28s %-6s %-20s %s  upstream=%s sni=%s\n' \
      v6 "$CFG_V6" "$(json_num "$CFG_V6" LISTEN_PORT)" "$UNIT_V6" "$state" \
      "$(json_str "$CFG_V6" CONNECT_IP)" "$(json_str "$CFG_V6" FAKE_SNI)"
  else
    printf '%-4s %-28s %-6s %-20s %s\n' v6 "$CFG_V6" "-" "$UNIT_V6" "not configured"
  fi
}

# ── Status short-circuit ────────────────────────────────────
if [[ $SHOW_STATUS -eq 1 ]]; then
  show_status
  exit 0
fi

# ── Must run as root ────────────────────────────────────────
if [[ ${EUID} -ne 0 ]]; then
  err "Run this script as root (sudo)."
fi

for t in curl systemctl sha256sum install awk ss; do
  command -v "$t" >/dev/null 2>&1 || err "Missing required tool: $t"
done

# Fail before touching anything if --v6 was asked for on a host without IPv6
# egress. Only checked when the instance does not exist yet: an existing
# config is never second-guessed.
if [[ $WANT_V6 -eq 1 && ! -f "$CFG_V6" ]]; then
  if ! check_v6_egress; then
    if [[ $FORCE -eq 1 ]]; then
      warn "IPv6 connectivity probe failed but --force was given; continuing."
      V6_PROBE_OK=0
    else
      err "No working IPv6 egress detected. Re-run with --force to override."
    fi
  else
    V6_PROBE_OK=1
  fi
fi

# Normalize/validate LOG_LEVEL so a typo doesn't silently fall back to "warn"
# inside the binary (which would hide the startup banner and look broken).
LOG_LEVEL="$(echo "${LOG_LEVEL}" | tr '[:upper:]' '[:lower:]')"
case "${LOG_LEVEL}" in
  error|warn|info|debug) ;;
  *) err "Invalid LOG_LEVEL='${LOG_LEVEL}' (valid: error|warn|info|debug)." ;;
esac

# ── Download binary to a temp file first ────────────────────
log "Downloading sni-spoof binary..."
TMP_BIN="$(mktemp)"
trap 'rm -f "$TMP_BIN"' EXIT
curl -fsSL "$DL_URL" -o "$TMP_BIN" || err "Failed to download binary from $DL_URL"
[[ -s "$TMP_BIN" ]] || err "Downloaded file is empty."

# ── Verify integrity BEFORE installing ──────────────────────
if [[ -n "$EXPECTED_SHA256" ]]; then
  log "Verifying SHA-256..."
  echo "${EXPECTED_SHA256}  ${TMP_BIN}" | sha256sum -c - >/dev/null 2>&1 \
    || err "Checksum mismatch — refusing to install. Downloaded bytes do not match EXPECTED_SHA256."
  log "Checksum OK."
else
  warn "EXPECTED_SHA256 is empty: this binary was fetched over HTTPS but is NOT verified."
  warn "Strongly recommended: pin EXPECTED_SHA256 (sha256sum of a trusted copy) and re-run."
  warn "SHA-256 of what was just downloaded:"
  echo -e "      $(sha256sum "$TMP_BIN" | awk '{print $1}')"
fi

install -m 0755 "$TMP_BIN" "$BIN_PATH"
log "Binary installed to $BIN_PATH"

# ── Decide how to bound the logs ────────────────────────────
# Preferred: redirect the service's stdout/stderr to a dedicated
# file and rotate it by size (needs systemd >= 240 for append:, and
# logrotate). Otherwise: log to the journal and cap the journal.
ensure_logrotate() {
  command -v logrotate >/dev/null 2>&1 && return 0
  warn "logrotate not found; attempting to install it..."
  if   command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq logrotate
  elif command -v dnf     >/dev/null 2>&1; then dnf install -y logrotate
  elif command -v yum     >/dev/null 2>&1; then yum install -y logrotate
  elif command -v zypper  >/dev/null 2>&1; then zypper -n install logrotate
  elif command -v apk     >/dev/null 2>&1; then apk add --no-cache logrotate
  else return 1
  fi
  command -v logrotate >/dev/null 2>&1
}

MODE="journal"
SYSTEMD_VER="$(systemctl --version | awk 'NR==1{print $2}')"
if [[ "$SYSTEMD_VER" =~ ^[0-9]+$ ]] && (( SYSTEMD_VER >= 240 )); then
  if ensure_logrotate; then
    MODE="file"
  else
    warn "Couldn't ensure logrotate; falling back to journal logging with a ${JOURNAL_CAP} cap."
  fi
else
  warn "systemd ${SYSTEMD_VER} < 240: per-file redirection unsupported; using journal + ${JOURNAL_CAP} cap."
fi

mkdir -p "$LOG_DIR" "$CFG_DIR"

# ── Config: create only when absent ─────────────────────────
write_config() {  # write_config PATH IP SNI PORT
  cat > "$1" << EOF
{
  "LISTEN_HOST": "127.0.0.1",
  "LISTEN_PORT": $4,
  "CONNECT_IP": "$2",
  "CONNECT_PORT": 443,
  "FAKE_SNI": "$3",
  "LOG_LEVEL": "${LOG_LEVEL}"
}
EOF
}

if [[ -f "$CFG_V4" ]]; then
  warn "Config already exists at $CFG_V4 — leaving it untouched."
else
  write_config "$CFG_V4" "$DEFAULT_V4_IP" "$DEFAULT_V4_SNI" "$PORT_V4"
  log "Config written to $CFG_V4 (v4, port ${PORT_V4})"
fi

# ── Unit writer ─────────────────────────────────────────────
write_unit() {  # write_unit UNIT CONFIG LOGFILE
  local unit="$1" cfg="$2" logfile="$3" directives=""
  if [[ "$MODE" == "file" ]]; then
    directives="StandardOutput=append:${logfile}
StandardError=append:${logfile}"
  fi
  cat > "/etc/systemd/system/${unit}.service" << EOF
[Unit]
Description=SNI Spoof DPI Bypass Forwarder (${unit})
After=network.target

[Service]
Type=simple
ExecStart=${BIN_PATH} ${cfg}
Restart=on-failure
RestartSec=5
User=root
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
${directives}

[Install]
WantedBy=multi-user.target
EOF
}

write_unit "$UNIT_V4" "$CFG_V4" "$LOG_V4"
log "Service ${UNIT_V4}.service written"

# ── Optional IPv6 instance ──────────────────────────────────
if [[ $WANT_V6 -eq 1 ]]; then
  if [[ -f "$CFG_V6" ]]; then
    warn "Config already exists at $CFG_V6 — leaving it untouched."
  else
    if [[ "${V6_PROBE_OK:-0}" -eq 1 ]]; then
      log "IPv6 connectivity probe OK."
    fi

    if [[ -z "$CONNECT_IP_ARG" ]]; then
      if [[ -t 0 ]]; then
        read -r -p "IPv6 upstream address (CONNECT_IP): " CONNECT_IP_ARG
      else
        err "--v6 needs --connect-ip when stdin is not a terminal"
      fi
    fi
    [[ -n "$CONNECT_IP_ARG" ]] || err "CONNECT_IP cannot be empty"
    if [[ -z "$FAKE_SNI_ARG" ]]; then
      if [[ -t 0 ]]; then
        read -r -p "Fake SNI [${DEFAULT_V6_SNI}]: " FAKE_SNI_ARG
      fi
      FAKE_SNI_ARG="${FAKE_SNI_ARG:-$DEFAULT_V6_SNI}"
    fi
    if port_in_use "$PORT_V6"; then
      err "Port ${PORT_V6} is already in use; refusing to create the IPv6 instance."
    fi
    write_config "$CFG_V6" "$CONNECT_IP_ARG" "$FAKE_SNI_ARG" "$PORT_V6"
    log "Config written to $CFG_V6 (v6, port ${PORT_V6})"
  fi
  write_unit "$UNIT_V6" "$CFG_V6" "$LOG_V6"
  log "Service ${UNIT_V6}.service written"
fi

# ── Log bounding for the chosen mode ────────────────────────
if [[ "$MODE" == "file" ]]; then
  log "Bounding logs via logrotate (cap ${LOG_MAX_SIZE}, keep ${LOG_KEEP})..."
  LOGROTATE_BIN="$(command -v logrotate)"
  ROTATE_CONF="${CFG_DIR}/logrotate.conf"
  ROTATE_STATE="${LOG_DIR}/.logrotate.status"

  # Kept out of /etc/logrotate.d on purpose so the system's daily run
  # doesn't fight our hourly timer over the same state.
  cat > "$ROTATE_CONF" << EOF
${LOG_DIR}/*.log {
    size ${LOG_MAX_SIZE}
    rotate ${LOG_KEEP}
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
EOF

  # Check size hourly so a chatty service can't balloon between daily runs.
  cat > /etc/systemd/system/sni-spoof-logrotate.service << EOF
[Unit]
Description=Rotate sni-spoof log if oversized

[Service]
Type=oneshot
ExecStart=${LOGROTATE_BIN} ${ROTATE_CONF} --state ${ROTATE_STATE}
EOF

  cat > /etc/systemd/system/sni-spoof-logrotate.timer << EOF
[Unit]
Description=Hourly sni-spoof log size check

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
EOF
else
  log "Bounding the systemd journal at ${JOURNAL_CAP} (global safety cap)..."
  warn "This affects the whole journal, not just sni-spoof."
  mkdir -p /etc/systemd/journald.conf.d
  cat > /etc/systemd/journald.conf.d/00-sni-spoof-cap.conf << EOF
[Journal]
SystemMaxUse=${JOURNAL_CAP}
RuntimeMaxUse=${JOURNAL_CAP}
EOF
  systemctl restart systemd-journald || warn "Could not restart systemd-journald."
fi

# ── Enable and (re)start ────────────────────────────────────
# The binary is shared, so an upgrade must restart every configured instance
# or one of them keeps running the previous build.
log "Enabling and restarting services..."
systemctl daemon-reload
systemctl enable "$UNIT_V4" >/dev/null 2>&1 || true
systemctl restart "$UNIT_V4"

V6_CONFIGURED=0
if [[ -f "$CFG_V6" ]]; then
  V6_CONFIGURED=1
  systemctl enable "$UNIT_V6" >/dev/null 2>&1 || true
  systemctl restart "$UNIT_V6"
fi

if [[ "$MODE" == "file" ]]; then
  systemctl enable --now sni-spoof-logrotate.timer >/dev/null 2>&1 || \
    warn "Could not enable the logrotate timer; logs will still rotate on the daily run."
fi

sleep 2
FAILED=0
unit_active "$UNIT_V4" || FAILED=1
if [[ $V6_CONFIGURED -eq 1 ]]; then
  unit_active "$UNIT_V6" || FAILED=1
fi

if [[ $FAILED -eq 0 ]]; then
  log "sni-spoof is running!"
  systemctl status "$UNIT_V4" --no-pager || true
  if [[ $V6_CONFIGURED -eq 1 ]]; then
    systemctl status "$UNIT_V6" --no-pager || true
  fi
  if [[ "$MODE" == "file" ]]; then
    log "Logs: ${LOG_DIR}/*.log (capped ~${LOG_MAX_SIZE} × ${LOG_KEEP} rotations)"
  else
    log "Logs: journalctl -u ${UNIT_V4}   (journal capped at ${JOURNAL_CAP})"
  fi
  log "Verbosity: LOG_LEVEL=${LOG_LEVEL} in ${CFG_DIR} (restart to change)."
  echo
  show_status
else
  if [[ "$MODE" == "file" ]]; then
    err "A service failed to start. Check: ${LOG_DIR}/*.log"
  else
    err "A service failed to start. Check: journalctl -u ${UNIT_V4} -n 30"
  fi
fi
