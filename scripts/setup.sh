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
DL_URL="http://5.160.219.169:8080/dl/sni-spoof-linux-amd64"
BIN_PATH="/usr/local/bin/sni-spoof"
CFG_DIR="/etc/sni-spoof"
CFG_PATH="${CFG_DIR}/config.json"
LOG_DIR="/var/log/sni-spoof"
LOG_FILE="${LOG_DIR}/sni-spoof.log"
LOG_MAX_SIZE="10M"     # rotate once the log grows past this
LOG_KEEP=5             # how many rotated (compressed) logs to keep
JOURNAL_CAP="200M"     # fallback: cap the journal if we can't use a file

# Binary verbosity. The daemon reads this from the JSON config key LOG_LEVEL
# (not an env var / flag). Valid: error | warn | info | debug.
#   error - only fatal/errors
#   warn  - + warnings (the binary's own built-in default)
#   info  - + startup banner & "listening on ..." (handy to confirm health)
#   debug - + per-connection/per-packet tracing (chatty; for troubleshooting)
# Default here is "info" so a fresh install actually shows it came up. Bump to
# "debug" only while diagnosing. After the in-kernel BPF capture filter, even
# debug no longer logs relayed data packets — just control packets.
LOG_LEVEL="info"

# Integrity check. Expected SHA-256 of the binary served by DL_URL. Pinned to
# the sni-spoof-linux-amd64 committed in this repo. If you rebuild/republish
# the binary, update this (sha256sum sni-spoof-linux-amd64) or set it empty to
# disable verification (NOT recommended; see the warning it prints).
EXPECTED_SHA256="4c6236118bbbc818946e92579ff3ee0676813c8f6fdfd0adec3f9d30653d5ccd"

# ── Must run as root ────────────────────────────────────────
if [[ ${EUID} -ne 0 ]]; then
  err "Run this script as root (sudo)."
fi

for t in curl systemctl sha256sum install awk; do
  command -v "$t" >/dev/null 2>&1 || err "Missing required tool: $t"
done

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
  warn "EXPECTED_SHA256 is empty: this binary was fetched over PLAINTEXT HTTP and is NOT verified."
  warn "Anyone on the network path could have replaced it, and it will run as root with CAP_NET_RAW."
  warn "Strongly recommended: pin EXPECTED_SHA256 (sha256sum of a trusted copy) and re-run."
  warn "SHA-256 of what was just downloaded:"
  echo -e "      $(sha256sum "$TMP_BIN" | awk '{print $1}')"
fi

install -m 0755 "$TMP_BIN" "$BIN_PATH"
log "Binary installed to $BIN_PATH"

# ── Write config (don't clobber an existing, tuned one) ─────
log "Writing config..."
mkdir -p "$CFG_DIR"
if [[ -f "$CFG_PATH" ]]; then
  warn "Config already exists at $CFG_PATH — leaving it untouched."
  warn "Delete it and re-run if you want the default regenerated."
  warn "Verbosity is the LOG_LEVEL key in that file (error|warn|info|debug);"
  warn "edit it and 'systemctl restart sni-spoof' to apply."
else
  cat > "$CFG_PATH" << EOF
{
  "LISTEN_HOST": "127.0.0.1",
  "LISTEN_PORT": 40443,
  "CONNECT_IP": "104.19.229.21",
  "CONNECT_PORT": 443,
  "FAKE_SNI": "www.hcaptcha.com",
  "LOG_LEVEL": "${LOG_LEVEL}"
}
EOF
  log "Config written to $CFG_PATH (LOG_LEVEL=${LOG_LEVEL})"
fi

mkdir -p "$LOG_DIR"

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

LOG_DIRECTIVES=""
if [[ "$MODE" == "file" ]]; then
  LOG_DIRECTIVES="StandardOutput=append:${LOG_FILE}
StandardError=append:${LOG_FILE}"
fi

# ── Write systemd unit ──────────────────────────────────────
log "Creating systemd service..."
cat > /etc/systemd/system/sni-spoof.service << EOF
[Unit]
Description=SNI Spoof DPI Bypass Forwarder
After=network.target

[Service]
Type=simple
ExecStart=${BIN_PATH} ${CFG_PATH}
Restart=on-failure
RestartSec=5
User=root
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
${LOG_DIRECTIVES}

[Install]
WantedBy=multi-user.target
EOF

# ── Set up log bounding for the chosen mode ─────────────────
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

# ── Enable and start ────────────────────────────────────────
log "Enabling and starting service..."
systemctl daemon-reload
systemctl enable sni-spoof >/dev/null 2>&1 || true
systemctl restart sni-spoof

if [[ "$MODE" == "file" ]]; then
  systemctl enable --now sni-spoof-logrotate.timer >/dev/null 2>&1 || \
    warn "Could not enable the logrotate timer; logs will still rotate on the daily run."
fi

sleep 2
if systemctl is-active --quiet sni-spoof; then
  log "sni-spoof is running!"
  systemctl status sni-spoof --no-pager || true
  if [[ "$MODE" == "file" ]]; then
    log "Logs: ${LOG_FILE} (capped ~${LOG_MAX_SIZE} × ${LOG_KEEP} rotations)"
  else
    log "Logs: journalctl -u sni-spoof   (journal capped at ${JOURNAL_CAP})"
  fi
  log "Verbosity: LOG_LEVEL=${LOG_LEVEL} in ${CFG_PATH} (restart to change)."
else
  if [[ "$MODE" == "file" ]]; then
    err "Service failed to start. Check: ${LOG_FILE}  (and: systemctl status sni-spoof)"
  else
    err "Service failed to start. Check: journalctl -u sni-spoof -n 30"
  fi
fi
