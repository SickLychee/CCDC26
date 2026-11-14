#!/usr/bin/env bash
# pa_change_pass.sh - Rotate a Palo Alto (PAN-OS) admin password via the XML API.
#
# Usage:  ./pa_change_pass.sh <firewall-mgmt-ip> [username]
#         (username defaults to "admin")
#
# The script prompts for the current password and the new password, so neither
# ends up in shell history or `ps`. It then:
#   1. Gets an API key using the current credentials
#   2. Lists every local admin account (look for ones you didn't create)
#   3. Hashes the new password on the firewall and sets it on the user
#   4. Commits and waits for the commit to finish
#   5. Confirms the new password works and the old one no longer does
#
# Requires: bash, curl. Uses -k because the mgmt cert is self-signed.

set -euo pipefail

FW="${1:-}"
USER_NAME="${2:-admin}"
[[ -z "$FW" ]] && { echo "Usage: $0 <firewall-mgmt-ip> [username]"; exit 1; }

API="https://${FW}/api/"
CURL=(curl -sk --connect-timeout 10 --max-time 120)

die()  { echo "[!] $*" >&2; exit 1; }
info() { echo "[*] $*"; }
ok()   { echo "[+] $*"; }

# Pull the text between <tag> and </tag> from XML on stdin (first match)
xml_get() { sed -n "s:.*<$1>\([^<]*\)</$1>.*:\1:p" | head -n1; }

# Escape characters that would break XML when the password is embedded in a command
xml_escape() {
  local s="$1"
  s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"
  s="${s//\"/&quot;}"; s="${s//\'/&apos;}"
  printf '%s' "$s"
}

keygen() {  # $1=user $2=pass -> prints key or nothing
  "${CURL[@]}" -X POST "$API" \
    --data-urlencode "type=keygen" \
    --data-urlencode "user=$1" \
    --data-urlencode "password=$2" | xml_get key
}

api() {     # api <key> name=value ...  (all values URL-encoded, sent as POST)
  local key="$1"; shift
  local args=(--data-urlencode "key=$key")
  for kv in "$@"; do args+=(--data-urlencode "$kv"); done
  "${CURL[@]}" -X POST "$API" "${args[@]}"
}

# ---- Prompt for credentials ------------------------------------------------
read -rsp "Current password for '$USER_NAME' [blank = admin]: " OLD_PASS; echo
OLD_PASS="${OLD_PASS:-admin}"

while true; do
  read -rsp "New password: " NEW_PASS; echo
  read -rsp "Confirm new password: " NEW_PASS2; echo
  [[ "$NEW_PASS" != "$NEW_PASS2" ]] && { echo "[!] Passwords don't match, try again."; continue; }
  [[ ${#NEW_PASS} -lt 12 ]] && { echo "[!] Use at least 12 characters."; continue; }
  break
done
unset NEW_PASS2

# ---- 1. Authenticate --------------------------------------------------------
info "Requesting API key from $FW as '$USER_NAME'..."
KEY="$(keygen "$USER_NAME" "$OLD_PASS")"
[[ -z "$KEY" ]] && die "Login failed - wrong current password, or the API/mgmt interface isn't reachable."
ok "Authenticated."

# ---- 2. Show all local admins ----------------------------------------------
info "Local admin accounts on this firewall:"
api "$KEY" "type=config" "action=get" "xpath=/config/mgt-config/users" \
  | grep -o '<entry name="[^"]*"' | sed 's/<entry name="\(.*\)"/      - \1/' || true
echo "      (Anything you don't recognize: delete it or rotate it next.)"

# ---- 3. Hash the new password and set it -----------------------------------
info "Hashing new password on the firewall..."
ESC_PASS="$(xml_escape "$NEW_PASS")"
PHASH="$(api "$KEY" "type=op" \
  "cmd=<request><password-hash><password>${ESC_PASS}</password></password-hash></request>" \
  | xml_get phash)"
unset ESC_PASS
[[ -z "$PHASH" ]] && die "Firewall didn't return a password hash."

info "Setting new password on '$USER_NAME'..."
SET_RESP="$(api "$KEY" "type=config" "action=set" \
  "xpath=/config/mgt-config/users/entry[@name='${USER_NAME}']" \
  "element=<phash>${PHASH}</phash>")"
grep -q 'status="success"' <<<"$SET_RESP" || die "Set failed: $SET_RESP"
ok "Candidate config updated."

# ---- 4. Commit ---------------------------------------------------------------
info "Committing (this also commits any other pending changes in the candidate config)..."
COMMIT_RESP="$(api "$KEY" "type=commit" "cmd=<commit></commit>")"
JOB="$(xml_get job <<<"$COMMIT_RESP")"
if [[ -z "$JOB" ]]; then
  grep -qi "no changes" <<<"$COMMIT_RESP" && die "Commit says there were no changes - password may already be set."
  die "Commit didn't start: $COMMIT_RESP"
fi
info "Commit job $JOB started, waiting..."

for _ in $(seq 1 90); do
  sleep 4
  JOB_RESP="$(api "$KEY" "type=op" "cmd=<show><jobs><id>${JOB}</id></jobs></show>")"
  STATUS="$(xml_get status <<<"$JOB_RESP")"
  PROGRESS="$(xml_get progress <<<"$JOB_RESP")"
  printf "\r      status=%s progress=%s%%   " "$STATUS" "$PROGRESS"
  if [[ "$STATUS" == "FIN" ]]; then
    echo
    RESULT="$(xml_get result <<<"$JOB_RESP")"
    [[ "$RESULT" == "OK" ]] || die "Commit finished with result '$RESULT': $JOB_RESP"
    ok "Commit succeeded."
    break
  fi
done
[[ "${STATUS:-}" == "FIN" ]] || die "Timed out waiting for commit job $JOB - check it in the GUI (Tasks)."

# ---- 5. Verify -------------------------------------------------------------
info "Verifying..."
[[ -n "$(keygen "$USER_NAME" "$NEW_PASS")" ]] && ok "New password works." \
  || echo "[!] New password did NOT authenticate - check the GUI before logging out!"
[[ -z "$(keygen "$USER_NAME" "$OLD_PASS")" ]] && ok "Old password rejected." \
  || echo "[!] Old password still works - something didn't apply."

unset OLD_PASS NEW_PASS PHASH KEY
echo
echo "Done. Note: API keys made with the old password can keep working. Kill them in"
echo "Device > Setup > Management > Authentication Settings > 'Expire All API Keys'."
