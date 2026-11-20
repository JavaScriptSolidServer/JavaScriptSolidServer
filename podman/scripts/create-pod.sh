#!/usr/bin/env bash
# Create a pod (account) with a generated password and save its login to
# ~/.config/jss-dev/<pod>-account.txt (mode 600), where grant-webid.sh and
# the README examples look for it. The password is never printed.
#
# Usage: scripts/create-pod.sh <pod> [email]
#   e.g. scripts/create-pod.sh billy            (email defaults to billy@localhost)
#
# Environment:
#   JSS_URL       server base URL (default http://localhost:4443)
#   ACCOUNT_FILE  where to save the login (default ~/.config/jss-dev/<pod>-account.txt)
#
# JSS 0.0.224 declares a limit of one POST /.pods per client IP per day, but
# it wasn't enforced in testing. If you get HTTP 429, `make restart` clears it.
#
# Requires curl, jq and openssl.
set -euo pipefail

if [ $# -lt 1 ] || [ $# -gt 2 ] || [ -z "$1" ]; then
  sed -n '8,9p' "$0" >&2
  exit 2
fi

POD=$1
EMAIL=${2:-$POD@localhost}
JSS_URL=${JSS_URL:-http://localhost:4443}
JSS_URL=${JSS_URL%/}
ACCOUNT_FILE=${ACCOUNT_FILE:-$HOME/.config/jss-dev/$POD-account.txt}

if [ -e "$ACCOUNT_FILE" ]; then
  echo "$ACCOUNT_FILE already exists; not overwriting it." >&2
  exit 1
fi

PASSWORD=$(openssl rand -base64 18)
body=$(jq -n --arg n "$POD" --arg e "$EMAIL" --arg p "$PASSWORD" '{name: $n, email: $e, password: $p}')

response=$(mktemp)
trap 'rm -f "$response"' EXIT
status=$(printf '%s' "$body" | curl -sS -o "$response" -w '%{http_code}' \
  -X POST "$JSS_URL/.pods" -H 'Content-Type: application/json' --data-binary @-)

if [ "$status" != 201 ]; then
  echo "Creating pod '$POD' failed (HTTP $status):" >&2
  jq -c 'del(.token)' "$response" >&2 2>/dev/null || cat "$response" >&2
  exit 1
fi

mkdir -p "$(dirname "$ACCOUNT_FILE")"
chmod 700 "$(dirname "$ACCOUNT_FILE")"
( umask 077
  { printf 'email=%s\npassword=%s\n' "$EMAIL" "$PASSWORD"
    jq -r '"webid=\(.webId)\npod=\(.podUri)"' "$response"; } > "$ACCOUNT_FILE.tmp" )
chmod 600 "$ACCOUNT_FILE.tmp" && mv "$ACCOUNT_FILE.tmp" "$ACCOUNT_FILE"

# The response also holds a long-lived token; don't print it.
jq -r '"WebID:   \(.webId)\nPod:     \(.podUri)"' "$response"
echo "Login:   $ACCOUNT_FILE"
