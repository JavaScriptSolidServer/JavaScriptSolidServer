#!/usr/bin/env bash
# Grant a WebID Read/Write/Control on a pod container, keeping the existing
# authorizations in its .acl. Safe to re-run: an existing grant for the same
# WebID is replaced, not duplicated.
#
# Usage: scripts/grant-webid.sh <pod> <container> <webid>
#   e.g. scripts/grant-webid.sh test private https://alexandriaconsulting.com/files/eric_jahn.rdf#me
#
# Environment:
#   JSS_URL       server base URL (default http://localhost:4443)
#   EMAIL, PASSWORD  pod owner's login; if unset, read from ACCOUNT_FILE
#   ACCOUNT_FILE  file with email=... and password=... lines
#                 (default ~/.config/jss-dev/<pod>-account.txt)
#   MODES         space-separated acl modes (default "Read Write Control")
#
# Requires curl and jq.
set -euo pipefail

if [ $# -ne 3 ] || [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
  sed -n '8,10p' "$0" >&2
  exit 2
fi

POD=$1
CONTAINER=${2%/}
WEBID=$3
JSS_URL=${JSS_URL:-http://localhost:4443}
JSS_URL=${JSS_URL%/}
MODES=${MODES:-Read Write Control}
ACCOUNT_FILE=${ACCOUNT_FILE:-$HOME/.config/jss-dev/$POD-account.txt}

if [ -z "${EMAIL:-}" ] || [ -z "${PASSWORD:-}" ]; then
  [ -r "$ACCOUNT_FILE" ] || { echo "Set EMAIL and PASSWORD, or create $ACCOUNT_FILE" >&2; exit 1; }
  EMAIL=$(sed -n 's/^email=//p' "$ACCOUNT_FILE")
  PASSWORD=$(sed -n 's/^password=//p' "$ACCOUNT_FILE")
fi

ACL_URL="$JSS_URL/$POD/$CONTAINER/.acl"

TOKEN=$(jq -n --arg e "$EMAIL" --arg p "$PASSWORD" '{email: $e, password: $p}' \
  | curl -fsS -X POST "$JSS_URL/idp/credentials" -H 'Content-Type: application/json' --data-binary @- \
  | jq -r .access_token)
[ -n "$TOKEN" ] && [ "$TOKEN" != null ] || { echo "Login failed for $EMAIL" >&2; exit 1; }

current=$(curl -fsS "$ACL_URL" -H "Authorization: Bearer $TOKEN" -H 'Accept: application/ld+json')

# JSS only accepts ACLs as JSON-LD (application/ld+json or application/json).
updated=$(jq --arg webid "$WEBID" --arg modes "$MODES" '
  ($webid | gsub("[^A-Za-z0-9]+"; "-") | "#grant-" + .) as $id
  | .["@graph"] = ([.["@graph"][] | select(.["@id"] != $id)] + [{
      "@id": $id,
      "@type": "acl:Authorization",
      "acl:agent": {"@id": $webid},
      "acl:accessTo": {"@id": "./"},
      "acl:default": {"@id": "./"},
      "acl:mode": [$modes | split(" ")[] | select(. != "") | {"@id": ("acl:" + .)}]
    }])' <<<"$current")

printf '%s' "$updated" | curl -fsS -o /dev/null -w "PUT $ACL_URL -> %{http_code}\n" \
  -X PUT "$ACL_URL" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/ld+json' --data-binary @-

curl -fsS "$ACL_URL" -H "Authorization: Bearer $TOKEN" -H 'Accept: application/ld+json' \
  | jq -r '.["@graph"][] | "\(.["@id"])\t\(.["acl:agent"]["@id"] // .["acl:agentClass"]["@id"] // "-")\t\([.["acl:mode"][]?["@id"]] | join(","))"'
