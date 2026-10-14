#!/usr/bin/env bash
#
# LWS conformance scoreboard (#621) — run Touchstone against a local JSS.
#
#   scripts/lws-conformance.sh [--module all|core|auth|core/containers|<test-id>]
#                              [--port N] [--ref <touchstone git ref>]
#                              [--reports DIR] [--no-build]
#
# Starts JSS in single-user mode on a throwaway data directory as an "open
# target" (public-write root ACL, no capabilities declared), runs Erich
# Bremer's Touchstone harness against it, and leaves the EARL / HTML / JUnit
# / Markdown reports under $REPORTS. The server is stopped on exit.
#
# Runs the harness with Docker if present, otherwise builds the CLI jar with
# the bundled Maven wrapper (needs a JDK 21+). Touchstone is cloned into
# .touchstone/src (gitignored) at $REF — pinned to a known-good commit by
# default, see the note next to it.
#
# This is a scoreboard, not a gate: JSS does not implement the LWS core
# protocol yet, so expect most MUSTs to fail. Exit codes follow Touchstone:
#   0  conformant            1  non-conformant (a verdict was reached)
#   2  no verdict — harness misconfigured or server unreachable
#
# Alice and bob send no credentials on an open target, so the three auth
# suites, access grants and webhooks are reported inapplicable. Set
# TOUCHSTONE_TOKEN_ALICE / TOUCHSTONE_TOKEN_BOB and pass --capabilities
# Authentication once there is an LWS authorization server to mint them.

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MODULE=all
PORT=3456
# master's Dockerfile omits the harness-clients module added in 7b13c27
# (ebremer/touchstone#2, fix in #3). Last commit before that. Move to master
# or a tag once the fix has landed.
REF=5c49679385de2ec087787a46e533cb741c018274
REPORTS="$ROOT/.touchstone/runs"
CAPABILITIES=""
BUILD=1

while [ $# -gt 0 ]; do
  case "$1" in
    --module)       MODULE=$2; shift 2 ;;
    --port)         PORT=$2; shift 2 ;;
    --ref)          REF=$2; shift 2 ;;
    --reports)      REPORTS=$2; shift 2 ;;
    --capabilities) CAPABILITIES=$2; shift 2 ;;
    --no-build)     BUILD=0; shift ;;
    -h|--help)      sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

SRC="$ROOT/.touchstone/src"
WORK=$(mktemp -d -t jss-touchstone.XXXXXX)
DATA="$WORK/data"
BASE_URL="http://127.0.0.1:$PORT/"
JSS_PID=""

cleanup() {
  if [ -n "$JSS_PID" ] && kill -0 "$JSS_PID" 2>/dev/null; then
    kill "$JSS_PID" 2>/dev/null || true
    wait "$JSS_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- which runner -----------------------------------------------------------

RUNNER=""
if command -v docker >/dev/null 2>&1; then
  RUNNER=docker
elif command -v java >/dev/null 2>&1; then
  jv=$(java -version 2>&1 | head -1 | sed -E 's/.*"([0-9]+).*/\1/')
  if [ "${jv:-0}" -ge 21 ] 2>/dev/null; then RUNNER=jar; fi
fi
if [ -z "$RUNNER" ]; then
  echo "need either docker or a JDK 21+ on PATH to run Touchstone" >&2
  exit 2
fi

# --- fetch touchstone -------------------------------------------------------

if [ ! -d "$SRC/.git" ]; then
  mkdir -p "$(dirname "$SRC")"
  git clone -q https://github.com/ebremer/touchstone "$SRC"
fi
git -C "$SRC" fetch -q origin
git -C "$SRC" checkout -q --detach "$REF"
echo "touchstone: $(git -C "$SRC" log -1 --format='%h %ad %s' --date=short)"

# --- build ------------------------------------------------------------------

if [ "$BUILD" = 1 ]; then
  if [ "$RUNNER" = docker ]; then
    docker build -q -t touchstone-harness:local "$SRC" >/dev/null
  else
    (cd "$SRC" && ./mvnw -q -B -ntp -pl harness-cli -am -Dmaven.test.skip=true package)
  fi
fi

# --- start jss as an open target ---------------------------------------------

mkdir -p "$DATA"
# Touchstone provisions its run root by POSTing to the base URL as alice;
# the default root ACL is public-read, so seed a public-write one. The
# server honours an existing .acl rather than regenerating it.
cat > "$DATA/.acl" <<'EOF'
{
  "@context": { "acl": "http://www.w3.org/ns/auth/acl#", "foaf": "http://xmlns.com/foaf/0.1/" },
  "@graph": [{
    "@id": "#public",
    "@type": "acl:Authorization",
    "acl:agentClass": { "@id": "foaf:Agent" },
    "acl:accessTo": { "@id": "./" },
    "acl:default": { "@id": "./" },
    "acl:mode": [
      { "@id": "acl:Read" }, { "@id": "acl:Write" },
      { "@id": "acl:Append" }, { "@id": "acl:Control" }
    ]
  }]
}
EOF

node "$ROOT/bin/jss.js" start --port "$PORT" --host 127.0.0.1 --root "$DATA" \
  --no-idp --no-multi-user > "$WORK/jss.log" 2>&1 &
JSS_PID=$!
for _ in $(seq 1 60); do
  curl -sf -o /dev/null "$BASE_URL" && break
  if ! kill -0 "$JSS_PID" 2>/dev/null; then
    echo "JSS exited during startup:" >&2; cat "$WORK/jss.log" >&2; exit 2
  fi
  sleep 0.5
done
curl -sf -o /dev/null "$BASE_URL" || { echo "JSS did not come up on $BASE_URL" >&2; cat "$WORK/jss.log" >&2; exit 2; }
echo "jss: $(node "$ROOT/bin/jss.js" --version) at $BASE_URL"

# --- run --------------------------------------------------------------------

mkdir -p "$REPORTS"
caps=""
for c in ${CAPABILITIES//,/ }; do caps="${caps:+$caps, }$c"; done
printf 'targets:\n  sut:\n    baseUrl: "%s"\n    adapter: env\n    capabilities: [%s]\n' \
  "$BASE_URL" "$caps" > "$WORK/targets.yaml"

set +e
if [ "$RUNNER" = docker ]; then
  cp "$WORK/targets.yaml" "$REPORTS/targets.yaml"
  docker run --rm --network host --user "$(id -u):$(id -g)" \
    -e TOUCHSTONE_TOKEN_ALICE -e TOUCHSTONE_TOKEN_BOB \
    -e TOUCHSTONE_WEBID_ALICE -e TOUCHSTONE_WEBID_BOB \
    -v "$REPORTS:/work" \
    touchstone-harness:local \
    run --target sut --module "$MODULE" \
        --targets /work/targets.yaml --report-dir /work \
        --catalog catalog --definitions definitions
else
  (cd "$SRC" && java -jar harness-cli/target/touchstone.jar \
    run --target sut --module "$MODULE" \
        --targets "$WORK/targets.yaml" --report-dir "$REPORTS" \
        --catalog catalog --definitions definitions)
fi
code=$?
set -e

latest=$(ls -td "$REPORTS"/*/ 2>/dev/null | head -1)
echo
case $code in
  0) echo "conformant" ;;
  1) echo "not conformant (a verdict was reached — this is the scoreboard)" ;;
  *) echo "no verdict (exit $code): harness misconfigured or server unreachable" >&2
     echo "--- jss log" >&2; cat "$WORK/jss.log" >&2 ;;
esac
[ -n "$latest" ] && echo "reports: $latest"
exit "$code"
