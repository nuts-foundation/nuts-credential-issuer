#!/usr/bin/env bash
# Interactive demo: starts an issuance and opens the issuer login page in your
# browser. You log in (editable fake eHerkenning) and consent; the script then
# waits for the ServiceProviderCredential to land in the wallet and prints it.
set -euo pipefail

NODE_INTERNAL=${NODE_INTERNAL:-http://localhost:18081}
ISSUER_SERVER=${ISSUER_SERVER:-http://issuer:8088}   # issuer as the node sees it
ISSUER_LOCAL=${ISSUER_LOCAL:-http://localhost:8088}  # issuer as the browser sees it
WALLET_SUBJECT=${WALLET_SUBJECT:-wallet}
FINAL_REDIRECT=${FINAL_REDIRECT:-http://localhost:1305}   # where the browser lands when done

WALLET_DID=$(curl -sf "$NODE_INTERNAL/internal/vdr/v2/subject/$WALLET_SUBJECT" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)[0])" 2>/dev/null || true)
if [ -z "$WALLET_DID" ]; then
  echo "Could not resolve a did:web for subject '$WALLET_SUBJECT'."
  echo "Create it in Nuts Admin (http://localhost:1305) first."
  exit 1
fi

# Snapshot the credential ids already in the wallet so we can spot the new one.
existing=$(curl -sf "$NODE_INTERNAL/internal/vcr/v2/holder/$WALLET_SUBJECT/vc" 2>/dev/null || echo '[]')
seen=$(printf '%s' "$existing" | python3 -c '
import sys, json, base64
def jti(jwt):
    p = jwt.split(".")[1]; p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p)).get("jti", "")
try:
    print(" ".join(jti(j) for j in json.load(sys.stdin)))
except Exception:
    pass
')

echo "Starting issuance for wallet $WALLET_SUBJECT ($WALLET_DID) ..."
start=$(curl -sf -X POST "$NODE_INTERNAL/internal/auth/v2/$WALLET_SUBJECT/request-credential" \
  -H 'Content-Type: application/json' -d "{
    \"wallet_did\": \"$WALLET_DID\",
    \"issuer\": \"$ISSUER_SERVER\",
    \"authorization_details\": [{\"type\":\"openid_credential\",\"credential_configuration_id\":\"ServiceProviderCredential\"}],
    \"redirect_uri\": \"$FINAL_REDIRECT\"
  }")
authorize_url=$(printf '%s' "$start" | python3 -c "import sys,json;print(json.load(sys.stdin)['redirect_uri'])")
# The authorize endpoint is advertised at the issuer's server host; rewrite it to
# the browser-reachable host.
authorize_url=${authorize_url//$ISSUER_SERVER/$ISSUER_LOCAL}

echo
echo "Open this URL in your browser, log in and consent:"
echo
echo "    $authorize_url"
echo
opener=$(command -v open || command -v xdg-open || true)
if [ -n "$opener" ]; then
  "$opener" "$authorize_url" >/dev/null 2>&1 || true
  echo "(opening it in your default browser...)"
fi

echo
echo "Waiting for the ServiceProviderCredential to arrive in the wallet (Ctrl-C to stop) ..."
for _ in $(seq 1 120); do
  vcs=$(curl -sf "$NODE_INTERNAL/internal/vcr/v2/holder/$WALLET_SUBJECT/vc" 2>/dev/null || echo '[]')
  if printf '%s' "$vcs" | SEEN="$seen" python3 -c '
import sys, os, json, base64
seen = set(os.environ.get("SEEN", "").split())
def claims(jwt):
    p = jwt.split(".")[1]; p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))
try:
    jwts = json.load(sys.stdin)
except Exception:
    sys.exit(1)
for jwt in jwts or []:
    c = claims(jwt); vc = c.get("vc", {})
    if c.get("jti") in seen:
        continue
    if "ServiceProviderCredential" in vc.get("type", []):
        print("\nIssued ServiceProviderCredential:")
        print(json.dumps(vc, indent=2))
        sys.exit(0)
sys.exit(1)
'; then
    exit 0
  fi
  sleep 2
done
echo "Timed out waiting for the credential. Did you finish login + consent in the browser?"
exit 1
