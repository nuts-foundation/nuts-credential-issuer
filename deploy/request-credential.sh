#!/usr/bin/env bash
# Drives the full OpenID4VCI flow headlessly: asks the Nuts node (wallet) to
# request a ServiceProviderCredential from the issuer, performs the demo login
# and consent, follows the callback, and prints the credential that lands in the
# wallet.
#
# Usage: deploy/request-credential.sh ["Organisation legal name"]
set -euo pipefail

NODE_INTERNAL=${NODE_INTERNAL:-http://localhost:18081}
ISSUER_SERVER=${ISSUER_SERVER:-http://issuer:8088}    # issuer as the node sees it
ISSUER_LOCAL=${ISSUER_LOCAL:-http://localhost:8088}   # issuer as the host sees it
NODE_PUBLIC_LOCAL=${NODE_PUBLIC_LOCAL:-http://localhost:8080}
WALLET_SUBJECT=${WALLET_SUBJECT:-wallet}
LEGAL_NAME=${1:-}

extract() { grep -oE "$1" | head -1 | sed -E "s/$2/\\1/"; }

# Resolve the wallet's did:web from the node (create the subject in Nuts Admin).
WALLET_DID=$(curl -sf "$NODE_INTERNAL/internal/vdr/v2/subject/$WALLET_SUBJECT" \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print(d[0])" 2>/dev/null || true)
if [ -z "$WALLET_DID" ]; then
  echo "Could not resolve a did:web for subject '$WALLET_SUBJECT'."
  echo "Create it in Nuts Admin (http://localhost:1305) first."
  exit 1
fi

echo "1. Asking the wallet ($WALLET_SUBJECT) to request a ServiceProviderCredential ..."
start=$(curl -sf -X POST "$NODE_INTERNAL/internal/auth/v2/$WALLET_SUBJECT/request-credential" \
  -H 'Content-Type: application/json' -d "{
    \"wallet_did\": \"$WALLET_DID\",
    \"issuer\": \"$ISSUER_SERVER\",
    \"authorization_details\": [{\"type\":\"openid_credential\",\"credential_configuration_id\":\"ServiceProviderCredential\"}],
    \"redirect_uri\": \"http://localhost/done\"
  }")
authorize_url=$(echo "$start" | python3 -c "import sys,json;print(json.load(sys.stdin)['redirect_uri'])")
# The issuer pages are served at localhost; make sure we call them there.
authorize_url=${authorize_url//$ISSUER_SERVER/$ISSUER_LOCAL}

echo "2. Opening the issuer login page ..."
login=$(curl -sfL "$authorize_url") # -L: /authorize redirects to the login page
session=$(echo "$login" | extract 'name="session" value="[^"]+"' '.*value="([^"]+)".*')
[ -n "$session" ] || { echo "could not find session on login page"; echo "$login"; exit 1; }

echo "3. Logging in (fake eHerkenning${LEGAL_NAME:+ as \"$LEGAL_NAME\"}) ..."
login_data="session=$session"
if [ -n "$LEGAL_NAME" ]; then
  login_data="$login_data&legal_name=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$LEGAL_NAME")"
fi
curl -sf -X POST "$ISSUER_LOCAL/login" -d "$login_data" >/dev/null

echo "4. Consenting to issuance ..."
redir=$(curl -sf -X POST "$ISSUER_LOCAL/consent" -d "session=$session")
action=$(echo "$redir" | extract 'action="[^"]+"' 'action="([^"]+)"')
code=$(echo "$redir" | extract 'name="code" value="[^"]+"' '.*value="([^"]+)".*')
state=$(echo "$redir" | extract 'name="state" value="[^"]+"' '.*value="([^"]+)".*')
# The action is the node's callback at the Docker hostname; reach it via localhost.
callback=${action//http:\/\/nutsnode:8080/$NODE_PUBLIC_LOCAL}

echo "5. Following the callback so the node completes token + credential exchange ..."
curl -s -o /dev/null "$callback?code=$code&state=$state"

echo "6. Reading the wallet ($WALLET_SUBJECT) ..."
# The wallet returns its credentials as JWTs; decode them to find the
# ServiceProviderCredential (its type is inside the base64 JWT payload).
for _ in $(seq 1 10); do
  vcs=$(curl -sf "$NODE_INTERNAL/internal/vcr/v2/holder/$WALLET_SUBJECT/vc" || true)
  if [ -n "$vcs" ] && printf '%s' "$vcs" | python3 -c '
import sys, json, base64
wallet_did, want_name = sys.argv[1], sys.argv[2]
try:
    jwts = json.load(sys.stdin)
except Exception:
    sys.exit(1)
def claims(jwt):
    p = jwt.split(".")[1]; p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))
def name_of(vc):
    subj = vc.get("credentialSubject", {})
    if isinstance(subj, list):
        subj = subj[0] if subj else {}
    return subj.get("name")
for jwt in jwts or []:
    vc = claims(jwt).get("vc", {})
    if "ServiceProviderCredential" not in vc.get("type", []):
        continue
    if want_name and name_of(vc) != want_name:
        continue
    print("\nServiceProviderCredential issued to", wallet_did)
    print(json.dumps(vc, indent=2))
    sys.exit(0)
sys.exit(1)
' "$WALLET_DID" "$LEGAL_NAME"; then
    exit 0
  fi
  sleep 1
done
echo "No ServiceProviderCredential found in the wallet yet. Check 'make logs'."
exit 1
