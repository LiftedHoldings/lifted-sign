#!/usr/bin/env bash
# Lifted Sign API — quickstart in pure curl. Sends one document, end to end.
#
#   export LIFTED_SIGN_KEY=sk_live_xxx
#   ./quickstart.sh contract.pdf dana@example.com "Dana Client"
#
# Requires: curl + jq. No other dependencies. Field placement is by ANCHOR — the
# signature snaps to text that already exists in the PDF ("Signature:"), no coordinate math.
set -euo pipefail

BASE="${LIFTED_SIGN_BASE:-https://sign.example.com}"
KEY="${LIFTED_SIGN_KEY:?set LIFTED_SIGN_KEY=sk_live_...}"
PDF="${1:?usage: ./quickstart.sh <pdf> <signer-email> [signer-name] [anchor]}"
EMAIL="${2:?usage: ./quickstart.sh <pdf> <signer-email> [signer-name] [anchor]}"
NAME="${3:-$EMAIL}"
ANCHOR="${4:-Signature:}"
AUTH=(-H "Authorization: Bearer $KEY")

# 1. Create an envelope from the PDF.
AID=$(curl -fsS "${AUTH[@]}" -F "file=@${PDF};type=application/pdf" -F "name=$(basename "$PDF")" \
        "$BASE/api/mysign/agreements" | jq -r '.id')
echo "1/4  created envelope #$AID"

# 2. Add a signer.
curl -fsS "${AUTH[@]}" -H "Content-Type: application/json" \
     -d "$(jq -nc --arg n "$NAME" --arg e "$EMAIL" '{signers:[{name:$n,email:$e}]}')" \
     "$BASE/api/mysign/agreements/$AID/signers" >/dev/null
echo "2/4  added signer $EMAIL"

# 3. Place a signature by anchor — wherever the doc says "$ANCHOR".
COUNT=$(curl -fsS "${AUTH[@]}" -H "Content-Type: application/json" \
     -d "$(jq -nc --arg e "$EMAIL" --arg a "$ANCHOR" \
              '{fields:[{signer:$e,type:"signature",anchor:$a}]}')" \
     "$BASE/api/mysign/agreements/$AID/fields" | jq -r '.count // 0')
echo "3/4  placed $COUNT field(s) at anchor \"$ANCHOR\""

# 4. Send it — freezes the PDF, emails each signer a single-use link.
curl -fsS "${AUTH[@]}" -X POST "$BASE/api/mysign/agreements/$AID/send" >/dev/null
echo "4/4  sent — $EMAIL has a signing link in their inbox"
echo
echo "Track it:  $BASE · envelope #$AID"
