#!/bin/sh
# Regenerates internal/p11names/names_generated.go from the miekg/pkcs11 constant
# definitions, so mechanism and return-code names stay in sync with the
# wrapper library version pinned in go.mod.
set -eu

PKCS11_VERSION=$(go list -m -f '{{.Version}}' github.com/miekg/pkcs11)
CONST="$(go env GOMODCACHE)/github.com/miekg/pkcs11@${PKCS11_VERSION}/zconst.go"
OUT="internal/p11names/names_generated.go"

{
  echo "// Code generated from github.com/miekg/pkcs11@${PKCS11_VERSION} zconst.go. DO NOT EDIT."
  echo "// Regenerate with: ./scripts/gen_names.sh"
  echo ""
  echo "package p11names"
  echo ""
  echo "// mechanismNames maps CKM_* mechanism codes to their canonical names."
  echo "var mechanismNames = map[uint]string{"
  awk '$1 ~ /^CKM_[A-Z0-9_]+$/ && $2 == "=" && $3 ~ /^0x[0-9a-fA-F]+$/ {
         if (!($3 in seen)) { seen[$3] = 1; printf "\t%s: \"%s\",\n", $3, $1 }
       }' "$CONST"
  echo "}"
  echo ""
  echo "// returnCodeNames maps CKR_* return values to their canonical names."
  echo "var returnCodeNames = map[uint]string{"
  awk '$1 ~ /^CKR_[A-Z0-9_]+$/ && $2 == "=" && $3 ~ /^0x[0-9a-fA-F]+$/ {
         if (!($3 in seen)) { seen[$3] = 1; printf "\t%s: \"%s\",\n", $3, $1 }
       }' "$CONST"
  echo "}"
} > "$OUT"

gofmt -w "$OUT"
echo "Generated $OUT"
