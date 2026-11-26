#!/bin/sh
set -eu

: "${GITHUB_PAT:?GITHUB_PAT is required}"

repo="${GITHUB_REPO:-ccbear3120/WenMian}"
workflow="${GITHUB_WORKFLOW:-update-rates.yml}"
ref="${GITHUB_REF_NAME:-main}"

response_file="${TMPDIR:-/tmp}/rate-dispatch-response.txt"

code=$(curl -sS -o "$response_file" -w '%{http_code}' \
  -X POST \
  -H "Authorization: Bearer $GITHUB_PAT" \
  -H "Accept: application/vnd.github+json" \
  -d "{\"ref\":\"$ref\"}" \
  "https://api.github.com/repos/$repo/actions/workflows/$workflow/dispatches") || {
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) request failed" >&2
  exit 1
}

if [ "$code" != "204" ]; then
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) HTTP $code" >&2
  cat "$response_file" >&2
  exit 1
fi

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) triggered $workflow on $ref"
