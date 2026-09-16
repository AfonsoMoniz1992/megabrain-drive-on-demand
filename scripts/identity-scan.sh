#!/usr/bin/env bash
#
# Identity scan for a public release of this plugin.
#
# It answers one question: "can I publish this repository without leaking who
# runs it?" Run it before every public push, tag or release.
#
# What it checks, in this order:
#   1. the working tree (every file git would ship, plus untracked ones);
#   2. every reachable commit, tree and blob in the history, and every tag object;
#   3. the Git identity metadata: author, committer and tagger names and addresses.
#
# Detectors come from two places:
#   * built-in generic patterns: tailnet domains, RFC1918 addresses, consumer
#     mailbox domains, Google OAuth client ids, Drive URLs and ids, service
#     account addresses.
#   * regexes supplied from OUTSIDE the tree, one per line, in the file named by
#     $IDENTITY_DENYLIST. Never commit that file: it holds the very identifiers
#     you are removing, and a committed denylist is itself a leak.
#
# Approval criteria (all must hold for exit 0 and `identity_scan=PASS`):
#   * zero detector hits in the tree;
#   * zero detector hits in every reachable commit, blob and tag object;
#   * every author/committer/tagger name equals $EXPECTED_IDENTITY_NAME;
#   * every author/committer/tagger address matches $ALLOWED_IDENTITY_EMAIL_RE.
#
# Usage:
#   scripts/identity-scan.sh [repo-path]
#
# Environment:
#   IDENTITY_DENYLIST          path to an out-of-tree denylist (optional)
#   EXPECTED_IDENTITY_NAME     default: obsidian-gdrive-streaming
#   ALLOWED_IDENTITY_EMAIL_RE  default: @users\.noreply\.github\.com$
#
set -euo pipefail

REPO="${1:-.}"
REPO="$(cd "$REPO" && pwd)"
EXPECTED_IDENTITY_NAME="${EXPECTED_IDENTITY_NAME:-obsidian-gdrive-streaming}"
ALLOWED_IDENTITY_EMAIL_RE="${ALLOWED_IDENTITY_EMAIL_RE:-@users\\.noreply\\.github\\.com$}"

BUILTIN_PATTERNS=(
  '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]*\.ts\.net'      # tailnet host domains
  '[A-Za-z0-9-]+\.ts\.net'
  '\b10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b'      # RFC1918
  '\b192\.168\.[0-9]{1,3}\.[0-9]{1,3}\b'
  '\b172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}\b'
  '[A-Za-z0-9._%+-]+@(gmail|googlemail|icloud|me|outlook|hotmail|live|proton|protonmail|yahoo)\.[A-Za-z]{2,}'
  '[0-9]{6,}-[a-z0-9]{12,}\.apps\.googleusercontent\.com'   # OAuth client ids
  'drive\.google\.com/(drive/)?(folders|file)/'             # Drive links
  '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.iam\.gserviceaccount\.com'
)

if [[ -n "${IDENTITY_DENYLIST:-}" ]]; then
  [[ -r "$IDENTITY_DENYLIST" ]] || { echo "identity_scan=FAIL (denylist not readable)"; exit 2; }
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    BUILTIN_PATTERNS+=("$line")
  done < "$IDENTITY_DENYLIST"
fi

PATTERN="$(IFS='|'; echo "${BUILTIN_PATTERNS[*]}")"
status=0

echo "== 1. working tree =="
# This script is excluded from its own tree scan: it necessarily contains the
# detector patterns as literals. Everything else, tracked or not, is scanned.
tree_hits="$(cd "$REPO" && grep -RIlE --exclude-dir=.git --exclude-dir=node_modules \
  --exclude=identity-scan.sh -- "$PATTERN" . 2>/dev/null || true)"
if [[ -n "$tree_hits" ]]; then
  echo "$tree_hits" | sed 's/^/HIT tree: /'
  status=1
else
  echo "tree_hits=0"
fi

echo "== 2. reachable history (blobs, commit messages, tag messages) =="
history_hits="$(
  cd "$REPO"
  git rev-list --all | while IFS= read -r commit; do
    git grep -IlE -- "$PATTERN" "$commit" 2>/dev/null | grep -v ':scripts/identity-scan.sh$' | sed "s|^|HIT ${commit:0:12}:|" || true
  done
  # commit messages
  git log --all --format='%H%x00%B' | grep -aE -- "$PATTERN" | cut -c1-120 | sed 's/^/HIT commit message /' || true
  # tag objects: the message starts after the blank line, so the tagger identity
  # line is deliberately not scanned here (section 3 owns identity metadata)
  git for-each-ref --format='%(objecttype) %(objectname)' refs/tags | while read -r type oid; do
    [[ "$type" == "tag" ]] || continue
    git cat-file -p "$oid" | sed '1,/^$/d' | grep -nE -- "$PATTERN" | sed "s|^|HIT tag message ${oid:0:12}:|" || true
  done
)"
if [[ -n "$history_hits" ]]; then
  echo "$history_hits"
  status=1
else
  echo "history_hits=0"
fi

echo "== 3. identity metadata (author, committer, tagger) =="
names="$(
  cd "$REPO"
  git log --all --format='%an%n%cn'
  git for-each-ref --format='%(taggername)' refs/tags
)"
emails="$(
  cd "$REPO"
  git log --all --format='%ae%n%ce'
  git for-each-ref --format='%(taggeremail)' refs/tags
)"
bad_names="$(printf '%s\n' "$names" | sed '/^$/d' | sort -u | grep -vxF -- "$EXPECTED_IDENTITY_NAME" || true)"
bad_emails="$(printf '%s\n' "$emails" | sed '/^$/d' | sed 's/^<//; s/>$//' | sort -u | grep -vE -- "$ALLOWED_IDENTITY_EMAIL_RE" || true)"
if [[ -n "$bad_names" ]]; then
  printf '%s\n' "$bad_names" | sed 's/^/HIT identity name (not the expected project name): /'
  status=1
fi
if [[ -n "$bad_emails" ]]; then
  printf '%s\n' "$bad_emails" | sed 's/^/HIT identity address (not the allowed pattern): /'
  status=1
fi
echo "distinct_identity_names=$(printf '%s\n' "$names" | sed '/^$/d' | sort -u | wc -l)"
echo "distinct_identity_addresses=$(printf '%s\n' "$emails" | sed '/^$/d; s/^<//; s/>$//' | sort -u | wc -l)"

echo "== 4. release artefacts on disk =="
for artefact in main.js manifest.json styles.css; do
  if [[ -f "$REPO/$artefact" ]] && grep -qE -- "$PATTERN" "$REPO/$artefact"; then
    echo "HIT artefact: $artefact"
    status=1
  fi
done

if [[ "$status" -eq 0 ]]; then
  echo "identity_scan=PASS"
else
  echo "identity_scan=FAIL"
fi
exit "$status"
