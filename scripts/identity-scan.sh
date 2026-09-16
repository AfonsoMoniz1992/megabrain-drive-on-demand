#!/usr/bin/env bash
#
# Identity scan — the publish gate for this repository.
#
# Question it answers: "can I publish this repository without leaking who runs
# it, and can I say exactly what I am claiming?" It is built so that a stricter
# auditor can disagree with your claim and still get the same facts out of it.
#
# Surfaces scanned, all four, at line level (so an exemption can be judged
# against the offending line rather than the file name):
#   1. the working tree, tracked and untracked;
#   2. every reachable commit and blob, every commit message and tag message;
#   3. the Git identity metadata: author, committer and tagger names/addresses;
#   4. the release artefacts on disk (main.js, manifest.json, styles.css).
#
# Detectors:
#   * built-in generic patterns: tailnet domains, RFC1918 addresses, consumer
#     mailbox domains, Google OAuth client ids, Drive links, service accounts;
#   * $IDENTITY_DENYLIST, a file kept OUTSIDE the tree, one regex per line. A
#     committed deny-list would itself leak what it lists. It is applied to all
#     four surfaces, the Git identity fields included.
#
# Declared exemptions:
#   * $IDENTITY_EXEMPTIONS (default scripts/identity-exemptions.txt in-tree)
#     holds `regex :: justification` lines. An exemption is honoured only with a
#     justification, and every hit it silences is printed as EXEMPT with that
#     justification. Nothing is silenced invisibly.
#   * IDENTITY_REQUIRE_NO_EXEMPTIONS=1 fails the gate if any exemption was used.
#     That is the strict mode: it is expected to fail for a repository published
#     under a personal account, and it shows exactly which declared exception is
#     carrying the difference.
#
# Self-exclusion, deliberately narrow:
#   * exactly $SELF_REL_PATH (scripts/identity-scan.sh), because the detector
#     patterns appear in it as literals;
#   * exactly $EXEMPTIONS_REL_PATH, because it must name what it exempts;
#   * there is no basename-wide or wildcard exclusion, so a file planted at any
#     other path is still scanned.
#
# Approval criteria (exit 0, `identity_scan=PASS`):
#   * zero enforced hits across the four surfaces;
#   * every author/committer/tagger name equals $EXPECTED_IDENTITY_NAME;
#   * every identity address matches $ALLOWED_IDENTITY_EMAIL_RE;
#   * every exemption in play carries a justification;
#   * and, in strict mode, no exemption was needed.
#
# Usage: scripts/identity-scan.sh [repo-path]
#
set -euo pipefail

REPO="${1:-.}"
REPO="$(cd "$REPO" && pwd)"
SELF_REL_PATH="scripts/identity-scan.sh"
EXEMPTIONS_REL_PATH="${IDENTITY_EXEMPTIONS_REL_PATH:-scripts/identity-exemptions.txt}"
EXPECTED_IDENTITY_NAME="${EXPECTED_IDENTITY_NAME:-obsidian-gdrive-streaming}"
ALLOWED_IDENTITY_EMAIL_RE="${ALLOWED_IDENTITY_EMAIL_RE:-@users\\.noreply\\.github\\.com$}"
REQUIRE_NO_EXEMPTIONS="${IDENTITY_REQUIRE_NO_EXEMPTIONS:-0}"

BUILTIN_PATTERNS=(
  '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]*\.ts\.net'
  '[A-Za-z0-9-]+\.ts\.net'
  '\b10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b'
  '\b192\.168\.[0-9]{1,3}\.[0-9]{1,3}\b'
  '\b172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}\b'
  '[A-Za-z0-9._%+-]+@(gmail|googlemail|icloud|me|outlook|hotmail|live|proton|protonmail|yahoo)\.[A-Za-z]{2,}'
  '[0-9]{6,}-[a-z0-9]{12,}\.apps\.googleusercontent\.com'
  'drive\.google\.com/(drive/)?(folders|file)/'
  '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.iam\.gserviceaccount\.com'
)

if [[ -n "${IDENTITY_DENYLIST:-}" ]]; then
  [[ -r "$IDENTITY_DENYLIST" ]] || { echo "identity_scan=FAIL (deny-list not readable)"; exit 2; }
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    BUILTIN_PATTERNS+=("$line")
  done < "$IDENTITY_DENYLIST"
fi
PATTERN="$(IFS='|'; echo "${BUILTIN_PATTERNS[*]}")"

EXEMPT_RE=()
EXEMPT_WHY=()
exemptions_declared=0
exempt_bad=0
exemptions_file="$REPO/$EXEMPTIONS_REL_PATH"
if [[ -r "$exemptions_file" ]]; then
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    pattern="${line%%::*}"
    why="${line#*::}"
    pattern="$(printf '%s' "$pattern" | sed 's/[[:space:]]*$//; s/^[[:space:]]*//')"
    why="$(printf '%s' "$why" | sed 's/^[[:space:]]*//')"
    if [[ -z "$pattern" || "$why" == "$line" || -z "$why" ]]; then
      echo "exemption_without_justification=$line"
      exempt_bad=1
      continue
    fi
    EXEMPT_RE+=("$pattern")
    EXEMPT_WHY+=("$why")
    exemptions_declared=$((exemptions_declared + 1))
  done < "$exemptions_file"
fi

# stdin: candidate hit lines (already prefixed HIT). Prints each line as EXEMPT
# with its justification when an exemption matches, otherwise unchanged.
classify() {
  local line matched
  while IFS= read -r line; do
    matched=""
    for i in "${!EXEMPT_RE[@]}"; do
      if [[ "$line" =~ ${EXEMPT_RE[$i]} ]]; then matched="${EXEMPT_WHY[$i]}"; break; fi
    done
    if [[ -n "$matched" ]]; then
      printf 'EXEMPT %s   <= %s\n' "${line:0:150}" "$matched"
    else
      printf '%s\n' "$line"
    fi
  done
}

cd "$REPO"
{
  echo "== 0. configuration =="
  echo "denylist=${IDENTITY_DENYLIST:-<none>} patterns=$(( ${#BUILTIN_PATTERNS[@]} ))"
  echo "exemptions_declared=${exemptions_declared} file=${EXEMPTIONS_REL_PATH}"
  echo "strict_mode=${REQUIRE_NO_EXEMPTIONS}"

  echo "== 1. working tree =="
  grep -RInE --exclude-dir=.git --exclude-dir=node_modules -- "$PATTERN" . 2>/dev/null \
    | grep -v "^\./${SELF_REL_PATH}:" \
    | grep -v "^\./${EXEMPTIONS_REL_PATH}:" \
    | cut -c1-180 | sed 's/^/HIT tree /' | classify || true

  echo "== 2. reachable history (blobs, commit messages, tag messages) =="
  git rev-list --all | while IFS= read -r commit; do
    git grep -InE -- "$PATTERN" "$commit" 2>/dev/null \
      | grep -v ":${SELF_REL_PATH}:" | grep -v ":${EXEMPTIONS_REL_PATH}:" \
      | cut -c1-180 | sed "s|^|HIT blob ${commit:0:12} |" || true
  done | classify
  git log --all --format='%H %B' | grep -aE -- "$PATTERN" | cut -c1-180 | sed 's/^/HIT commit message /' | classify || true
  git for-each-ref --format='%(objecttype) %(objectname)' refs/tags | while read -r type oid; do
    [[ "$type" == "tag" ]] || continue
    git cat-file -p "$oid" | sed '1,/^$/d' | grep -nE -- "$PATTERN" | cut -c1-180 | sed "s|^|HIT tag message ${oid:0:12} |" || true
  done | classify

  echo "== 3. identity metadata (author, committer, tagger) =="
  names="$(git log --all --format='%an%n%cn'; git for-each-ref --format='%(taggername)' refs/tags)"
  emails="$(git log --all --format='%ae%n%ce'; git for-each-ref --format='%(taggeremail)' refs/tags | sed 's/^<//; s/>$//')"
  printf '%s\n' "$names" | sed '/^$/d' | sort -u | grep -vxF -- "$EXPECTED_IDENTITY_NAME" | sed 's/^/HIT identity name: /' | classify || true
  printf '%s\n' "$emails" | sed '/^$/d' | sort -u | grep -vE -- "$ALLOWED_IDENTITY_EMAIL_RE" | sed 's/^/HIT identity address: /' | classify || true
  printf '%s\n' "$names" "$emails" | sed '/^$/d' | sort -u | grep -E -- "$PATTERN" | sed 's/^/HIT identity field: /' | classify || true
  echo "distinct_identity_names=$(printf '%s\n' "$names" | sed '/^$/d' | sort -u | wc -l)"
  echo "distinct_identity_addresses=$(printf '%s\n' "$emails" | sed '/^$/d' | sort -u | wc -l)"

  echo "== 4. release artefacts on disk =="
  for artefact in main.js manifest.json styles.css; do
    [[ -f "$REPO/$artefact" ]] || continue
    grep -nE -- "$PATTERN" "$REPO/$artefact" | cut -c1-180 | sed "s|^|HIT artefact ${artefact} |" || true
  done | classify
} > /tmp/identity-scan-report.$$ 2>&1

report="$(cat /tmp/identity-scan-report.$$)"
rm -f /tmp/identity-scan-report.$$
printf '%s\n' "$report"

exempted_hits=$(printf '%s\n' "$report" | grep -c '^EXEMPT' || true)
enforced_hits=$(printf '%s\n' "$report" | grep -c '^HIT' || true)

status=0
[[ "$enforced_hits" -gt 0 ]] && status=1
[[ "$exempt_bad" -ne 0 ]] && status=1
if [[ "$REQUIRE_NO_EXEMPTIONS" == "1" && "$exempted_hits" -gt 0 ]]; then
  status=1
  echo "strict_mode_failure=exemptions_used( ${exempted_hits} ) — the declared exceptions are what let this repository pass; see ${EXEMPTIONS_REL_PATH}"
fi

echo "exempted_hits=${exempted_hits} enforced_hits=${enforced_hits}"
if [[ "$status" -eq 0 ]]; then
  echo "identity_scan=PASS enforced_hits=0 exemptions=${exempted_hits}"
else
  echo "identity_scan=FAIL enforced_hits=${enforced_hits} exemptions=${exempted_hits}"
fi
exit "$status"
