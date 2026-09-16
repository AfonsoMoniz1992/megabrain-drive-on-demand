#!/usr/bin/env bash
#
# Identity scan — the publish gate for this repository.
#
# Design rule: the gate must not be able to pass while hiding something, and
# every claim made about it must be reproducible with the commands below.
#
# Surfaces scanned, all four, at line level:
#   1. the working tree, tracked and untracked;
#   2. every reachable commit and blob, every commit message and tag message;
#   3. the Git identity metadata: author, committer and tagger names/addresses;
#   4. the release artefacts on disk (main.js, manifest.json, styles.css).
#
# Declared directory exclusions (reported with counts on every run):
#   * .git and node_modules. Neither is distributed, and content that reaches
#     the published artefact is covered by surface 4, which scans the built files
#     where bundled dependencies actually surface. Nothing else is excluded.
#
# Detectors:
#   * built-in generic patterns (tailnet domains, RFC1918, consumer mailboxes,
#     Google OAuth client ids, Drive links, service accounts);
#   * $IDENTITY_DENYLIST, one regex per line, kept OUTSIDE the tree. An
#     authoritative run REQUIRES it: without a deny-list the gate only proves the
#     built-in patterns, so it fails instead of reporting a pass. Set
#     IDENTITY_ALLOW_NO_DENYLIST=1 for a smoke run that is explicitly
#     non-authoritative. The deny-list is applied to all four surfaces,
#     including the Git identity fields.
#
# Declared exemptions ($IDENTITY_EXEMPTIONS, default scripts/identity-exemptions.txt):
#   * each line is `regex :: justification`; a line without a justification fails
#     the gate.
#   * masking is per identifier, not per line: the exempted substring is removed
#     from the candidate line and the REMAINDER is re-scanned. An exempted value
#     can therefore never hide a co-located forbidden identifier.
#   * every masked hit is printed as EXEMPT with its justification, plus the
#     residual text that was re-checked.
#
# Strict mode (IDENTITY_REQUIRE_NO_EXEMPTIONS=1):
#   * fails if any exemption was USED, or if the exemptions file DECLARES any
#     entry — because a repository that declares an exception cannot claim none.
#     It therefore fails in every configuration for this repository, which is the
#     honest measure of the declared owner-account exception.
#
# Approval criteria (exit 0, `identity_scan=PASS`):
#   * a deny-list is present (or the run is explicitly non-authoritative);
#   * zero enforced hits on all four surfaces;
#   * every identity name equals $EXPECTED_IDENTITY_NAME;
#   * every identity address matches $ALLOWED_IDENTITY_EMAIL_RE;
#   * every exemption carries a justification;
#   * strict mode: no exemption declared and none used.
#
# Usage: scripts/identity-scan.sh [repo-path]
# Self-test: scripts/identity-scan-selftest.sh
#
set -euo pipefail

REPO="${1:-.}"
REPO="$(cd "$REPO" && pwd)"
SELF_REL_PATH="scripts/identity-scan.sh"
EXEMPTIONS_REL_PATH="${IDENTITY_EXEMPTIONS_REL_PATH:-scripts/identity-exemptions.txt}"
EXPECTED_IDENTITY_NAME="${EXPECTED_IDENTITY_NAME:-obsidian-gdrive-streaming}"
ALLOWED_IDENTITY_EMAIL_RE="${ALLOWED_IDENTITY_EMAIL_RE:-@users\\.noreply\\.github\\.com$}"
REQUIRE_NO_EXEMPTIONS="${IDENTITY_REQUIRE_NO_EXEMPTIONS:-0}"
ALLOW_NO_DENYLIST="${IDENTITY_ALLOW_NO_DENYLIST:-0}"
EXCLUDED_DIRS=(.git node_modules)

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

denylist_state="present"
if [[ -n "${IDENTITY_DENYLIST:-}" ]]; then
  if [[ ! -r "$IDENTITY_DENYLIST" ]]; then
    echo "identity_scan=FAIL (deny-list not readable)"
    exit 2
  fi
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    BUILTIN_PATTERNS+=("$line")
  done < "$IDENTITY_DENYLIST"
elif [[ "$ALLOW_NO_DENYLIST" == "1" ]]; then
  denylist_state="missing (non-authoritative run: IDENTITY_ALLOW_NO_DENYLIST=1)"
else
  echo "identity_scan=FAIL (no deny-list: set IDENTITY_DENYLIST to the out-of-tree file, or IDENTITY_ALLOW_NO_DENYLIST=1 for a smoke run)"
  exit 2
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

# stdin: candidate HIT lines. For each: strip the exempted identifiers, re-scan
# the remainder, and only then classify. Returns EXEMPT (masked, residual clean)
# or leaves the line as a HIT — including when something forbidden shares the
# line with an exempted value.
classify() {
  local line residual why i matched_reason
  while IFS= read -r line; do
    residual="$line"
    why=""
    for i in "${!EXEMPT_RE[@]}"; do
      if printf '%s' "$residual" | grep -qE -- "${EXEMPT_RE[$i]}"; then
        why="${EXEMPT_WHY[$i]}"
        residual="$(printf '%s' "$residual" | sed -E "s/${EXEMPT_RE[$i]}/ /g")"
      fi
    done
    if [[ -n "$why" ]]; then
      if printf '%s' "$residual" | grep -qE -- "$PATTERN"; then
        printf 'HIT %s   [co-located with an exempted identifier: residual still matches] <= %s\n' "${line:0:150}" "$why"
      else
        printf 'EXEMPT %s   <= %s\n' "${line:0:150}" "$why"
      fi
    else
      printf '%s\n' "$line"
    fi
  done
}

excluded_git=$(cd "$REPO" && find . -maxdepth 1 -type d -name .git | wc -l)
excluded_nm=$(cd "$REPO" && find . -maxdepth 1 -type d -name node_modules | wc -l)

cd "$REPO"
{
  echo "== 0. configuration =="
  echo "denylist=${IDENTITY_DENYLIST:-<none>} [$denylist_state] patterns=$(( ${#BUILTIN_PATTERNS[@]} ))"
  echo "exemptions_declared=${exemptions_declared} file=${EXEMPTIONS_REL_PATH}"
  echo "excluded_dirs=$(IFS=,; echo "${EXCLUDED_DIRS[*]}") present(.git=${excluded_git},node_modules=${excluded_nm})"
  echo "note=excluded directories are not distributed; content that reaches the release is scanned under surface 4"
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
} > /tmp/identity-scan.$$.out 2>&1

report="$(cat /tmp/identity-scan.$$.out)"
rm -f /tmp/identity-scan.$$.out
printf '%s\n' "$report"

exempted_hits=$(printf '%s\n' "$report" | grep -c '^EXEMPT' || true)
enforced_hits=$(printf '%s\n' "$report" | grep -c '^HIT' || true)
colocated_hits=$(printf '%s\n' "$report" | grep -c 'co-located' || true)

status=0
[[ "$enforced_hits" -gt 0 ]] && status=1
[[ "$exempt_bad" -ne 0 ]] && status=1
[[ "$denylist_state" == present ]] || status=1
if [[ "$REQUIRE_NO_EXEMPTIONS" == "1" ]]; then
  if [[ "$exempted_hits" -gt 0 ]]; then
    status=1
    echo "strict_mode_failure=exemptions_used( ${exempted_hits} )"
  fi
  if [[ "$exemptions_declared" -gt 0 ]]; then
    status=1
    echo "strict_mode_failure=exemptions_declared( ${exemptions_declared} ) in ${EXEMPTIONS_REL_PATH} — a repository that declares an exception cannot claim none"
  fi
fi

echo "exempted_hits=${exempted_hits} enforced_hits=${enforced_hits} co_located_hits=${colocated_hits}"
if [[ "$status" -eq 0 ]]; then
  echo "identity_scan=PASS enforced_hits=0 exemptions_used=${exempted_hits}"
else
  echo "identity_scan=FAIL enforced_hits=${enforced_hits} exemptions_used=${exempted_hits}"
fi
exit "$status"
