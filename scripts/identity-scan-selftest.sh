#!/usr/bin/env bash
#
# Adversarial self-test for scripts/identity_scan.py.
#
# Two things are verified for every scenario: the EXIT STATUS (the gate's actual
# approval criterion) and the expected line in the output. Checking only output
# text would pass a gate that prints FAIL and returns success.
#
# Every sample identifier is generated at run time, so this file contains no
# literal identifier and needs no exclusion from the scan it exercises.
#
# Usage: scripts/identity-scan-selftest.sh
#
set -euo pipefail

SCANNER_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/identity_scan.py"
[[ -r "$SCANNER_SRC" ]] || { echo "selftest=FAIL (scanner not found)"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FIXTURE="$WORK/fixture"
DENY="$WORK/denylist.txt"
EMPTY_DENY="$WORK/empty.txt"
COMMENT_DENY="$WORK/comments.txt"
INVALID_DENY="$WORK/invalid.txt"

NONCE="zz$$$(date +%s)"
OWNER_ID="zzowner${NONCE}"
LEAK_ID="zzleak${NONCE}"
HOST_ID="zzhost${NONCE}"
HOST_FQDN="${HOST_ID}.t""s.n""et"
SLASH_ID="zz/path${NONCE}"

printf '%s\n%s\n%s\n%s\n' "$LEAK_ID" "$OWNER_ID" "$HOST_ID" "$SLASH_ID" > "$DENY"
: > "$EMPTY_DENY"
printf '# only comments here\n\n' > "$COMMENT_DENY"
printf 'valid%s\n[unclosed\n' "$NONCE" > "$INVALID_DENY"

build_fixture() {   # $1 = "declaring" | "empty"
  rm -rf "$FIXTURE"
  mkdir -p "$FIXTURE/scripts"
  cp "$SCANNER_SRC" "$FIXTURE/scripts/identity_scan.py"
  chmod +x "$FIXTURE/scripts/identity_scan.py"
  if [[ "$1" == "declaring" ]]; then
    printf '%s :: declared test exception for the selftest fixture\n' "$OWNER_ID" \
      > "$FIXTURE/scripts/identity-exemptions.txt"
  else
    printf '# no declared exemptions\n' > "$FIXTURE/scripts/identity-exemptions.txt"
  fi
  printf 'Fixture repository. No identifiers here.\n' > "$FIXTURE/README.md"
  git -C "$FIXTURE" init -q
  git -C "$FIXTURE" config user.name "obsidian-gdrive-streaming"
  git -C "$FIXTURE" config user.email "obsidian-gdrive-streaming@users.noreply.github.com"
  git -C "$FIXTURE" add -A
  git -C "$FIXTURE" commit -q -m "fixture baseline"
}

LAST_RC=0
LAST_OUT=""
run_gate() {        # env assignments as arguments
  LAST_RC=0
  LAST_OUT="$( cd "$FIXTURE" && env "$@" python3 scripts/identity_scan.py . 2>&1 )" || LAST_RC=$?
}

failures=0
check() {           # $1 name, $2 expected rc, $3 expected pattern
  local name="$1" expected_rc="$2" pattern="$3"
  if [[ "$LAST_RC" == "$expected_rc" ]] && grep -qE -- "$pattern" <<<"$LAST_OUT"; then
    printf 'selftest_%s=PASS\n' "$name"
  else
    printf 'selftest_%s=FAIL (rc=%s expected_rc=%s pattern=%s)\n' "$name" "$LAST_RC" "$expected_rc" "$pattern"
    failures=$((failures + 1))
  fi
}

build_fixture declaring

# T1 — no deny-list: configuration error, exit 2.
run_gate IDENTITY_ALLOW_NO_DENYLIST=0
check no_denylist_refused 2 'no deny-list'

# T2 — empty deny-list: still a configuration error, not a pass.
run_gate "IDENTITY_DENYLIST=$EMPTY_DENY"
check empty_denylist_refused 2 'no usable pattern'

# T3 — comment-only deny-list: same.
run_gate "IDENTITY_DENYLIST=$COMMENT_DENY"
check comment_only_denylist_refused 2 'no usable pattern'

# T4 — invalid regex in the deny-list: refused, never ignored.
run_gate "IDENTITY_DENYLIST=$INVALID_DENY"
check invalid_denylist_pattern_refused 2 'invalid deny-list pattern'

# T5 — clean fixture with an empty exemptions file: a plain PASS.
build_fixture empty
run_gate "IDENTITY_DENYLIST=$DENY"
check clean_fixture_plain_pass 0 '^identity_scan=PASS$'

# T6 — declared exemption: pass, but never a plain PASS.
build_fixture declaring
printf '%s lives here\n' "$OWNER_ID" > "$FIXTURE/notes.txt"
run_gate "IDENTITY_DENYLIST=$DENY"
check declared_exception_not_plain_pass 0 'identity_scan=PASS_WITH_DECLARED_EXCEPTIONS'

# T7 — strict mode fails on the declaration alone.
run_gate "IDENTITY_DENYLIST=$DENY" IDENTITY_REQUIRE_NO_EXEMPTIONS=1
check strict_mode_fails_on_declaration 1 'strict_mode_failure=.*exemptions_declared'

# T8 — identifier planted at another path.
mkdir -p "$FIXTURE/sub" && printf 'host: %s\n' "$LEAK_ID" > "$FIXTURE/sub/other.txt"
run_gate "IDENTITY_DENYLIST=$DENY"
check planted_identifier_reported 1 'HIT tree sub/other.txt'
rm -rf "$FIXTURE/sub"

# T9 — the scanner's own basename at another path.
mkdir -p "$FIXTURE/sub" && printf 'host: %s\n' "$LEAK_ID" > "$FIXTURE/sub/identity_scan.py"
run_gate "IDENTITY_DENYLIST=$DENY"
check same_basename_other_path_reported 1 'HIT tree sub/identity_scan.py'
rm -rf "$FIXTURE/sub"

# T10 — identifier hidden only in a file name.
printf 'nothing to see here\n' > "$FIXTURE/notes-$LEAK_ID.txt"
run_gate "IDENTITY_DENYLIST=$DENY"
check filename_identifier_reported 1 'HIT tree-path'
rm -f "$FIXTURE/notes-$LEAK_ID.txt"

# T11 — co-location: an exempted value must not hide a forbidden one.
printf '%s and %s on one line\n' "$OWNER_ID" "$HOST_FQDN" > "$FIXTURE/scratch.txt"
run_gate "IDENTITY_DENYLIST=$DENY"
check co_located_identifier_reported 1 'partially covered|HIT tree scratch.txt'
rm -f "$FIXTURE/scratch.txt"

# T12 — partial overlap: the exemption matches only a prefix of a forbidden value.
printf '%s.%s.%s\n' "$OWNER_ID" "t""s" "n""et" > "$FIXTURE/partial.txt"
run_gate "IDENTITY_DENYLIST=$DENY"
check partial_overlap_reported 1 'partially covered'
rm -f "$FIXTURE/partial.txt"

# T13 — forbidden value placed far beyond any display truncation point.
python3 - "$FIXTURE/longline.txt" "$OWNER_ID" "$HOST_FQDN" <<'PY'
import sys
path, owner, host = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, "w", encoding="utf-8") as handle:
    handle.write(owner + " " + "x" * 400 + " " + host + "\n")
PY
run_gate "IDENTITY_DENYLIST=$DENY"
check far_identifier_reported 1 'partially covered|HIT tree longline.txt'
rm -f "$FIXTURE/longline.txt"

# T14 — an exemption whose pattern contains a slash behaves consistently.
build_fixture empty
printf '# none\n' > "$FIXTURE/scripts/identity-exemptions.txt"
printf '%s :: exemption containing a path separator\n' "$SLASH_ID" >> "$FIXTURE/scripts/identity-exemptions.txt"
printf 'value: %s\n' "$SLASH_ID" > "$FIXTURE/notes.txt"
run_gate "IDENTITY_DENYLIST=$DENY"
check exemption_with_separator_ok 0 'identity_scan=PASS_WITH_DECLARED_EXCEPTIONS'
rm -f "$FIXTURE/notes.txt"

# T15 — a leak that exists in history but no longer in the tree.
build_fixture declaring
printf 'host: %s\n' "$LEAK_ID" > "$FIXTURE/history-leak.txt"
git -C "$FIXTURE" add -A && git -C "$FIXTURE" commit -q -m "fixture with a leak"
rm -f "$FIXTURE/history-leak.txt"
git -C "$FIXTURE" add -A && git -C "$FIXTURE" commit -q -m "fixture leak removed from the tree"
run_gate "IDENTITY_DENYLIST=$DENY"
check history_leak_reported 1 'HIT blob'

# T16 — Git identity metadata outside the policy is reported.
build_fixture empty
printf 'another line\n' >> "$FIXTURE/README.md"
git -C "$FIXTURE" add -A
GIT_AUTHOR_NAME="Some Other Person" GIT_AUTHOR_EMAIL="someone@example.test" \
  GIT_COMMITTER_NAME="Some Other Person" GIT_COMMITTER_EMAIL="someone@example.test" \
  git -C "$FIXTURE" commit -q -m "fixture with foreign identity"
run_gate "IDENTITY_DENYLIST=$DENY"
check foreign_identity_reported 1 'HIT identity name'

# T17 — metadata matching a declared exemption is KNOWN, never silenced, and blocks a plain PASS.
build_fixture declaring
printf 'another line\n' >> "$FIXTURE/README.md"
git -C "$FIXTURE" add -A
# The policy name is kept, and the declared-exception identifier sits in the
# address: it must be reported as KNOWN, never silenced, and never a plain PASS.
GIT_AUTHOR_NAME="obsidian-gdrive-streaming" GIT_AUTHOR_EMAIL="${OWNER_ID}@users.noreply.github.com" \
  GIT_COMMITTER_NAME="obsidian-gdrive-streaming" GIT_COMMITTER_EMAIL="${OWNER_ID}@users.noreply.github.com" \
  git -C "$FIXTURE" commit -q -m "fixture with an exempted identity"
run_gate "IDENTITY_DENYLIST=$DENY"
check exempted_identity_reported_as_known 0 'KNOWN-IDENTITY-EXCEPTION'

# T18 — smoke mode without a deny-list is possible and says it is not authoritative.
build_fixture empty
run_gate IDENTITY_ALLOW_NO_DENYLIST=1
check smoke_mode_flagged 0 'non-authoritative run'

echo "selftest_failures=${failures}"
if [[ "$failures" -eq 0 ]]; then
  echo "identity_scan_selftest=PASS"
else
  echo "identity_scan_selftest=FAIL"
fi
exit "$failures"
