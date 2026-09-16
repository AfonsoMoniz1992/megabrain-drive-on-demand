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
ERE_DENY="$WORK/ere-denylist.txt"
EMPTY_DENY="$WORK/empty.txt"
COMMENT_DENY="$WORK/comments.txt"
INVALID_DENY="$WORK/invalid.txt"

NONCE="zz$$$(date +%s)"
OWNER_ID="zzowner${NONCE}"
LEAK_ID="zzleak${NONCE}"
HOST_ID="zzhost${NONCE}"
HOST_FQDN="${HOST_ID}.t""s.n""et"
SLASH_ID="zz/path${NONCE}"
PROJECT_NAME="obsidian-gdrive-streaming"
PROJECT_EMAIL="${PROJECT_NAME}@users.noreply.github.com"

printf '%s\n%s\n%s\n%s\n' "$LEAK_ID" "$OWNER_ID" "$HOST_ID" "$SLASH_ID" > "$DENY"
# (?i) is valid for the matching engine and invalid as a POSIX extended regex:
# the gate must not depend on `git grep -E` to find it.
printf '(?i)%s\n' "$LEAK_ID" > "$ERE_DENY"
: > "$EMPTY_DENY"
printf '# only comments here\n\n' > "$COMMENT_DENY"
printf 'valid%s\n[unclosed\n' "$NONCE" > "$INVALID_DENY"

AUTH_ENV=("IDENTITY_DENYLIST=$DENY" "EXPECTED_IDENTITY_EMAIL=$PROJECT_EMAIL")

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
  git -C "$FIXTURE" config user.name "$PROJECT_NAME"
  git -C "$FIXTURE" config user.email "$PROJECT_EMAIL"
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

# T5 — no declared account for the identity: configuration error.
run_gate "IDENTITY_DENYLIST=$DENY"
check missing_expected_identity_email_refused 2 'no EXPECTED_IDENTITY_EMAIL'

# T6 — clean fixture with an empty exemptions file: a plain PASS.
build_fixture empty
run_gate "${AUTH_ENV[@]}"
check clean_fixture_plain_pass 0 '^identity_scan=PASS$'

# T7 — declared exemption: pass, but never a plain PASS.
build_fixture declaring
printf '%s lives here\n' "$OWNER_ID" > "$FIXTURE/notes.txt"
run_gate "${AUTH_ENV[@]}"
check declared_exception_not_plain_pass 0 'identity_scan=PASS_WITH_DECLARED_EXCEPTIONS'

# T8 — strict mode fails on the declaration alone.
run_gate "${AUTH_ENV[@]}" IDENTITY_REQUIRE_NO_EXEMPTIONS=1
check strict_mode_fails_on_declaration 1 'strict_mode_failure=.*exemptions_declared'

# T9 — identifier planted at another path.
mkdir -p "$FIXTURE/sub" && printf 'host: %s\n' "$LEAK_ID" > "$FIXTURE/sub/other.txt"
run_gate "${AUTH_ENV[@]}"
check planted_identifier_reported 1 'HIT tree sub/other.txt'
rm -rf "$FIXTURE/sub"

# T10 — the scanner's own basename at another path.
mkdir -p "$FIXTURE/sub" && printf 'host: %s\n' "$LEAK_ID" > "$FIXTURE/sub/identity_scan.py"
run_gate "${AUTH_ENV[@]}"
check same_basename_other_path_reported 1 'HIT tree sub/identity_scan.py'
rm -rf "$FIXTURE/sub"

# T11 — identifier hidden only in a file name.
printf 'nothing to see here\n' > "$FIXTURE/notes-$LEAK_ID.txt"
run_gate "${AUTH_ENV[@]}"
check filename_identifier_reported 1 'HIT tree-path'
rm -f "$FIXTURE/notes-$LEAK_ID.txt"

# T12 — co-location: an exempted value must not hide a forbidden one.
printf '%s and %s on one line\n' "$OWNER_ID" "$HOST_FQDN" > "$FIXTURE/scratch.txt"
run_gate "${AUTH_ENV[@]}"
check co_located_identifier_reported 1 'partially covered|HIT tree scratch.txt'
rm -f "$FIXTURE/scratch.txt"

# T13 — partial overlap: the exemption matches only a prefix of a forbidden value.
printf '%s.%s.%s\n' "$OWNER_ID" "t""s" "n""et" > "$FIXTURE/partial.txt"
run_gate "${AUTH_ENV[@]}"
check partial_overlap_reported 1 'partially covered'
rm -f "$FIXTURE/partial.txt"

# T14 — forbidden value placed far beyond any display truncation point.
python3 - "$FIXTURE/longline.txt" "$OWNER_ID" "$HOST_FQDN" <<'PY'
import sys
path, owner, host = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, "w", encoding="utf-8") as handle:
    handle.write(owner + " " + "x" * 400 + " " + host + "\n")
PY
run_gate "${AUTH_ENV[@]}"
check far_identifier_reported 1 'partially covered|HIT tree longline.txt'
rm -f "$FIXTURE/longline.txt"

# T15 — a deny-list pattern valid for the matcher but invalid as a POSIX ERE must
# still be matched, in the tree and in history.
printf 'host: %s\n' "$LEAK_ID" > "$FIXTURE/ere-case.txt"
git -C "$FIXTURE" add -A && git -C "$FIXTURE" commit -q -m "fixture for an ERE-incompatible pattern"
rm -f "$FIXTURE/ere-case.txt"
git -C "$FIXTURE" add -A && git -C "$FIXTURE" commit -q -m "fixture removes it from the tree"
run_gate "IDENTITY_DENYLIST=$ERE_DENY" "EXPECTED_IDENTITY_EMAIL=$PROJECT_EMAIL"
check ere_incompatible_pattern_still_matches 1 'HIT blob'

# T16 — an exemption whose pattern contains a slash behaves consistently.
build_fixture empty
printf '%s :: exemption containing a path separator\n' "$SLASH_ID" >> "$FIXTURE/scripts/identity-exemptions.txt"
printf 'value: %s\n' "$SLASH_ID" > "$FIXTURE/notes.txt"
run_gate "${AUTH_ENV[@]}"
check exemption_with_separator_ok 0 'identity_scan=PASS_WITH_DECLARED_EXCEPTIONS'
rm -f "$FIXTURE/notes.txt"

# T17 — Git identity metadata outside the policy is reported.
build_fixture empty
printf 'another line\n' >> "$FIXTURE/README.md"
git -C "$FIXTURE" add -A
GIT_AUTHOR_NAME="Some Other Person" GIT_AUTHOR_EMAIL="someone@example.test" \
  GIT_COMMITTER_NAME="Some Other Person" GIT_COMMITTER_EMAIL="someone@example.test" \
  git -C "$FIXTURE" commit -q -m "fixture with foreign identity"
run_gate "${AUTH_ENV[@]}"
check foreign_identity_reported 1 'HIT identity name'

# T18 — an allowlist-shaped address that is not the declared account is a hit.
build_fixture empty
printf 'another line\n' >> "$FIXTURE/README.md"
git -C "$FIXTURE" add -A
GIT_AUTHOR_NAME="$PROJECT_NAME" GIT_AUTHOR_EMAIL="someone-else@users.noreply.github.com" \
  GIT_COMMITTER_NAME="$PROJECT_NAME" GIT_COMMITTER_EMAIL="someone-else@users.noreply.github.com" \
  git -C "$FIXTURE" commit -q -m "fixture with another account"
run_gate "${AUTH_ENV[@]}"
check other_account_address_reported 1 'not the declared distributing account'

# T19 — metadata matching a declared exemption is KNOWN, never silenced, and blocks a plain PASS.
build_fixture declaring
EXEMPT_EMAIL="${OWNER_ID}@users.noreply.github.com"
# Every commit in this fixture carries the exempted account, so the declared
# expectation matches and the only question is how the gate reports it.
git -C "$FIXTURE" config user.email "$EXEMPT_EMAIL"
git -C "$FIXTURE" commit -q --amend --reset-author --no-edit
run_gate "IDENTITY_DENYLIST=$DENY" "EXPECTED_IDENTITY_EMAIL=$EXEMPT_EMAIL"
check exempted_identity_reported_as_known 0 'KNOWN-IDENTITY-EXCEPTION'

# T20 — node_modules is a declared scope exclusion: its content is not scanned,
# and the same content published as an artefact is caught.
build_fixture empty
mkdir -p "$FIXTURE/node_modules/pkg"
printf 'host: %s\n' "$LEAK_ID" > "$FIXTURE/node_modules/pkg/index.js"
run_gate "${AUTH_ENV[@]}"
check node_modules_not_scanned_by_declaration 0 'excluded_dirs=\.git,node_modules'
cp "$FIXTURE/node_modules/pkg/index.js" "$FIXTURE/main.js"
run_gate "${AUTH_ENV[@]}"
check bundled_leak_caught_in_artefact 1 'HIT artefact main.js'
rm -rf "$FIXTURE/node_modules" "$FIXTURE/main.js"

# T21 — smoke mode without a deny-list is possible and says it is not authoritative.
build_fixture empty
run_gate IDENTITY_ALLOW_NO_DENYLIST=1
check smoke_mode_flagged 0 'non-authoritative run'

# T22 — an annotated tag with a foreign tagger is a hit. Regression test for a
# for-each-ref format string that emitted "%x00" literally, so taggers were never
# compared against the policy while the documentation claimed they were.
build_fixture empty
GIT_COMMITTER_NAME="Foreign Tagger" GIT_COMMITTER_EMAIL="tagger@example.test" \
  git -C "$FIXTURE" tag -a "probe-$LEAK_ID" -m "annotated tag probe"
run_gate "${AUTH_ENV[@]}"
check foreign_annotated_tagger_reported 1 'HIT identity tagger'
git -C "$FIXTURE" tag -d "probe-$LEAK_ID" >/dev/null

# T23 — a deny-list listing both the slug and the full public address form is
# satisfied only when both forms are declared.
build_fixture declaring
ADDR="${OWNER_ID}@users.noreply.github.com"
printf '%s :: declared test exception, slug form\n%s :: declared test exception, full address form\n' \
  "$OWNER_ID" "$ADDR" > "$FIXTURE/scripts/identity-exemptions.txt"
printf '%s\n%s\n' "$OWNER_ID" "$ADDR" > "$WORK/two-line-denylist.txt"
git -C "$FIXTURE" config user.email "$ADDR"
git -C "$FIXTURE" commit -q --amend --reset-author --no-edit
run_gate "IDENTITY_DENYLIST=$WORK/two-line-denylist.txt" "EXPECTED_IDENTITY_EMAIL=$ADDR"
check slug_and_address_denylist_declared 0 'identity_scan=PASS_WITH_DECLARED_EXCEPTIONS'

# T24 — an empty directory carries a name but no file path.
build_fixture empty
mkdir -p "$FIXTURE/dir-$LEAK_ID"
run_gate "${AUTH_ENV[@]}"
check empty_directory_name_reported 1 "HIT tree-path dir-$LEAK_ID"
rmdir "$FIXTURE/dir-$LEAK_ID"

# T25 — content that is not UTF-8 still has to be searched.
build_fixture empty
python3 - "$FIXTURE/wide.txt" "$LEAK_ID" <<'PY'
import sys
with open(sys.argv[1], "wb") as handle:
    handle.write(("host: " + sys.argv[2] + "\n").encode("utf-16"))
PY
run_gate "${AUTH_ENV[@]}"
check utf16_content_reported 1 'utf-16'
rm -f "$FIXTURE/wide.txt"

# T26 — reference names are published too.
build_fixture empty
git -C "$FIXTURE" tag "probe-$LEAK_ID"
run_gate "${AUTH_ENV[@]}"
check ref_name_reported 1 "HIT ref refs/tags/probe-$LEAK_ID"
git -C "$FIXTURE" tag -d "probe-$LEAK_ID" >/dev/null

echo "selftest_failures=${failures}"
if [[ "$failures" -eq 0 ]]; then
  echo "identity_scan_selftest=PASS"
else
  echo "identity_scan_selftest=FAIL"
fi
exit "$failures"
