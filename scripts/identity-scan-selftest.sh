#!/usr/bin/env bash
#
# Adversarial self-test for scripts/identity-scan.sh.
#
# A gate that has never failed has not been tested. This script builds a
# disposable fixture repository and checks that the gate fails exactly when it
# should, including the two ways it was previously possible to slip past it:
# a forbidden identifier sharing a line with an exempted value, and a forbidden
# identifier planted at a path other than the scanner's own.
#
# Every sample identifier is generated at run time, so this file contains no
# literal identifier and needs no exclusion from the scan it exercises.
#
# Usage: scripts/identity-scan-selftest.sh
# Exit 0 only when every scenario behaves as documented.
#
set -euo pipefail

SCANNER_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/identity-scan.sh"
[[ -r "$SCANNER_SRC" ]] || { echo "selftest=FAIL (scanner not found)"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FIXTURE="$WORK/fixture"
DENY="$WORK/denylist.txt"

# Sample identifiers, assembled here and never written as literals. The tailnet
# domain is split so that this file does not match the pattern it tests.
NONCE="zz$$$(date +%s)"
OWNER_ID="zzowner${NONCE}"
LEAK_ID="zzleak${NONCE}"
HOST_ID="zzhost${NONCE}"
HOST_FQDN="${HOST_ID}.t""s.n""et"
printf '%s\n%s\n%s\n' "$LEAK_ID" "$OWNER_ID" "$HOST_ID" > "$DENY"

build_fixture() {   # $1 = "declaring" | "empty"
  rm -rf "$FIXTURE"
  mkdir -p "$FIXTURE/scripts"
  cp "$SCANNER_SRC" "$FIXTURE/scripts/identity-scan.sh"
  chmod +x "$FIXTURE/scripts/identity-scan.sh"
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

run_gate() {        # env assignments as arguments; prints combined output
  ( cd "$FIXTURE" && env "$@" bash scripts/identity-scan.sh . 2>&1 )
}

failures=0
check() {           # $1 name, $2 expected 0/1, $3 output, $4 expected pattern
  local name="$1" expected="$2" out="$3" pattern="$4" actual=0
  grep -qE -- "$pattern" <<<"$out" || actual=1
  if [[ "$actual" == "$expected" ]]; then
    printf 'selftest_%s=PASS\n' "$name"
  else
    printf 'selftest_%s=FAIL (exit=%s expected=%s pattern=%s)\n' "$name" "$actual" "$expected" "$pattern"
    failures=$((failures + 1))
  fi
}

# T1 — no deny-list at all: the gate must refuse to pass.
build_fixture declaring
out="$(run_gate IDENTITY_ALLOW_NO_DENYLIST=0 || true)"
check no_denylist_refused 0 "$out" 'identity_scan=FAIL \(no deny-list'

# T2 — clean fixture with a deny-list: the gate passes.
out="$(run_gate "IDENTITY_DENYLIST=$DENY" || true)"
check clean_fixture_passes 0 "$out" 'identity_scan=PASS'

# T3 — strict mode must fail because the fixture declares an exception.
out="$(run_gate "IDENTITY_DENYLIST=$DENY" IDENTITY_REQUIRE_NO_EXEMPTIONS=1 || true)"
check strict_mode_fails_on_declaration 0 "$out" 'strict_mode_failure=exemptions_declared'

# T4 — forbidden identifier at another path: must be reported.
mkdir -p "$FIXTURE/sub" && printf 'host: %s\n' "$LEAK_ID" > "$FIXTURE/sub/other.txt"
out="$(run_gate "IDENTITY_DENYLIST=$DENY" || true)"
check planted_identifier_reported 0 "$out" 'HIT tree ./sub/other.txt'
rm -rf "$FIXTURE/sub"

# T5 — the scanner's own basename at another path: must still be reported.
mkdir -p "$FIXTURE/sub" && printf 'host: %s\n' "$LEAK_ID" > "$FIXTURE/sub/identity-scan.sh"
out="$(run_gate "IDENTITY_DENYLIST=$DENY" || true)"
check same_basename_other_path_reported 0 "$out" 'HIT tree ./sub/identity-scan.sh'
rm -rf "$FIXTURE/sub"

# T6 — an exempted identifier must not hide a co-located forbidden identifier.
printf '%s and %s on one line\n' "$OWNER_ID" "$HOST_FQDN" > "$FIXTURE/scratch.txt"
out="$(run_gate "IDENTITY_DENYLIST=$DENY" || true)"
check co_located_identifier_reported 0 "$out" 'co-located'
rm -f "$FIXTURE/scratch.txt"

# T7 — an exemption without a justification fails the gate.
printf '%s\n' "$OWNER_ID" > "$FIXTURE/scripts/identity-exemptions.txt"
out="$(run_gate "IDENTITY_DENYLIST=$DENY" || true)"
check unjustified_exemption_fails 0 "$out" 'exemption_without_justification'

# T8 — a fixture with no declared exception passes even in strict mode.
build_fixture empty
out="$(run_gate "IDENTITY_DENYLIST=$DENY" IDENTITY_REQUIRE_NO_EXEMPTIONS=1 || true)"
check strict_mode_passes_without_exemptions 0 "$out" 'identity_scan=PASS'

# T9 — smoke mode without a deny-list is possible, and says it is not authoritative.
out="$(run_gate IDENTITY_ALLOW_NO_DENYLIST=1 || true)"
check smoke_mode_flagged 0 "$out" 'non-authoritative run'

# T10 — a leak committed to history (not only the working tree) is reported.
build_fixture declaring
printf 'host: %s\n' "$LEAK_ID" > "$FIXTURE/history-leak.txt"
git -C "$FIXTURE" add -A && git -C "$FIXTURE" commit -q -m "fixture with a leak"
rm -f "$FIXTURE/history-leak.txt"
git -C "$FIXTURE" add -A && git -C "$FIXTURE" commit -q -m "fixture leak removed from the tree"
out="$(run_gate "IDENTITY_DENYLIST=$DENY" || true)"
check history_leak_reported 0 "$out" 'HIT blob'

echo "selftest_failures=${failures}"
if [[ "$failures" -eq 0 ]]; then
  echo "identity_scan_selftest=PASS"
else
  echo "identity_scan_selftest=FAIL"
fi
exit "$failures"
