#!/usr/bin/env bash
# GDrive Streaming OAuth broker — step 6b post-enable acceptance (blocking).
#
# Run immediately after the system service is enabled. It proves the service is the sole
# owner of the four configured broker listeners and the only broker process alive. Every
# failure stops the service, confirms it is inactive, and exits non-zero, so a rejected
# deployment is never left running.
#
# The four expected ports are read from the environment of the running process, not from
# the configuration file. The kernel hands back exactly the environment systemd built from
# EnvironmentFile=, so quoting, escaping, line continuations and the last-assignment rule
# never have to be re-implemented here and can never disagree with what the broker got.
# A variable that is absent from the process environment falls back to the documented
# default; a variable that is present but unusable is a failure, never a default.
#
# Overridable for testing: GDRIVE_STREAM_SERVICE, GDRIVE_STREAM_PROC_ROOT, GDRIVE_STREAM_SUDO,
# GDRIVE_STREAM_ENTRYPOINT_PATTERN.
set -u

BROKER_SERVICE="${GDRIVE_STREAM_SERVICE:-gdrive-stream-broker.service}"
PROC_ROOT="${GDRIVE_STREAM_PROC_ROOT:-/proc}"
ENTRYPOINT_PATTERN="${GDRIVE_STREAM_ENTRYPOINT_PATTERN:-broker/dist/index\.js}"
SUDO="${GDRIVE_STREAM_SUDO-sudo}"

# The broker itself refuses anything outside this range and refuses duplicate ports, so the
# gate applies the same rules instead of trusting the configuration.
MIN_PORT=1024
MAX_PORT=65535

RESOLVED_PORT=""

fail() {
  printf 'ABORT: %s\n' "$1" >&2
  $SUDO systemctl stop "$BROKER_SERVICE"
  if [ "$($SUDO systemctl is-active "$BROKER_SERVICE" 2>/dev/null || true)" != "inactive" ]; then
    printf 'STOP FAILED: %s is not inactive; stop it by hand before continuing\n' "$BROKER_SERVICE" >&2
  fi
  exit 1
}

system_main_pid=$($SUDO systemctl show -p MainPID --value "$BROKER_SERVICE" 2>/dev/null)
[ -n "${system_main_pid:-}" ] || fail "cannot query the system service MainPID"
case "$system_main_pid" in
  0 | *[!0-9]*) fail "the system service has no MainPID" ;;
esac

# /proc/<pid>/environ is NUL-delimited. Port values never contain a newline, so translating
# the separators is enough, and reading it needs the same privilege ss needs below.
environ=$($SUDO cat "$PROC_ROOT/$system_main_pid/environ" 2>/dev/null | tr '\0' '\n')
[ -n "$environ" ] || fail "cannot read the environment of pid $system_main_pid (is /proc mounted and privileged?)"

# resolve_port sets RESOLVED_PORT. It is deliberately never called inside a command
# substitution, so fail() ends the whole gate rather than a subshell.
resolve_port() {
  local name="$1" fallback="$2" raw
  if printf '%s\n' "$environ" | grep -q "^${name}="; then
    raw=$(printf '%s\n' "$environ" | sed -n "s/^${name}=//p" | tail -1)
    case "$raw" in
      '') fail "$name is set for the service but empty" ;;
      *[!0-9]*) fail "$name is set for the service but is not a number ('$raw')" ;;
    esac
    if [ "$raw" -lt "$MIN_PORT" ] || [ "$raw" -gt "$MAX_PORT" ]; then
      fail "$name=$raw is outside the usable TCP port range $MIN_PORT-$MAX_PORT"
    fi
    RESOLVED_PORT="$raw"
  else
    RESOLVED_PORT="$fallback"
  fi
}

resolve_port PORT 34003
public_port="$RESOLVED_PORT"
resolve_port GDRIVE_STREAM_ADMIN_PORT 34004
admin_port="$RESOLVED_PORT"
resolve_port GDRIVE_STREAM_GATEWAY_PORT 34005
gateway_port="$RESOLVED_PORT"
resolve_port GDRIVE_STREAM_PRIVATE_GATEWAY_PORT 34006
private_gateway_port="$RESOLVED_PORT"

seen_ports=""
for entry in \
  "PORT=$public_port" \
  "GDRIVE_STREAM_ADMIN_PORT=$admin_port" \
  "GDRIVE_STREAM_GATEWAY_PORT=$gateway_port" \
  "GDRIVE_STREAM_PRIVATE_GATEWAY_PORT=$private_gateway_port"; do
  name=${entry%%=*}
  value=${entry#*=}
  case " $seen_ports " in
    *" $value "*) fail "$name and an earlier port both resolve to $value; the broker cannot listen twice on one port" ;;
  esac
  seen_ports="$seen_ports $value"
done

printf 'expected_listener_ports=%s %s %s %s\n' "$public_port" "$admin_port" "$gateway_port" "$private_gateway_port"

# sudo is required: without it ss cannot attribute sockets to another user's process,
# which would make this check fail open with an empty owner list.
for port in "$public_port" "$admin_port" "$gateway_port" "$private_gateway_port"; do
  bound=$($SUDO ss -ltnH "sport = :$port" 2>/dev/null | awk '{print $4}' | sort -u)
  [ "$bound" = "127.0.0.1:$port" ] || fail "port $port is not bound to loopback only ('${bound:-none}')"
  owners=$($SUDO ss -ltnpH "sport = :$port" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u)
  [ "$owners" = "$system_main_pid" ] || fail "port $port is not owned solely by the service (owners '${owners:-none}', expected $system_main_pid)"
done

# No second broker-shaped node process may be running either.
if candidates=$(pgrep -f "$ENTRYPOINT_PATTERN" 2>/dev/null); then :; else
  pgrep_status=$?
  [ "$pgrep_status" -eq 1 ] || fail "pgrep failed with status $pgrep_status"
  candidates=""
fi
extra=""
for pid in $candidates; do
  [ "$pid" = "$system_main_pid" ] && continue
  comm=$(cat "/proc/$pid/comm" 2>/dev/null) || fail "cannot classify pid $pid"
  case "$comm" in node | nodejs | node-* | nodejs-*) extra="$extra $pid" ;; esac
done
[ -z "${extra# }" ] || fail "a second broker process exists (${extra# })"

printf 'post_enable_acceptance=PASS\n'
