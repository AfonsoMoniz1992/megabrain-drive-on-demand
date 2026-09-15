import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const acceptancePath = fileURLToPath(new URL("../deploy/post-enable-acceptance.sh", import.meta.url));

/** The MainPID the fake systemctl reports, and therefore the only legitimate listener owner. */
const MAIN_PID = 4242;

function makeDir(): string {
  return mkdtempSync(path.join(tmpdir(), "gdrive-stream-6b-"));
}

function writeExecutable(file: string, body: string): void {
  writeFileSync(file, body, { mode: 0o755 });
  chmodSync(file, 0o755);
}

type Result = { status: number | null; stdout: string; stderr: string; stopped: boolean };

type Harness = { run: () => Result };

/**
 * Build a sandbox where /proc, systemctl, ss and pgrep are stand-ins, so the real gate runs
 * end to end without touching a live host.
 */
function harness(options: {
  /** The environment the broker process was actually given, as systemd would deliver it. */
  processEnvironment: string[];
  /** Which ports answer as listening; defaults to the four the environment implies. */
  listeners?: string;
  /** Skip writing /proc/<pid>/environ at all. */
  withoutEnvironFile?: boolean;
  pgrepExit?: number;
}): Harness {
  const dir = makeDir();
  const binDir = path.join(dir, "bin");
  const procRoot = path.join(dir, "proc");
  mkdirSync(binDir);
  mkdirSync(path.join(procRoot, String(MAIN_PID)), { recursive: true });

  if (!options.withoutEnvironFile) {
    writeFileSync(path.join(procRoot, String(MAIN_PID), "environ"), options.processEnvironment.map((entry) => `${entry}\0`).join(""));
  }

  const stopLog = path.join(dir, "stopped");
  const stateFile = path.join(dir, "state");
  writeFileSync(stateFile, "active\n");

  const environmentPort = (name: string, fallback: number): number => {
    const entry = options.processEnvironment.find((candidate) => candidate.startsWith(`${name}=`));
    return entry === undefined ? fallback : Number(entry.slice(name.length + 1));
  };
  const implied = [
    environmentPort("PORT", 34003),
    environmentPort("GDRIVE_STREAM_ADMIN_PORT", 34004),
    environmentPort("GDRIVE_STREAM_GATEWAY_PORT", 34005),
    environmentPort("GDRIVE_STREAM_PRIVATE_GATEWAY_PORT", 34006),
  ];
  const listeners = options.listeners ?? implied.map((port) => `${port}:${MAIN_PID}`).join(" ");

  writeExecutable(path.join(binDir, "sudo"), '#!/usr/bin/env bash\nexec "$@"\n');
  writeExecutable(
    path.join(binDir, "systemctl"),
    `#!/usr/bin/env bash
command="$1"; shift
case "$command" in
  show) printf '%s\\n' "${MAIN_PID}" ;;
  stop) printf 'stopped\\n' >> "${stopLog}"; printf 'inactive\\n' > "${stateFile}" ;;
  is-active) cat "${stateFile}" ;;
  *) printf 'active\\n' ;;
esac
`,
  );
  writeExecutable(
    path.join(binDir, "ss"),
    `#!/usr/bin/env bash
query=""
for argument in "$@"; do
  case "$argument" in sport*) query="$argument" ;; esac
done
port="\${query##*:}"
for entry in ${listeners}; do
  if [ "\${entry%%:*}" = "$port" ]; then
    printf 'LISTEN 0 128 127.0.0.1:%s 0.0.0.0:* users:(("node",pid=%s,fd=20))\\n' "$port" "\${entry##*:}"
    exit 0
  fi
done
exit 1
`,
  );
  writeExecutable(path.join(binDir, "pgrep"), `#!/usr/bin/env bash\nexit ${options.pgrepExit ?? 1}\n`);

  const env = {
    ...process.env,
    PATH: `${binDir}:${path.dirname(process.execPath)}:/usr/bin:/bin`,
    GDRIVE_STREAM_SUDO: "sudo",
    GDRIVE_STREAM_PROC_ROOT: procRoot,
    GDRIVE_STREAM_SERVICE: "gdrive-stream-broker.service",
  };

  return {
    run: () => {
      const result = spawnSync("bash", [acceptancePath], { encoding: "utf8", env });
      return {
        status: result.status,
        stdout: result.stdout ?? "",
        stderr: result.stderr ?? "",
        stopped: existsSync(stopLog),
      };
    },
  };
}

const HEALTHY_ENVIRONMENT = [
  "PORT=34003",
  "GDRIVE_STREAM_ADMIN_PORT=34004",
  "GDRIVE_STREAM_GATEWAY_PORT=34005",
  "GDRIVE_STREAM_PRIVATE_GATEWAY_PORT=34006",
];

describe("step 6b post-enable acceptance", () => {
  it("checks the ports the process actually received and leaves a healthy service running", () => {
    const result = harness({ processEnvironment: HEALTHY_ENVIRONMENT }).run();

    expect(result.stdout).toContain("expected_listener_ports=34003 34004 34005 34006");
    expect(result.stdout).toContain("post_enable_acceptance=PASS");
    expect(result.status).toBe(0);
    expect(result.stopped).toBe(false);
  });

  it("checks the effective port even when the configuration is written in a confusing way", () => {
    // systemd turns EnvironmentFile= containing GDRIVE_STREAM_GATEWAY_PORT="3401"5 into 34015, so
    // the process environment carries 34015 and the gate must inspect 34015, never 3401.
    const result = harness({
      processEnvironment: [
        "PORT=3401",
        "GDRIVE_STREAM_ADMIN_PORT=34014",
        "GDRIVE_STREAM_GATEWAY_PORT=34015",
        "GDRIVE_STREAM_PRIVATE_GATEWAY_PORT=34016",
      ],
    }).run();

    expect(result.stdout).toContain("expected_listener_ports=3401 34014 34015 34016");
    expect(result.status).toBe(0);
    expect(result.stopped).toBe(false);
  });

  it("falls back to the documented default only when the process really lacks the variable", () => {
    const result = harness({
      processEnvironment: ["PORT=34003", "GDRIVE_STREAM_ADMIN_PORT=34004", "GDRIVE_STREAM_PRIVATE_GATEWAY_PORT=34006"],
    }).run();

    expect(result.stdout).toContain("expected_listener_ports=34003 34004 34005 34006");
    expect(result.status).toBe(0);
    expect(result.stopped).toBe(false);
  });

  it("stops the service when a variable is present but is not a number", () => {
    const result = harness({
      processEnvironment: ["PORT=34003", "GDRIVE_STREAM_ADMIN_PORT=34004", "GDRIVE_STREAM_GATEWAY_PORT=not-a-port", "GDRIVE_STREAM_PRIVATE_GATEWAY_PORT=34006"],
    }).run();

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("is set for the service but is not a number");
    expect(result.stopped).toBe(true);
  });

  it("stops the service when a variable is present but empty", () => {
    const result = harness({
      processEnvironment: ["PORT=34003", "GDRIVE_STREAM_ADMIN_PORT=34004", "GDRIVE_STREAM_GATEWAY_PORT=", "GDRIVE_STREAM_PRIVATE_GATEWAY_PORT=34006"],
    }).run();

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("is set for the service but empty");
    expect(result.stopped).toBe(true);
  });

  it("stops the service when a port is outside the usable TCP range", () => {
    const result = harness({
      processEnvironment: ["PORT=34003", "GDRIVE_STREAM_ADMIN_PORT=34004", "GDRIVE_STREAM_GATEWAY_PORT=99999", "GDRIVE_STREAM_PRIVATE_GATEWAY_PORT=34006"],
    }).run();

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("outside the usable TCP port range");
    expect(result.stopped).toBe(true);
  });

  it("stops the service when two ports resolve to the same value", () => {
    const result = harness({
      processEnvironment: ["PORT=34003", "GDRIVE_STREAM_ADMIN_PORT=34004", "GDRIVE_STREAM_GATEWAY_PORT=34003", "GDRIVE_STREAM_PRIVATE_GATEWAY_PORT=34006"],
    }).run();

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("both resolve to 34003");
    expect(result.stopped).toBe(true);
  });

  it("stops the service when the process environment cannot be read", () => {
    const result = harness({ processEnvironment: HEALTHY_ENVIRONMENT, withoutEnvironFile: true }).run();

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("cannot read the environment of pid");
    expect(result.stopped).toBe(true);
  });

  it("stops the service when a listener belongs to a different process", () => {
    const result = harness({
      processEnvironment: HEALTHY_ENVIRONMENT,
      listeners: `34003:${MAIN_PID} 34004:${MAIN_PID} 34005:9999 34006:${MAIN_PID}`,
    }).run();

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("is not owned solely by the service");
    expect(result.stopped).toBe(true);
  });

  it("stops the service when a query fails instead of treating the failure as a pass", () => {
    const result = harness({ processEnvironment: HEALTHY_ENVIRONMENT, pgrepExit: 2 }).run();

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("pgrep failed with status 2");
    expect(result.stopped).toBe(true);
  });
});
