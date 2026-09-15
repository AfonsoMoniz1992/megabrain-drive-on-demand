import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const unitPath = resolve(process.cwd(), "deploy/systemd/gdrive-stream-broker.system.service");

function directives(): Map<string, string> {
  const output = new Map<string, string>();
  for (const raw of readFileSync(unitPath, "utf8").split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("[")) continue;
    const separator = line.indexOf("=");
    if (separator > 0) output.set(line.slice(0, separator), line.slice(separator + 1));
  }
  return output;
}

describe("self-hosted system broker unit", () => {
  it("runs as a dedicated account with root-controlled configuration", () => {
    const unit = directives();
    expect(unit.get("User")).toBe("gdrive-stream-broker");
    expect(unit.get("Group")).toBe("gdrive-stream-broker");
    expect(unit.get("WorkingDirectory")).toBe("/opt/gdrive-stream-broker/current");
    expect(unit.get("EnvironmentFile")).toBe("/etc/gdrive-stream-broker/runtime.env");
    // The broker's direct-entrypoint guard compares the resolved invocation
    // path with import.meta.url. Invoke it relative to the root-owned working
    // directory so a /opt/current release symlink cannot suppress startup.
    expect(unit.get("ExecStart")).toBe("/usr/bin/node broker/dist/index.js");
  });

  it("denies the Drive roots and restricts writable state structurally", () => {
    const unit = directives();
    expect(unit.get("ProtectHome")).toBe("tmpfs");
    // ProtectHome=tmpfs hides the entire host home tree in the service mount
    // namespace. Do not combine it with host /home paths in InaccessiblePaths:
    // systemd resolves the latter after constructing the tmpfs view.
    expect(unit.has("InaccessiblePaths")).toBe(false);
    expect(unit.get("StateDirectory")).toBe("gdrive-stream-broker");
    expect(unit.get("ReadWritePaths")).toBe("/var/lib/gdrive-stream-broker");
    expect(unit.get("CapabilityBoundingSet")).toBe("");
    expect(unit.get("AmbientCapabilities")).toBe("");
  });

  it("keeps the runtime narrow without embedding secret values", () => {
    const unit = directives();
    expect(unit.get("NoNewPrivileges")).toBe("yes");
    expect(unit.get("AppArmorProfile")).toBe("gdrive-stream-broker");
    expect(unit.get("PrivateMounts")).toBe("yes");
    expect(unit.get("PrivateDevices")).toBe("yes");
    expect(unit.get("RestrictAddressFamilies")).toBe("AF_UNIX AF_INET");
    expect(unit.get("ProtectSystem")).toBe("strict");
    expect(unit.get("UMask")).toBe("0077");
    expect([...directives().values()].join("\n")).not.toMatch(/(?:secret|token|password|api[_-]?key)\s*=\s*[^\s]/i);
  });
});
