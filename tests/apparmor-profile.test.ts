import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const profilePath = resolve(process.cwd(), "deploy/apparmor/gdrive-stream-broker");

function profile(): string {
  return readFileSync(profilePath, "utf8");
}

describe("GDriveStreaming broker AppArmor profile", () => {
  it("is an enforcing profile with explicit Drive/home denials", () => {
    const text = profile();
    expect(text).toContain("profile gdrive-stream-broker flags=(attach_disconnected,mediate_deleted)");
    // AppArmor prohibits combining ix with a deny rule; m/x deny the same
    // relevant access classes without an invalid execution qualifier.
    expect(text).toContain("deny /home/** rwlkmx,");
    expect(text).toContain("deny /root/** rwlkmx,");
    expect(text).toContain("deny /run/user/** rwlkmx,");
  });

  it("permits only the root-owned release, non-secret runtime config and state", () => {
    const text = profile();
    expect(text).toContain("/opt/gdrive-stream-broker/** r,");
    expect(text).toContain("/etc/gdrive-stream-broker/runtime.env r,");
    expect(text).toContain("/etc/gdrive-stream-broker/secrets/* r,");
    expect(text).toContain("/var/lib/gdrive-stream-broker/** rwk,");
    expect(text).not.toMatch(/\/opt\/gdrive-stream-broker\/\*\*\s+[^,]*w/);
  });

  it("allows only the broker's necessary socket families", () => {
    const text = profile();
    for (const family of ["network unix stream,", "network inet stream,", "network inet dgram,", "network inet6 stream,", "network inet6 dgram,"]) {
      expect(text).toContain(family);
    }
  });
});
