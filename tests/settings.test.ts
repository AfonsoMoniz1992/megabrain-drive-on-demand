import { describe, expect, it } from "vitest";
import {
  DEFAULT_BROKER_BASE_URL,
  DEFAULT_SETTINGS,
  PERSISTED_SETTING_KEYS,
  brokerBaseUrlForRuntime,
  brokerChangeInvalidatesEnrollment,
  normalizeAllowedRootName,
  normalizeBrokerBaseUrl,
  rootChangeInvalidatesEnrollment,
  toPersistedSettings
} from "../src/settings";
import { ALLOWED_PLUGIN_DATA_ROOT_KEYS, findForbiddenPersistence } from "../src/auth/persistence";

const ENROLLMENT_CODE = "ENROLL-SECRET-CODE";

describe("mobile beta settings", () => {
  it("requires an operator to configure a broker rather than targeting a personal host", () => {
    expect(DEFAULT_SETTINGS.brokerBaseUrl).toBe("");
    expect(DEFAULT_BROKER_BASE_URL).toBe("");
    expect(brokerBaseUrlForRuntime(DEFAULT_BROKER_BASE_URL)).toBe("https://broker.invalid");
    expect(DEFAULT_SETTINGS.enrollmentCode).toBe("");
  });

  it("never persists the one-time enrollment code", () => {
    const settings = { ...DEFAULT_SETTINGS, brokerBaseUrl: DEFAULT_BROKER_BASE_URL, enrollmentCode: ENROLLMENT_CODE };
    const persisted = toPersistedSettings(settings);
    expect(Object.keys(persisted)).not.toContain("enrollmentCode");
    expect(JSON.stringify(persisted)).not.toContain(ENROLLMENT_CODE);
    expect(findForbiddenPersistence(persisted)).toEqual([]);
  });

  it("persists only keys that are on the persistence allowlist", () => {
    for (const key of PERSISTED_SETTING_KEYS) {
      expect([...ALLOWED_PLUGIN_DATA_ROOT_KEYS]).toContain(key);
    }
    expect([...PERSISTED_SETTING_KEYS]).not.toContain("enrollmentCode");
    expect([...PERSISTED_SETTING_KEYS]).not.toContain("accessToken");
  });

  it("refuses to persist a non-HTTPS or malformed broker base URL", () => {
    expect(() => toPersistedSettings({ ...DEFAULT_SETTINGS, brokerBaseUrl: "http://evil.example/gdrive-stream-oauth" })).toThrow(/HTTPS/i);
    expect(() => toPersistedSettings({ ...DEFAULT_SETTINGS, brokerBaseUrl: "not a url" })).toThrow(/invalid/i);
  });

  it("clears hostile or malformed values instead of substituting a personal broker", () => {
    expect(normalizeBrokerBaseUrl("http://evil.example/gdrive-stream-oauth")).toBe("");
    expect(normalizeBrokerBaseUrl("")).toBe("");
    expect(normalizeBrokerBaseUrl("https://broker.example.test/gdrive-stream-api")).toBe("https://broker.example.test/gdrive-stream-api");
  });

  it("does not invalidate enrollment for a delayed no-op mobile field event", () => {
    const broker = "https://broker.example.test/gdrive-stream-api";
    const root = "operator-test-root";
    expect(brokerChangeInvalidatesEnrollment(broker, broker)).toBe(false);
    expect(rootChangeInvalidatesEnrollment(root, `  ${root}  `)).toBe(false);
    expect(normalizeAllowedRootName(`  ${root}  `)).toBe(root);
  });

  it("invalidates enrollment when the effective broker or root changes", () => {
    expect(brokerChangeInvalidatesEnrollment("https://broker.example.test/one", "https://broker.example.test/two")).toBe(true);
    expect(rootChangeInvalidatesEnrollment("operator-test-root", "a-different-test-root")).toBe(true);
  });
});
