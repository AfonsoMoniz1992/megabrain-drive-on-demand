import { App, Notice, Plugin, PluginSettingTab, Setting, type WorkspaceLeaf, requestUrl } from "obsidian";
import { BrokerClient, type BrokerRequestFn } from "./auth/broker-client";
import {
  deviceFingerprint,
  type DeviceIdentity
} from "./auth/device-identity";
import { loadOrCreateDeviceIdentity, saveDeviceIdentity } from "./auth/device-identity-store";
import { LeaseManager, type EnrollmentView } from "./auth/lease-manager";
import { logoutDeviceSession } from "./auth/logout-device-session";
import { buildPersistedPluginData, toPersistedEnrollment } from "./auth/persistence";
import { publishCacheFile } from "./core/atomic-cache-write";
import { PLUGIN_CACHE_ROOT, cachePathForRemoteFile } from "./core/path";
import type { RemoteFile } from "./core/remote-index";
import { DriveReadClient } from "./drive/drive-read-client";
import { MetadataIndex, type IndexedMetadata } from "./drive/metadata-index";
import { obsidianTransport } from "./drive/obsidian-transport";
import { DriveRootScope } from "./drive/root-scope";
import { driveAccessDecision } from "./release-gate";
import {
  DEFAULT_BROKER_BASE_URL,
  DEFAULT_SETTINGS,
  allowedRootNameForRuntime,
  brokerBaseUrlForRuntime,
  brokerChangeInvalidatesEnrollment,
  normalizeAllowedRootName,
  normalizeBrokerBaseUrl,
  rootChangeInvalidatesEnrollment,
  toPersistedSettings,
  type GDriveStreamingSettings
} from "./settings";
import { LatestWriteQueue } from "./settings-write-queue";
import { BrowserController, describeBrowserState, describeEnrollmentLabel } from "./ui/browser-state";
import { GDRIVE_STREAM_BROWSER_VIEW_TYPE, GDriveStreamingBrowserView, type GDriveStreamingBrowserHost } from "./ui/browser-view";
import { EnrollmentBroadcast } from "./ui/enrollment-broadcast";

/**
 * Read-only GDriveStreaming Drive plugin (mobile beta).
 *
 * The plugin makes a Google Drive request only after the device is enrolled and
 * holds a valid device-bound lease (see `driveAccessDecision`). It persists only
 * the broker base URL, the pair id and non-secret
 * enrollment metadata; access tokens, refresh tokens, client secrets,
 * authorization codes, nonces and sealed leases are never written to disk.
 */
export default class GDriveStreamingDrivePlugin extends Plugin {
  settings: GDriveStreamingSettings = { ...DEFAULT_SETTINGS };

  private readonly browserIndex = new MetadataIndex();
  private identity!: DeviceIdentity;
  private leaseManager!: LeaseManager;
  private controller!: BrowserController;
  private currentAccessToken = "";
  private persistedPairId: string | null = null;
  private readonly settingsWrites = new LatestWriteQueue();
  private logoutInProgress = false;

  async onload(): Promise<void> {
    await this.loadSettings();
    this.setUpDrive();

    this.addSettingTab(new GDriveStreamingSettingsTab(this.app, this));
    this.registerView(GDRIVE_STREAM_BROWSER_VIEW_TYPE, (leaf: WorkspaceLeaf) => new GDriveStreamingBrowserView(leaf, this.browserHost()));
    this.addRibbonIcon("cloud", "Open GDriveStreaming Drive (read-only)", () => void this.activateBrowser());
    this.addCommand({ id: "open-browser", name: "Open read-only Drive browser", callback: () => void this.activateBrowser() });
    this.addCommand({ id: "enroll-device", name: "Enroll this device with a one-time code", callback: () => void this.activateBrowser() });
    this.addCommand({ id: "renew-lease", name: "Renew read-only Drive lease", callback: () => void this.renewLease() });
    this.addCommand({ id: "logout-device", name: "Log out and remove this device identity", callback: () => void this.logout() });

    this.registerEvent(this.app.vault.on("delete", (file) => {
      if (file.path === PLUGIN_CACHE_ROOT || file.path.startsWith(`${PLUGIN_CACHE_ROOT}/`)) {
        new Notice("Plugin cache removed locally. Google Drive was not changed.");
      }
    }));
  }

  onunload(): void {
    this.app.workspace.detachLeavesOfType(GDRIVE_STREAM_BROWSER_VIEW_TYPE);
  }

  async loadSettings(): Promise<void> {
    const raw = ((await this.loadData()) as Record<string, unknown> | null) ?? {};
    this.settings = {
      ...DEFAULT_SETTINGS,
      brokerBaseUrl: normalizeBrokerBaseUrl(typeof raw.brokerBaseUrl === "string" ? raw.brokerBaseUrl : DEFAULT_BROKER_BASE_URL),
      allowedRootName: normalizeAllowedRootName(typeof raw.allowedRootName === "string" ? raw.allowedRootName : ""),
      driveRootId: typeof raw.driveRootId === "string" ? raw.driveRootId : "",
      remoteFiles: Array.isArray(raw.remoteFiles) ? (raw.remoteFiles as RemoteFile[]) : [],
      changesPageToken: typeof raw.changesPageToken === "string" ? raw.changesPageToken : undefined,
      enrollmentCode: ""
    };

    // Legacy `raw.deviceIdentity` is deliberately ignored. Private keys are
    // loaded only from Obsidian's per-vault SecretStorage.
    this.identity = loadOrCreateDeviceIdentity(this.app.secretStorage);

    const enrollment = raw.enrollment as { pairId?: unknown } | undefined;
    this.persistedPairId = typeof enrollment?.pairId === "string" ? enrollment.pairId : null;
  }

  async saveSettings(): Promise<void> {
    // `toPersistedSettings` drops the transient enrollment code and refuses a
    // malformed broker URL; `buildPersistedPluginData` re-asserts the allowlist.
    saveDeviceIdentity(this.app.secretStorage, this.identity);
    const persisted = toPersistedSettings({ ...this.settings, remoteFiles: this.settings.remoteFiles });
    const enrollment = this.leaseManager ? this.leaseManager.enrollment : { pairId: this.persistedPairId, status: "not_enrolled" as const, expiresAtMs: null };
    const data = buildPersistedPluginData({
      brokerBaseUrl: String(persisted.brokerBaseUrl),
      allowedRootName: String(persisted.allowedRootName ?? ""),
      enrollment: toPersistedEnrollment(enrollment),
      legacy: {
        driveRootId: String(persisted.driveRootId ?? ""),
        remoteFiles: Array.isArray(persisted.remoteFiles) ? (persisted.remoteFiles as RemoteFile[]) : [],
        changesPageToken: typeof persisted.changesPageToken === "string" ? persisted.changesPageToken : undefined
      }
    });
    await this.settingsWrites.enqueue(() => this.saveData(data));
  }

  /**
   * Rebuilds the client boundary after an operator changes broker ownership.
   * An existing pairing id is intentionally discarded rather than sent to a
   * newly configured origin; enrollment must begin again at that origin.
   */
  async updateBrokerBaseUrl(value: string): Promise<void> {
    if (!brokerChangeInvalidatesEnrollment(this.settings.brokerBaseUrl, value)) return;
    this.settings.brokerBaseUrl = normalizeBrokerBaseUrl(value);
    this.persistedPairId = null;
    this.currentAccessToken = "";
    this.setUpDrive();
    await this.saveSettings();
    this.refreshBrowser();
  }

  /**
   * Applies the operator's harmless Drive folder name. The broker seals this
   * exact name into every lease and the plugin refuses a lease for any other
   * root, so changing it invalidates the current pairing.
   */
  async updateAllowedRootName(value: string): Promise<void> {
    if (!rootChangeInvalidatesEnrollment(this.settings.allowedRootName, value)) return;
    this.settings.allowedRootName = normalizeAllowedRootName(value);
    this.persistedPairId = null;
    this.currentAccessToken = "";
    this.setUpDrive();
    await this.saveSettings();
    this.refreshBrowser();
  }

  private setUpDrive(): void {
    // Production wiring mirrors the tests: the root scope resolves its root id
    // through the same read-only client it later guards queries for.
    let client: DriveReadClient;
    const configuredRootName = allowedRootNameForRuntime(this.settings.allowedRootName);
    const scope = new DriveRootScope({ listFoldersByName: (name: string) => client.listFoldersByName(name) }, configuredRootName);
    client = new DriveReadClient({ transport: obsidianTransport, accessToken: () => this.currentAccessToken, scope });

    const request: BrokerRequestFn = async (brokerRequest) => {
      const response = await requestUrl({
        url: brokerRequest.url,
        method: brokerRequest.method,
        headers: brokerRequest.headers,
        body: brokerRequest.body,
        throw: false
      });
      let json: unknown;
      try { json = response.json; } catch { json = undefined; }
      return { status: response.status, json };
    };

    this.leaseManager = new LeaseManager({
      broker: new BrokerClient({ baseUrl: brokerBaseUrlForRuntime(this.settings.brokerBaseUrl), request }),
      identity: this.identity,
      openAuthorizationUrl: (url) => { window.open(url, "_blank"); },
      rootFolderName: configuredRootName,
      initialPairId: this.persistedPairId,
      onEnrollment: (state) => { if (!this.logoutInProgress) void this.persistEnrollment(state); this.enrollmentBroadcast.notify(); }
    });
    this.controller = new BrowserController({
      source: client,
      scope,
      index: this.browserIndex,
      enrollment: () => this.leaseManager.enrollment,
      fingerprint: () => this.deviceFingerprint()
    });
  }

  /** Non-secret enrollment metadata is persisted; tokens never are. */
  private async persistEnrollment(state: EnrollmentView): Promise<void> {
    this.persistedPairId = state.pairId;
    if (this.identity) await this.saveSettings();
    this.refreshBrowser();
  }

  /**
   * Surfaces that render enrollment state subscribe here so they re-render on
   * every state change. Without it, the settings screen keeps showing the state
   * it was opened with, and the waiting-for-consent state is invisible to the
   * operator who is waiting for it.
   */
  private readonly enrollmentBroadcast = new EnrollmentBroadcast();

  onEnrollmentStateChange(listener: () => void): () => void {
    return this.enrollmentBroadcast.subscribe(listener);
  }

  enrollmentState(): EnrollmentView { return this.leaseManager.enrollment; }
  deviceFingerprint(): string { return deviceFingerprint(this.identity); }

  /** Local logout only; remote broker enrollment is intentionally not revoked here. */
  async logout(): Promise<void> {
    this.logoutInProgress = true;
    try {
      this.identity = await logoutDeviceSession({
        leaseManager: this.leaseManager,
        secretStorage: this.app.secretStorage,
        persistClearedEnrollment: async () => {
          this.persistedPairId = null;
          const persisted = toPersistedSettings({ ...this.settings, remoteFiles: this.settings.remoteFiles });
          const clearedData = buildPersistedPluginData({
            brokerBaseUrl: String(persisted.brokerBaseUrl),
            allowedRootName: String(persisted.allowedRootName ?? ""),
            enrollment: { pairId: null, status: "not_enrolled", expiresAtMs: null },
            legacy: {
              driveRootId: String(persisted.driveRootId ?? ""),
              remoteFiles: Array.isArray(persisted.remoteFiles) ? (persisted.remoteFiles as RemoteFile[]) : [],
              changesPageToken: typeof persisted.changesPageToken === "string" ? persisted.changesPageToken : undefined
            }
          });
          await this.settingsWrites.enqueue(() => this.saveData(clearedData));
        },
        clearCurrentAccessToken: () => { this.currentAccessToken = ""; }
      });
      // LeaseManager captures a DeviceIdentity at construction. Rebuild the
      // broker/Drive wiring so a later enrollment proves possession of this
      // fresh identity, never the just-cleared identity.
      this.setUpDrive();
      new Notice("Logged out. This device identity and local enrollment were removed. Re-enrol to continue.");
    } finally {
      this.logoutInProgress = false;
      this.refreshBrowser();
    }
  }

  async activateBrowser(): Promise<void> {
    const existing = this.app.workspace.getLeavesOfType(GDRIVE_STREAM_BROWSER_VIEW_TYPE)[0];
    const leaf = existing ?? this.app.workspace.getRightLeaf(false);
    if (!leaf) return;
    await leaf.setViewState({ type: GDRIVE_STREAM_BROWSER_VIEW_TYPE, active: true });
    await this.app.workspace.revealLeaf(leaf);
  }

  refreshBrowser(): void {
    for (const leaf of this.app.workspace.getLeavesOfType(GDRIVE_STREAM_BROWSER_VIEW_TYPE)) {
      const view = leaf.view;
      if (view instanceof GDriveStreamingBrowserView) view.render();
    }
  }

  private browserHost(): GDriveStreamingBrowserHost {
    return {
      enrollment: () => this.leaseManager.enrollment,
      fingerprint: () => this.deviceFingerprint(),
      rootName: () => this.settings.allowedRootName || allowedRootNameForRuntime(this.settings.allowedRootName),
      brokerBaseUrl: () => brokerBaseUrlForRuntime(this.settings.brokerBaseUrl),
      listRoot: () => this.browse(() => this.controller.openRoot()),
      listFolder: (folderId: string) => this.browse(() => this.controller.openFolder(folderId)),
      search: (query: string) => this.controller.search(query),
      download: (fileId: string) => this.downloadFile(fileId),
      enroll: (enrollmentCode: string) => this.enrollDevice(enrollmentCode)
    };
  }

  /**
   * Gate in front of every Drive request: renew the lease through the broker
   * first, then require both an enrollment and a valid lease.
   */
  private async authorizeDrive(): Promise<void> {
    if (this.leaseManager.enrollment.status !== "enrolled") {
      throw new Error("Not enrolled: enrol this device before reading Google Drive.");
    }
    try {
      this.currentAccessToken = await this.leaseManager.getValidAccessToken();
    } catch {
      this.currentAccessToken = "";
      throw new Error("Enrolment expired or was revoked. Re-enrol this device to continue.");
    }
    const decision = driveAccessDecision({ enrolled: true, hasValidLease: this.leaseManager.hasValidLease() });
    if (!decision.allowed) {
      this.currentAccessToken = "";
      throw new Error(decision.reason);
    }
  }

  private async browse<T>(operation: () => Promise<T>): Promise<T> {
    await this.authorizeDrive();
    return operation();
  }

  async enrollDevice(enrollmentCode: string): Promise<void> {
    if (this.settings.brokerBaseUrl === "") {
      throw new Error("Configure the HTTPS broker base URL in settings before enrolment.");
    }
    if (this.settings.allowedRootName === "") {
      throw new Error("Configure the Drive test-root folder name in settings before enrolment.");
    }
    // The code is transient: held in memory for the single enrollment call and
    // cleared whether it succeeds or fails. It is excluded from persistence.
    this.settings.enrollmentCode = enrollmentCode;
    try {
      await this.leaseManager.enroll(enrollmentCode);
      this.settings.enrollmentCode = "";
      await this.saveSettings();
      new Notice("Device enrolled. Read-only access is ready.");
    } catch (error) {
      this.settings.enrollmentCode = "";
      throw error;
    } finally {
      this.refreshBrowser();
    }
  }

  /** Explicit single-file download into the fixed plugin cache namespace. */
  private async downloadFile(fileId: string): Promise<{ message: string; path: string }> {
    await this.authorizeDrive();
    const downloaded = await this.controller.download(fileId);
    const path = cachePathForRemoteFile(PLUGIN_CACHE_ROOT, downloaded.fileId, downloaded.name || downloaded.fileId);
    const folder = `${PLUGIN_CACHE_ROOT}/by-id/${encodeURIComponent(downloaded.fileId)}`;
    try {
      await this.app.vault.adapter.mkdir(folder);
    } catch {
      // The folder already exists; the cache root is plugin-owned.
    }
    const bytes = downloaded.bytes;
    await publishCacheFile(
      this.app.vault.adapter,
      path,
      bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer
    );
    return {
      message: `Downloaded ${downloaded.name || downloaded.fileId} (${bytes.byteLength} bytes) to ${path}. No vault-wide sync was performed.`,
      path
    };
  }

  private async renewLease(): Promise<void> {
    if (this.leaseManager.enrollment.status !== "enrolled") {
      new Notice("Not enrolled: enrol this device with a one-time code first.");
      return;
    }
    try {
      await this.leaseManager.getValidAccessToken();
      new Notice("Read-only Drive lease renewed.");
    } catch {
      new Notice("Lease renewal failed. If the pairing expired or was revoked, re-enrol this device.");
    }
    this.refreshBrowser();
  }
}

class GDriveStreamingSettingsTab extends PluginSettingTab {
  private unsubscribeEnrollment: (() => void) | null = null;

  constructor(app: App, private readonly plugin: GDriveStreamingDrivePlugin) { super(app, plugin); }

  hide(): void {
    this.unsubscribeEnrollment?.();
    this.unsubscribeEnrollment = null;
  }

  display(): void {
    const { containerEl } = this;
    containerEl.empty();
    // Re-render on every enrollment state change. Enrolment waits for a Google
    // approval for minutes, so a screen that only renders once would keep saying
    // "Not enrolled" while the pairing is in fact alive and waiting.
    this.unsubscribeEnrollment?.();
    this.unsubscribeEnrollment = this.plugin.onEnrollmentStateChange(() => {
      if (!this.containerEl.isConnected) { this.hide(); return; }
      this.display();
    });
    containerEl.createEl("h2", { text: "GDriveStreaming Drive on Demand" });

    const state = describeBrowserState(this.plugin.enrollmentState(), this.plugin.deviceFingerprint(), this.plugin.settings.allowedRootName || "unconfigured");
    const status = containerEl.createDiv({ cls: "gdrive-stream-settings-status" });
    status.createEl("p", { text: `Enrollment status: ${describeEnrollmentLabel(state.status)}` });
    status.createEl("p", { text: "Device enrollment fingerprint (copy the full 64-character value):" });
    const fingerprintInput = status.createEl("input", { type: "text", value: state.fingerprint });
    fingerprintInput.readOnly = true;
    fingerprintInput.setAttribute("aria-label", "Device enrollment fingerprint");
    status.createEl("p", { text: state.reason });
    // The values requests will actually use. A value that was truncated, or
    // pasted into the wrong field, is visible here instead of only at the broker.
    const effectiveBroker = this.plugin.settings.brokerBaseUrl === ""
      ? "not configured — enrolment is blocked"
      : brokerBaseUrlForRuntime(this.plugin.settings.brokerBaseUrl);
    status.createEl("p", { cls: "gdrive-stream-settings-effective", text: `Effective broker base URL: ${effectiveBroker}` });
    status.createEl("p", { cls: "gdrive-stream-settings-effective", text: `Effective Drive test root: ${this.plugin.settings.allowedRootName || "not configured"}` });

    new Setting(containerEl)
      .setName("Broker base URL")
      .setDesc("HTTPS base URL of your self-hosted GDriveStreaming broker. Configure it before enrolment. The plugin contacts this broker for pairing and Google directly for read-only Drive data.")
      .addText((text) => text
        .setValue(this.plugin.settings.brokerBaseUrl)
        .onChange(async (value) => {
          if (value.trim() !== "" && normalizeBrokerBaseUrl(value) === "") {
            new Notice("Broker base URL not saved: it must be an https origin with no credentials, query, fragment or extra text appended.");
          }
          await this.plugin.updateBrokerBaseUrl(value);
        }));

    new Setting(containerEl)
      .setName("Allowed Drive test root")
      .setDesc("Exact folder name your broker seals into device leases. Use a dedicated harmless test folder, never a production vault. This must match the broker's configured root exactly.")
      .addText((text) => text
        .setValue(this.plugin.settings.allowedRootName)
        .setPlaceholder("your-harmless-test-root")
        .onChange(async (value) => {
          if (value.trim() !== "" && normalizeAllowedRootName(value) === "") {
            new Notice("Allowed Drive test root not saved: use a single folder name with no slashes, control characters or appended text.");
          }
          await this.plugin.updateAllowedRootName(value);
        }));

    // The code field is offered only from a settled not-enrolled state: while a
    // pairing is waiting for Google consent a second one-time code would be
    // consumed for nothing.
    if (state.status === "not_enrolled") {
      const codeInput = containerEl.createEl("input", { type: "text", placeholder: "One-time enrollment code" });
      const enrollButton = containerEl.createEl("button", { text: "Enrol this device" });
      enrollButton.onclick = () => {
        const code = codeInput.value.trim();
        if (!code) { new Notice("Enter the one-time enrollment code first."); return; }
        enrollButton.setAttribute("disabled", "true");
        new Notice("Enrolment started. Approve the Google request in the browser window that opens.");
        void (async () => {
          try {
            await this.plugin.enrollDevice(code);
            codeInput.value = "";
            this.display();
          } catch (error) {
            new Notice(`Enrollment failed: ${error instanceof Error ? error.message : "unexpected error"}`);
            enrollButton.removeAttribute("disabled");
          }
        })();
      };
    }
    if (state.status === "awaiting_consent") {
      const checkAgain = containerEl.createEl("button", { text: "Check status again" });
      checkAgain.onclick = () => this.display();
    }

    const openButton = containerEl.createEl("button", { text: "Open read-only Drive browser" });
    openButton.onclick = () => void this.plugin.activateBrowser();

    new Setting(containerEl)
      .setName("Log out and remove this device identity")
      .setDesc("Removes this device's local identity and pairing. It does not revoke the broker enrollment; ask an operator to revoke a lost phone remotely.")
      .addButton((button) => button.setButtonText("Log out").onClick(async () => {
        await this.plugin.logout();
        this.display();
      }));

    containerEl.createEl("p", { text: `Plugin data persists the broker base URL, pair id, enrollment metadata and cache root (${PLUGIN_CACHE_ROOT}/). Device private identity is stored separately in Obsidian SecretStorage. Access tokens, refresh tokens, client secrets and authorization codes are never written to plugin data; the enrollment code is used once and discarded.` });
    containerEl.createEl("p", { text: "This build reads metadata and downloads single files on demand only. It never creates, renames, moves, deletes, trashes or syncs anything in Google Drive." });
  }
}
