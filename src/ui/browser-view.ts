import { ItemView, Notice, TFile, type WorkspaceLeaf } from "obsidian";
import type { EnrollmentView } from "../auth/lease-manager";
import type { IndexedMetadata } from "../drive/metadata-index";
import { DRIVE_FOLDER_MIME } from "../drive/root-scope";
import { describeBrowserState, describeEnrollmentLabel } from "./browser-state";

/**
 * Read-only GDriveStreaming Drive browser (Obsidian ItemView).
 *
 * The view is deliberately dumb: every product rule (enrollment gate, root
 * scope, metadata-only listing, size-capped single-file download) lives in
 * `browser-state.ts` and is enforced again by the plugin host. This file only
 * draws metadata and forwards user intent, so there is no create, rename, move,
 * delete, trash or upload affordance anywhere in the UI.
 */

export const GDRIVE_STREAM_BROWSER_VIEW_TYPE = "gdrive-stream-drive-browser";

export interface GDriveStreamingBrowserHost {
  enrollment(): EnrollmentView;
  fingerprint(): string;
  /** The operator-configured Drive root these diagnostics refer to. */
  rootName(): string;
  /** The broker base URL requests actually go to, for failure diagnostics. */
  brokerBaseUrl(): string;
  /** Lists the configured root (renews the lease if needed). */
  listRoot(): Promise<IndexedMetadata[]>;
  /** Lists one in-scope folder. Refuses anything outside the root. */
  listFolder(folderId: string): Promise<IndexedMetadata[]>;
  /** Metadata-only search over what has already been listed. */
  search(query: string): IndexedMetadata[];
  /** Downloads a single file on demand under the size cap into the vault cache. */
  download(fileId: string): Promise<{ message: string; path: string }>;
  /** Runs the lease-manager enrollment flow and opens the authorization URL. */
  enroll(enrollmentCode: string): Promise<void>;
}

function messageOf(error: unknown): string {
  if (error instanceof Error && error.message) return error.message;
  return "unexpected error";
}

function formatSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export class GDriveStreamingBrowserView extends ItemView {
  private rows: IndexedMetadata[] = [];
  private folderId: string | null = null;
  private term = "";

  constructor(leaf: WorkspaceLeaf, private readonly host: GDriveStreamingBrowserHost) {
    super(leaf);
  }

  getViewType(): string { return GDRIVE_STREAM_BROWSER_VIEW_TYPE; }
  getDisplayText(): string { return "GDriveStreaming Drive (read-only)"; }
  getIcon(): string { return "cloud"; }

  async onOpen(): Promise<void> {
    this.render();
    if (this.host.enrollment().status === "enrolled") void this.loadRoot();
  }

  render(): void {
    const container = this.contentEl;
    container.empty();
    const state = describeBrowserState(this.host.enrollment(), this.host.fingerprint(), this.host.rootName());

    container.createEl("h3", { text: "GDriveStreaming Drive (read-only)" });
    const summary = container.createDiv({ cls: "gdrive-stream-drive-summary" });
    summary.createEl("div", { text: `Status: ${describeEnrollmentLabel(state.status)}` });
    summary.createEl("div", { text: `Device fingerprint: ${state.fingerprint}` });
    summary.createEl("div", { text: state.reason });

    if (state.status === "awaiting_consent") {
      this.renderAwaitingConsent(container);
      return;
    }
    if (!state.canBrowse) {
      this.renderEnrollment(container);
      return;
    }
    this.renderBrowser(container);
  }

  /**
   * Pairing exists but no lease has been issued yet, so the enrolment form is
   * withheld (a second code would be wasted) and the operator is told to finish
   * the approval that is already waiting in the browser.
   */
  private renderAwaitingConsent(container: HTMLElement): void {
    const panel = container.createDiv({ cls: "gdrive-stream-awaiting-consent" });
    panel.createEl("h4", { text: "Waiting for Google consent" });
    panel.createEl("p", { text: "Approve read-only access in the browser window that just opened. Enrolment completes only when that approval returns; until then this device holds no usable lease." });
    const retry = panel.createEl("button", { text: "Check status again" });
    retry.onclick = () => this.render();
    panel.createEl("p", { cls: "gdrive-stream-note", text: `Diagnostics: broker ${this.host.brokerBaseUrl()} · root ${this.host.rootName()}` });
  }

  private renderEnrollment(container: HTMLElement): void {
    const panel = container.createDiv({ cls: "gdrive-stream-not-enrolled" });
    panel.createEl("h4", { text: "Not enrolled" });
    panel.createEl("p", { text: "Authorise this device with a one-time enrollment code. Approving access opens your system browser; the code is used once and is never saved." });

    const input = panel.createEl("input", { type: "text", placeholder: "One-time enrollment code" });
    input.addClass("gdrive-stream-enrollment-code");
    const button = panel.createEl("button", { text: "Enroll this device" });
    button.onclick = () => {
      const code = input.value.trim();
      if (!code) { new Notice("Enter the one-time enrollment code first."); return; }
      button.setAttribute("disabled", "true");
      void (async () => {
        try {
          await this.host.enroll(code);
          input.value = "";
          new Notice(`Device enrolled. Read-only ${this.host.rootName()} access is ready.`);
          this.render();
        } catch (error) {
          new Notice(`Enrollment failed: ${messageOf(error)}`);
          button.removeAttribute("disabled");
          this.render();
        }
      })();
    };
    panel.createEl("p", { cls: "gdrive-stream-note", text: "Stored on this device: broker URL, device keys, pair id and enrollment status only." });
  }

  private renderBrowser(container: HTMLElement): void {
    const toolbar = container.createDiv({ cls: "gdrive-stream-toolbar" });

    const search = toolbar.createEl("input", { type: "search", placeholder: `Search ${this.host.rootName()} metadata` });
    search.value = this.term;
    search.oninput = () => { this.term = search.value; };
    const searchButton = toolbar.createEl("button", { text: "Search" });
    searchButton.onclick = () => {
      try {
        this.folderId = null;
        this.rows = this.host.search(this.term);
        this.render();
      } catch (error) {
        new Notice(`Search unavailable: ${messageOf(error)}`);
      }
    };

    const rootButton = toolbar.createEl("button", { text: `${this.host.rootName()} root` });
    rootButton.onclick = () => void this.loadRoot();

    toolbar.createEl("span", { cls: "gdrive-stream-readonly-badge", text: "read-only" });

    const list = container.createDiv({ cls: "gdrive-stream-drive-list" });
    if (!this.rows.length) {
      list.createEl("p", { text: this.folderId === null ? "No metadata listed yet." : "This folder is empty." });
    }
    for (const file of this.rows) {
      const isFolder = file.mimeType === DRIVE_FOLDER_MIME;
      const row = list.createDiv({ cls: "gdrive-stream-drive-item" });
      row.createSpan({ text: isFolder ? "📁 " : "☁️ " });
      row.createSpan({ cls: "gdrive-stream-drive-name", text: file.name });
      row.createSpan({
        cls: "gdrive-stream-drive-meta",
        text: ` — ${file.mimeType} · ${file.modifiedTime || "unknown time"} · ${formatSize(file.size)}`
      });
      const action = row.createEl("button", { text: isFolder ? "Open" : "Download" });
      action.onclick = () => {
        action.setAttribute("disabled", "true");
        void (async () => {
          try {
            if (isFolder) {
              const files = await this.host.listFolder(file.id);
              this.folderId = file.id;
              this.rows = files;
              this.render();
              return;
            }
            const downloaded = await this.host.download(file.id);
            new Notice(downloaded.message);
            try {
              await this.openDownloaded(downloaded.path);
            } catch (error) {
              // The bytes are already in the vault cache, so this is not a read
              // failure and must not be reported as one.
              new Notice(`Downloaded, but opening the note failed: ${messageOf(error)}`);
            }
            action.removeAttribute("disabled");
          } catch (error) {
            new Notice(`Read failed: ${messageOf(error)} ${this.diagnostics()}`);
            action.removeAttribute("disabled");
            this.render();
          }
        })();
      };
    }
    container.createEl("p", { cls: "gdrive-stream-note", text: "Metadata and on-demand single-file reads only. Nothing is created, renamed, moved, deleted or synced." });
  }

  private async loadRoot(): Promise<void> {
    try {
      this.term = "";
      this.folderId = null;
      this.rows = await this.host.listRoot();
    } catch (error) {
      new Notice(`Read failed: ${messageOf(error)} ${this.diagnostics()}`);
      this.rows = [];
    }
    this.render();
  }

  /**
   * The two configuration values a failure usually comes from, appended to
   * error notices. A truncated broker URL or a stray value in the wrong field
   * is then visible in the failure itself instead of costing an investigation.
   */
  private diagnostics(): string {
    return `[broker ${this.host.brokerBaseUrl()} · root ${this.host.rootName()}]`;
  }

  /** Opens the note that was just downloaded so a click shows its content. */
  private async openDownloaded(path: string): Promise<void> {
    const file = this.app.vault.getAbstractFileByPath(path);
    if (file instanceof TFile) {
      // "tab" keeps the read-only browser view in place; reusing the most recent
      // leaf would replace the very view the operator clicked in.
      await this.app.workspace.getLeaf("tab").openFile(file);
      return;
    }
    new Notice(`Downloaded to ${path}. Open it from the file explorer to read it.`);
  }
}
