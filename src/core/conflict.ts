export type WriteDecision = "upload" | "conflict" | "refresh" | "noop";

export function decideWrite(input: { localChanged: boolean; baseRevision: string; remoteRevision: string }): WriteDecision {
  if (!input.localChanged) return input.baseRevision === input.remoteRevision ? "noop" : "refresh";
  return input.baseRevision === input.remoteRevision ? "upload" : "conflict";
}
