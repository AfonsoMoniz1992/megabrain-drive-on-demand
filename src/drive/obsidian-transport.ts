import { requestUrl } from "obsidian";
import type { HttpTransport, HttpRequest, HttpResponse } from "./google-drive-api";

/** Obsidian's requestUrl avoids browser CORS restrictions and works on mobile. */
export const obsidianTransport: HttpTransport = {
  async request(request: HttpRequest): Promise<HttpResponse> {
    const response = await requestUrl({
      url: request.url,
      method: request.method ?? "GET",
      headers: request.headers,
      body: request.body,
      throw: false
    });
    let json: unknown;
    try { json = response.json; } catch { json = undefined; }
    return { status: response.status, json, arrayBuffer: response.arrayBuffer, headers: response.headers };
  }
};
