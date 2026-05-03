/**
 * Client HTTP unic pentru intregul frontend.
 *
 * Autentificarea este pe baza unui cookie HttpOnly setat de backend la /auth/login.
 * Frontend-ul NU citeste si NU stocheaza tokenul — doar `credentials: "include"`
 * face browser-ul sa il trimita automat la cererile catre backend.
 */

export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "/api/v1";

export type HttpMethod = "GET" | "POST" | "PUT" | "DELETE";

export class HttpError extends Error {
  status: number;
  body: unknown;

  constructor(status: number, message: string, body: unknown) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.body = body;
  }
}

function safeJsonParse(text: string): unknown {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export async function http<T>(
  path: string,
  opts: {
    method: HttpMethod;
    body?: unknown;
    headers?: Record<string, string>;
    timeoutMs?: number;
  } = { method: "GET" },
): Promise<T> {
  const timeoutMs = opts.timeoutMs ?? 8000;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  // Path absolut (incepe cu http) → folosit ca atare. Altfel se prefixeaza cu API_BASE_URL.
  const url = path.startsWith("http") ? path : `${API_BASE_URL}${path}`;

  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(opts.headers ?? {}),
  };
  if (opts.body !== undefined && headers["Content-Type"] === undefined) {
    headers["Content-Type"] = "application/json";
  }

  try {
    const res = await fetch(url, {
      method: opts.method,
      headers,
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      // Esential: trimite cookie-ul HttpOnly de sesiune.
      credentials: "include",
      signal: controller.signal,
    });

    const text = await res.text();
    const data = safeJsonParse(text);

    if (!res.ok) {
      const detail =
        typeof data === "object" && data && "detail" in (data as Record<string, unknown>)
          ? String((data as Record<string, unknown>).detail)
          : `HTTP ${res.status}`;
      throw new HttpError(res.status, detail, data);
    }

    return data as T;
  } catch (e: unknown) {
    if (e instanceof Error && e.name === "AbortError") {
      throw new Error("Request timeout");
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

// Helpere scurte pentru cazuri uzuale.
export const apiGet = <T>(path: string) => http<T>(path, { method: "GET" });
export const apiPost = <TReq, TRes>(path: string, body: TReq) =>
  http<TRes>(path, { method: "POST", body });
export const apiDelete = <T = void>(path: string) =>
  http<T>(path, { method: "DELETE" });
