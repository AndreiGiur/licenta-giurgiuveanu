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
  },
): Promise<T> {
  const timeoutMs = opts.timeoutMs ?? 8000;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(path, {
      method: opts.method,
      headers: {
        "Content-Type": "application/json",
        ...(opts.headers ?? {}),
      },
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      signal: controller.signal,
    });

    const text = await res.text();
    const data = safeJsonParse(text);

    if (!res.ok) {
      const msg =
        typeof data === "object" && data && "detail" in (data as any)
          ? String((data as any).detail)
          : `HTTP ${res.status}`;
      throw new HttpError(res.status, msg, data);
    }

    return data as T;
  } catch (e: any) {
    if (e?.name === "AbortError") {
      throw new Error("Request timeout");
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}
