/** A minimal JSON-RPC 2.0 client over fetch, with retries for transient failures. */
export class RpcError extends Error {}

export async function rpc<T>(url: string, method: string, params: unknown[], opts: { retries?: number; headers?: Record<string, string> } = {}): Promise<T> {
  const retries = opts.retries ?? 4;
  let last: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", ...(opts.headers ?? {}) },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        signal: AbortSignal.timeout(30_000),
      });
      if (res.status === 429 || res.status >= 500) throw new RpcError(`${method}: HTTP ${res.status}`);
      const body = (await res.json()) as { result?: T; error?: { code?: number; message?: string } };
      if (body.error) throw new RpcError(`${method}: ${body.error.message ?? "error"} (${body.error.code ?? "?"})`);
      return body.result as T;
    } catch (e) {
      last = e;
      if (attempt < retries) await new Promise((r) => setTimeout(r, 500 * 2 ** attempt));
    }
  }
  throw last instanceof Error ? last : new RpcError(String(last));
}
