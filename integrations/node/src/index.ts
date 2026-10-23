// @doorkeep/verify: check a doorkeep token from your backend.
//
//   import { createVerifier } from "@doorkeep/verify";
//   const dk = createVerifier({ endpoint: process.env.DOORKEEP_URL!, secret: process.env.DOORKEEP_SECRET! });
//   const r = await dk.verify(req.body["dk-response"], { action: "signup", remoteIp: req.ip });
//   if (!r.success) return res.status(403).send("Please try again");

export interface VerifyOptions {
  /** Expected action, e.g. "signup". */
  action?: string;
  /** Expected hostname of the page. */
  hostname?: string;
  /** Client IP, checked when the site has strict_ip enabled. */
  remoteIp?: string;
}

export interface VerifyResult {
  success: boolean;
  challenge_ts?: string;
  hostname?: string;
  action?: string;
  "error-codes": string[];
  score?: number;
  doorkeep?: { event_id: string; risk: number; outcome: "allow" | "challenge" | "block"; reasons: string[]; challenge: string };
  /** True when doorkeep was unreachable and failMode is "open". */
  failedOpen?: boolean;
}

export interface VerifierConfig {
  endpoint: string;
  secret: string;
  /** What to do when doorkeep cannot be reached. Default "closed". */
  failMode?: "open" | "closed";
  timeoutMs?: number;
  fetch?: typeof fetch;
}

export class DoorkeepUnavailableError extends Error {
  constructor(cause: unknown) {
    super("doorkeep: verify unavailable");
    this.name = "DoorkeepUnavailableError";
    (this as any).cause = cause;
  }
}

/** Parse a JSON body, reporting the status and a snippet of anything else. */
async function readJSON(res: Response): Promise<unknown> {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`HTTP ${res.status}, not JSON: ${text.slice(0, 80)}`);
  }
}

export function createVerifier(cfg: VerifierConfig) {
  const endpoint = cfg.endpoint.replace(/\/+$/, "");
  const f = cfg.fetch ?? fetch;
  const timeout = cfg.timeoutMs ?? 3000;

  async function post(path: string, body: Record<string, string>): Promise<Response> {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), timeout);
    try {
      return await f(endpoint + path, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(body).toString(),
        signal: ac.signal,
      });
    } finally {
      clearTimeout(t);
    }
  }

  return {
    /** Verify a token. A missing token resolves to success: false. */
    async verify(response: string | null | undefined, opts: VerifyOptions = {}): Promise<VerifyResult> {
      if (!response) return { success: false, "error-codes": ["missing-input-response"] };
      const body: Record<string, string> = { secret: cfg.secret, response };
      if (opts.action) body.expected_action = opts.action;
      if (opts.hostname) body.expected_hostname = opts.hostname;
      if (opts.remoteIp) body.remoteip = opts.remoteIp;
      // doorkeep always answers siteverify with JSON. Anything else (5xx, a
      // proxy's HTML error page, a wrong endpoint) means it was not reached.
      let result: VerifyResult;
      try {
        const res = await post("/v1/siteverify", body);
        if (res.status >= 500) throw new Error("HTTP " + res.status);
        result = (await readJSON(res)) as VerifyResult;
        if (typeof result.success !== "boolean") throw new Error("unexpected response from " + endpoint);
      } catch (e) {
        if (cfg.failMode === "open") return { success: true, "error-codes": [], failedOpen: true };
        throw new DoorkeepUnavailableError(e);
      }
      return result;
    },

    /** Label an event so the site's supervised model learns your ground truth. */
    async report(eventId: string, label: "bot" | "human"): Promise<void> {
      let j: { success: boolean; "error-codes"?: string[] };
      try {
        j = (await readJSON(await post("/v1/report", { secret: cfg.secret, event_id: eventId, label }))) as typeof j;
      } catch (e) {
        throw new DoorkeepUnavailableError(e);
      }
      if (!j.success) throw new Error("doorkeep: report failed: " + (j["error-codes"] || []).join(","));
    },
  };
}

export type Verifier = ReturnType<typeof createVerifier>;

// ---------------- Express / Connect middleware ----------------

interface MiddlewareRequest {
  body?: Record<string, unknown>;
  ip?: string;
  socket?: { remoteAddress?: string };
  doorkeep?: VerifyResult;
}
interface MiddlewareResponse {
  status(code: number): MiddlewareResponse;
  json(body: unknown): unknown;
}
type Next = (err?: unknown) => void;

export interface MiddlewareOptions {
  /** Expected action; the token must have been issued for it. */
  action?: string;
  /** Form field carrying the token. Default "dk-response". */
  field?: string;
  /** Client address for strict IP binding. Default req.ip. */
  remoteIp?: (req: MiddlewareRequest) => string | undefined;
  /** Called instead of the default 403 JSON response when the check fails. */
  onFail?: (req: MiddlewareRequest, res: MiddlewareResponse, result: VerifyResult) => void;
}

/**
 * Express (or any Connect-style) middleware that verifies the token in the
 * request body before the route runs. Needs a body parser
 * (express.urlencoded / express.json) in front of it. The result is put on
 * req.doorkeep for the route.
 *
 *   app.post("/signup", express.urlencoded({ extended: false }), doorkeep.middleware({ action: "signup" }), handler)
 */
export function middleware(v: Verifier, opts: MiddlewareOptions = {}) {
  const field = opts.field ?? "dk-response";
  return async (req: MiddlewareRequest, res: MiddlewareResponse, next: Next) => {
    const token = req.body?.[field];
    let result: VerifyResult;
    try {
      result = await v.verify(typeof token === "string" ? token : "", {
        action: opts.action,
        remoteIp: opts.remoteIp ? opts.remoteIp(req) : (req.ip ?? req.socket?.remoteAddress),
      });
    } catch (e) {
      return next(e); // doorkeep unreachable with failMode "closed"
    }
    req.doorkeep = result;
    if (result.success) return next();
    if (opts.onFail) return opts.onFail(req, res, result);
    res.status(403).json({ error: "doorkeep-check-failed" });
  };
}
