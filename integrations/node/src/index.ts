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
      let res: Response;
      try {
        res = await post("/v1/siteverify", body);
        if (res.status >= 500) throw new Error("HTTP " + res.status);
      } catch (e) {
        if (cfg.failMode === "open") return { success: true, "error-codes": [], failedOpen: true };
        throw new DoorkeepUnavailableError(e);
      }
      return (await res.json()) as VerifyResult;
    },

    /** Label an event so the site's supervised model learns your ground truth. */
    async report(eventId: string, label: "bot" | "human"): Promise<void> {
      const res = await post("/v1/report", { secret: cfg.secret, event_id: eventId, label });
      const j = (await res.json()) as { success: boolean; "error-codes": string[] };
      if (!j.success) throw new Error("doorkeep: report failed: " + j["error-codes"].join(","));
    },
  };
}

export type Verifier = ReturnType<typeof createVerifier>;
