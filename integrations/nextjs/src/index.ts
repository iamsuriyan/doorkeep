// Config and middleware helpers (no React).

/**
 * Wrap next.config to proxy /_dk/* to doorkeep on your own origin:
 *   export default withDoorkeepProxy({ ... })
 */
export function withDoorkeepProxy<T extends { rewrites?: any }>(config: T, url = process.env.DOORKEEP_URL): T {
  if (!url) throw new Error("doorkeep: set DOORKEEP_URL");
  const target = url.replace(/\/+$/, "");
  const prev = config.rewrites;
  return {
    ...config,
    async rewrites() {
      const mine = [{ source: "/_dk/:path*", destination: `${target}/:path*` }];
      const r = typeof prev === "function" ? await prev() : prev;
      if (!r) return mine;
      if (Array.isArray(r)) return [...mine, ...r];
      return { ...r, beforeFiles: [...mine, ...(r.beforeFiles || [])] };
    },
  };
}

export interface GateOptions {
  /** doorkeep's URL (default DOORKEEP_URL). */
  url?: string;
  /**
   * The client's address. By default the last X-Forwarded-For hop, which is
   * the address your platform or reverse proxy saw (Vercel, Netlify, nginx
   * and Caddy all append it). If clients reach the Next.js server directly
   * with no proxy in front, any X-Forwarded-For is the client's own claim:
   * return the socket address here, or undefined to send none.
   */
  clientIp?: (req: Request) => string | undefined;
}

/** The last X-Forwarded-For hop: the one your own proxy appended. */
export function lastForwardedFor(req: Request): string | undefined {
  const hops = (req.headers.get("x-forwarded-for") || "").split(",").map((h) => h.trim()).filter(Boolean);
  return hops[hops.length - 1];
}

/**
 * Edge mode for Next.js middleware/proxy: protect paths with the hosted
 * check. Returns a Response to send, or null to continue.
 *
 *   export async function middleware(req) {
 *     return (await doorkeepGate(req)) ?? NextResponse.next();
 *   }
 *   export const config = { matcher: ["/search/:path*"] };
 *
 * doorkeep must list the Next.js server in trusted_proxies so it accepts the
 * forwarded address; only one hop is forwarded, never the client's chain.
 */
export async function doorkeepGate(req: Request, opts: GateOptions | string = {}): Promise<Response | null> {
  const o: GateOptions = typeof opts === "string" ? { url: opts } : opts;
  const url = o.url ?? process.env.DOORKEEP_URL;
  if (!url) throw new Error("doorkeep: set DOORKEEP_URL");
  const u = new URL(req.url);
  const headers: Record<string, string> = {
    Cookie: req.headers.get("cookie") || "",
    "User-Agent": req.headers.get("user-agent") || "",
    Accept: req.headers.get("accept") || "",
    "X-Forwarded-Host": u.host,
    "X-Forwarded-Proto": u.protocol.replace(":", ""),
    "X-Original-URI": u.pathname + u.search,
  };
  const ip = (o.clientIp ?? lastForwardedFor)(req);
  if (ip) headers["X-Forwarded-For"] = ip;
  const res = await fetch(url.replace(/\/+$/, "") + "/v1/auth", { headers }).catch(() => null);
  if (!res) return null; // doorkeep unreachable: fail open at the edge
  if (res.status === 200) return null;
  if (res.status === 403) return new Response("Forbidden", { status: 403 });
  if ((req.headers.get("accept") || "").includes("text/html")) {
    return Response.redirect(new URL("/_dk/challenge?rd=" + encodeURIComponent(u.pathname + u.search), u), 302);
  }
  return new Response(JSON.stringify({ error: "doorkeep-check-required" }), { status: 401, headers: { "Content-Type": "application/json" } });
}
