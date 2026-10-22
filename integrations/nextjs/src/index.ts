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

/**
 * Edge mode for Next.js middleware/proxy: protect paths with the hosted
 * check. Returns a Response to send, or null to continue.
 *
 *   export async function middleware(req) {
 *     return (await doorkeepGate(req)) ?? NextResponse.next();
 *   }
 *   export const config = { matcher: ["/search/:path*"] };
 */
export async function doorkeepGate(req: Request, url = process.env.DOORKEEP_URL): Promise<Response | null> {
  if (!url) throw new Error("doorkeep: set DOORKEEP_URL");
  const u = new URL(req.url);
  const res = await fetch(url.replace(/\/+$/, "") + "/v1/auth", {
    headers: {
      Cookie: req.headers.get("cookie") || "",
      "User-Agent": req.headers.get("user-agent") || "",
      Accept: req.headers.get("accept") || "",
      "X-Forwarded-Host": u.host,
      "X-Forwarded-Proto": u.protocol.replace(":", ""),
      "X-Forwarded-For": req.headers.get("x-forwarded-for") || "",
      "X-Original-URI": u.pathname + u.search,
    },
  }).catch(() => null);
  if (!res) return null; // doorkeep unreachable: fail open at the edge
  if (res.status === 200) return null;
  if (res.status === 403) return new Response("Forbidden", { status: 403 });
  if ((req.headers.get("accept") || "").includes("text/html")) {
    return Response.redirect(new URL("/_dk/challenge?rd=" + encodeURIComponent(u.pathname + u.search), u), 302);
  }
  return new Response(JSON.stringify({ error: "doorkeep-check-required" }), { status: 401, headers: { "Content-Type": "application/json" } });
}
