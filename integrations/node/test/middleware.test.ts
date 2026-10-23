import { describe, expect, it } from "vitest";
import { createVerifier, DoorkeepUnavailableError, middleware } from "../src/index";

function fakeFetch(handler: (body: URLSearchParams) => [number, unknown]) {
  return (async (_url: string, init: RequestInit) => {
    const [status, json] = handler(new URLSearchParams(String(init.body)));
    return new Response(JSON.stringify(json), { status, headers: { "Content-Type": "application/json" } });
  }) as unknown as typeof fetch;
}

function res() {
  const r = { code: 0, body: undefined as unknown, status(c: number) { r.code = c; return r; }, json(b: unknown) { r.body = b; return r; } };
  return r;
}

describe("middleware", () => {
  const v = createVerifier({
    endpoint: "https://dk.test", secret: "s",
    fetch: fakeFetch((b) => [200, { success: b.get("response") === "good" && b.get("expected_action") === "signup", "error-codes": [] , doorkeep: { risk: 3 } }]),
  });

  it("calls next and exposes the result for a valid token", async () => {
    const req: any = { body: { "dk-response": "good" }, ip: "203.0.113.5" };
    let called = false;
    await middleware(v, { action: "signup" })(req, res(), () => { called = true; });
    expect(called).toBe(true);
    expect(req.doorkeep.doorkeep.risk).toBe(3);
  });

  it("answers 403 for a missing or bad token without calling next", async () => {
    for (const body of [{ "dk-response": "bad" }, {}, undefined]) {
      const r = res();
      let called = false;
      await middleware(v, { action: "signup" })({ body } as any, r, () => { called = true; });
      expect(called).toBe(false);
      expect(r.code).toBe(403);
    }
  });

  it("supports a custom field and failure handler", async () => {
    let failed = false;
    await middleware(v, { action: "signup", field: "cf-turnstile-response", onFail: () => { failed = true; } })({ body: { "cf-turnstile-response": "bad" } } as any, res(), () => {});
    expect(failed).toBe(true);
  });

  it("passes an outage to the error handler when failing closed", async () => {
    const down = createVerifier({ endpoint: "https://dk.test", secret: "s", fetch: fakeFetch(() => [503, {}]) });
    let err: unknown;
    await middleware(down)({ body: { "dk-response": "x" } } as any, res(), (e) => { err = e; });
    expect(err).toBeInstanceOf(DoorkeepUnavailableError);
  });
});
