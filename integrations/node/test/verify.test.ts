import { describe, expect, it } from "vitest";
import { createVerifier, DoorkeepUnavailableError } from "../src/index";

function fakeFetch(handler: (url: string, body: URLSearchParams) => [number, unknown]) {
  return (async (url: string, init: RequestInit) => {
    const [status, json] = handler(url, new URLSearchParams(String(init.body)));
    return new Response(JSON.stringify(json), { status, headers: { "Content-Type": "application/json" } });
  }) as unknown as typeof fetch;
}

describe("verify", () => {
  it("sends the Turnstile-compatible form and returns the result", async () => {
    let seen: URLSearchParams | null = null;
    const dk = createVerifier({
      endpoint: "https://dk.test/", secret: "dk_sk_x",
      fetch: fakeFetch((url, body) => { expect(url).toBe("https://dk.test/v1/siteverify"); seen = body; return [200, { success: true, "error-codes": [], doorkeep: { risk: 3, outcome: "allow" } }]; }),
    });
    const r = await dk.verify("tok", { action: "signup", remoteIp: "203.0.113.5" });
    expect(r.success).toBe(true);
    expect(seen!.get("secret")).toBe("dk_sk_x");
    expect(seen!.get("expected_action")).toBe("signup");
    expect(seen!.get("remoteip")).toBe("203.0.113.5");
  });

  it("treats a missing token as a failed check without calling doorkeep", async () => {
    const dk = createVerifier({ endpoint: "https://dk.test", secret: "s", fetch: (() => { throw new Error("should not be called"); }) as any });
    expect((await dk.verify("")).success).toBe(false);
  });

  it("fails closed by default and open when configured", async () => {
    const down = fakeFetch(() => [503, {}]);
    await expect(createVerifier({ endpoint: "https://dk.test", secret: "s", fetch: down }).verify("t")).rejects.toBeInstanceOf(DoorkeepUnavailableError);
    const open = await createVerifier({ endpoint: "https://dk.test", secret: "s", fetch: down, failMode: "open" }).verify("t");
    expect(open).toMatchObject({ success: true, failedOpen: true });
  });
});
