// Server side: verifyDoorkeep() for Server Actions and Route Handlers.
import { createVerifier, type VerifyResult } from "@doorkeep/verify";

export class DoorkeepVerifyError extends Error {
  constructor(public result: VerifyResult) {
    super("doorkeep: check failed: " + (result["error-codes"].join(",") || result.doorkeep?.outcome || "unknown"));
    this.name = "DoorkeepVerifyError";
  }
}

let verifier: ReturnType<typeof createVerifier> | null = null;
function get() {
  const endpoint = process.env.DOORKEEP_URL;
  const secret = process.env.DOORKEEP_SECRET;
  if (!endpoint || !secret) throw new Error("doorkeep: set DOORKEEP_URL and DOORKEEP_SECRET");
  verifier ??= createVerifier({ endpoint, secret, failMode: process.env.DOORKEEP_FAIL_MODE === "open" ? "open" : "closed" });
  return verifier;
}

/**
 * Verify the dk-response from FormData (Server Actions) or a token string.
 * Throws DoorkeepVerifyError unless the outcome is allow.
 */
export async function verifyDoorkeep(input: FormData | string | null | undefined, opts: { action?: string; remoteIp?: string } = {}): Promise<VerifyResult> {
  const token = typeof input === "string" || input == null ? input : (input.get("dk-response") as string | null);
  const r = await get().verify(token, { action: opts.action, remoteIp: opts.remoteIp });
  if (!r.success) throw new DoorkeepVerifyError(r);
  return r;
}
