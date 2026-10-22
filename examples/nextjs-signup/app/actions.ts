"use server";
import { verifyDoorkeep, DoorkeepVerifyError } from "@doorkeep/next/server";

export async function signup(_prev: unknown, form: FormData) {
  try {
    const r = await verifyDoorkeep(form, { action: "signup" });
    return { ok: true, message: `Welcome, ${form.get("name")}!`, risk: r.doorkeep?.risk ?? null, reasons: r.doorkeep?.reasons ?? [] };
  } catch (e) {
    if (e instanceof DoorkeepVerifyError) {
      return { ok: false, message: "We could not verify this request. Please try again.", risk: e.result.doorkeep?.risk ?? null, reasons: e.result.doorkeep?.reasons ?? [] };
    }
    throw e;
  }
}
