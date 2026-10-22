import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { FEATURE_PROBES, FONT_PROBES } from "../src/schema";
import { Stat, b64url, bitsB64, sha256 } from "../src/util";

describe("sha256", () => {
  it("matches node:crypto for many lengths", () => {
    for (let len = 0; len < 200; len += 7) {
      const buf = new Uint8Array(len).map((_, i) => (i * 31 + len) & 0xff);
      const want = createHash("sha256").update(buf).digest("hex");
      const got = Buffer.from(sha256(buf)).toString("hex");
      expect(got).toBe(want);
    }
  });

  it("matches the Go PoW preimage layout", () => {
    // Go: sha256(nonce || salt || u32be(i) || u32be(x))
    const prefix = new TextEncoder().encode("nonce-abc" + "c2FsdA");
    const buf = new Uint8Array(prefix.length + 8);
    buf.set(prefix);
    const dv = new DataView(buf.buffer);
    dv.setUint32(prefix.length, 3);
    dv.setUint32(prefix.length + 4, 0x01020304);
    const want = createHash("sha256").update(Buffer.concat([Buffer.from("nonce-abcc2FsdA"), Buffer.from([0, 0, 0, 3, 1, 2, 3, 4])])).digest("hex");
    expect(Buffer.from(sha256(buf)).toString("hex")).toBe(want);
  });
});

describe("encoding", () => {
  it("b64url has no padding or unsafe chars", () => {
    expect(b64url(new Uint8Array([0xfb, 0xff, 0xfe]))).toBe("-__-");
  });
  it("bitsB64 is little-endian per byte", () => {
    // bits 0..7 = true,false x7 ; bit 8 = true -> bytes [0x01, 0x01]
    const bits = Array(9).fill(false);
    bits[0] = true;
    bits[8] = true;
    expect(Buffer.from(bitsB64(bits), "base64url")).toEqual(Buffer.from([1, 1]));
  });
});

describe("Stat", () => {
  it("computes mean and cv", () => {
    const s = new Stat();
    [10, 10, 10].forEach((x) => s.push(x));
    expect(s.mean).toBe(10);
    expect(s.cv).toBe(0);
    const t = new Stat();
    [1, 2, 3, 4].forEach((x) => t.push(x));
    expect(t.mean).toBe(2.5);
    expect(t.cv).toBeCloseTo(0.5164, 3);
  });
});

describe("schema contract with Go", () => {
  it("has the probe counts normalise.go expects", () => {
    expect(FEATURE_PROBES.length).toBe(12);
    expect(FONT_PROBES.length).toBe(20);
  });
});
