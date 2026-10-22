// Proof-of-work worker. Solves sub-puzzles i in `idx` for
// SHA-256(nonce || salt || u32be(i) || u32be(x)) with `bits` leading zeros.
// Mirrors internal/challenge/pow. Uses the synchronous SHA-256 because
// crypto.subtle's per-call overhead dominates for 50-byte inputs.
import { sha256 } from "./util";

interface Job {
  nonce: string;
  salt: string;
  bits: number;
  idx: number[];
}

function lz(h: Uint8Array): number {
  let n = 0;
  for (let i = 0; i < h.length; i++) {
    const b = h[i];
    if (b === 0) { n += 8; continue; }
    return n + Math.clz32(b) - 24;
  }
  return n;
}

self.onmessage = (ev: MessageEvent<Job>) => {
  const { nonce, salt, bits, idx } = ev.data;
  const prefix = new TextEncoder().encode(nonce + salt);
  const buf = new Uint8Array(prefix.length + 8);
  buf.set(prefix);
  const dv = new DataView(buf.buffer);
  const out: Array<[number, number]> = [];
  for (const i of idx) {
    dv.setUint32(prefix.length, i);
    for (let x = 0; x < 0xffffffff; x++) {
      dv.setUint32(prefix.length + 4, x);
      if (lz(sha256(buf)) >= bits) {
        out.push([i, x]);
        break;
      }
    }
  }
  (self as unknown as Worker).postMessage(out);
};
