// Runs the PoW challenge across up to four workers.
declare const __POW_WORKER__: string;

export async function solvePoW(nonce: string, salt: string, bits: number, n: number): Promise<number[]> {
  const workers = Math.max(1, Math.min(navigator.hardwareConcurrency || 2, 4, n));
  const url = URL.createObjectURL(new Blob([__POW_WORKER__], { type: "text/javascript" }));
  try {
    const jobs = Array.from({ length: workers }, (_, w) => {
      const idx: number[] = [];
      for (let i = w; i < n; i += workers) idx.push(i);
      return new Promise<Array<[number, number]>>((resolve, reject) => {
        const wk = new Worker(url);
        wk.onmessage = (e) => { wk.terminate(); resolve(e.data); };
        wk.onerror = (e) => { wk.terminate(); reject(e); };
        wk.postMessage({ nonce, salt, bits, idx });
      });
    });
    const sol = new Array<number>(n);
    for (const part of await Promise.all(jobs)) for (const [i, x] of part) sol[i] = x;
    return sol;
  } finally {
    URL.revokeObjectURL(url);
  }
}
