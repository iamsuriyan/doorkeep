// Fingerprint-consistency inputs (design section 1.2 B). High-entropy
// renderings (canvas, audio, fonts) leave the browser only as hashes or
// presence bitmasks.
import { FEATURE_PROBES, FONT_PROBES, type Payload } from "../schema";
import { bitsB64, hash, safe, withTimeout } from "../util";

function screenInfo(): number[] {
  const s = screen;
  const o = safe(() => (screen.orientation?.type || "").startsWith("landscape") ? 1 : (screen.orientation?.type ? 2 : 0), 0);
  return [s.width, s.height, s.availWidth, s.availHeight, s.colorDepth, devicePixelRatio || 1, o];
}

function webgl(): [string, string] | undefined {
  return safe(() => {
    const c = document.createElement("canvas");
    const gl = (c.getContext("webgl") || c.getContext("experimental-webgl")) as WebGLRenderingContext | null;
    if (!gl) return undefined;
    const ext = gl.getExtension("WEBGL_debug_renderer_info");
    const v = ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
    const r = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
    (gl.getExtension("WEBGL_lose_context") as any)?.loseContext();
    return [String(v || ""), String(r || "")] as [string, string];
  }, undefined);
}

/** Canvas drawn with the server seed so a captured hash cannot be replayed
 * under another nonce (design section 2.3 rule 5). */
async function canvas(seed: string): Promise<{ h: string; s?: string; b: boolean }> {
  const draw = (seed: string): string | null =>
    safe(() => {
      const c = document.createElement("canvas");
      c.width = 240;
      c.height = 60;
      const x = c.getContext("2d");
      if (!x) return null;
      x.textBaseline = "top";
      x.font = "14px 'Arial'";
      x.fillStyle = "#f60";
      x.fillRect(100, 1, 62, 20);
      x.fillStyle = "#069";
      x.fillText("doorkeep " + seed + " \u{1F6AA}", 2, 15);
      x.fillStyle = "rgba(102,204,0,0.7)";
      x.fillText("doorkeep " + seed, 4, 17);
      const g = x.createLinearGradient(0, 0, 240, 0);
      g.addColorStop(0, "#c0f");
      g.addColorStop(1, "#0cf");
      x.fillStyle = g;
      x.beginPath();
      x.arc(200, 40, 18, 0, Math.PI * 2, true);
      x.fill();
      return c.toDataURL();
    }, null);
  const url = draw(seed);
  if (!url) return { h: "", b: true };
  const blank = safe(() => {
    const c = document.createElement("canvas");
    c.width = 240;
    c.height = 60;
    return c.toDataURL();
  }, "");
  if (url === blank) return { h: "", b: true };
  const fixed = draw("static");
  return { h: await hash(url), s: fixed ? await hash(fixed) : undefined, b: false };
}

async function audio(): Promise<string | undefined> {
  const Ctx = (window as any).OfflineAudioContext || (window as any).webkitOfflineAudioContext;
  if (!Ctx) return undefined;
  const run = async (): Promise<string | undefined> => {
    const ctx = new Ctx(1, 5000, 44100);
    const osc = ctx.createOscillator();
    osc.type = "triangle";
    osc.frequency.value = 10000;
    const comp = ctx.createDynamicsCompressor();
    comp.threshold.value = -50;
    comp.knee.value = 40;
    comp.ratio.value = 12;
    comp.attack.value = 0;
    comp.release.value = 0.25;
    osc.connect(comp);
    comp.connect(ctx.destination);
    osc.start(0);
    const buf: AudioBuffer = await ctx.startRendering();
    const d = buf.getChannelData(0);
    let sum = 0;
    for (let i = 4500; i < 5000; i++) sum += Math.abs(d[i]);
    return hash(sum.toString());
  };
  return withTimeout(run().catch(() => undefined), 150, undefined);
}

/** Font presence via canvas text metrics against two generic baselines. */
function fonts(): string {
  return safe(() => {
    const c = document.createElement("canvas").getContext("2d");
    if (!c) return "";
    const text = "mmmmmmmmmmlli1WQ@#é";
    const base: Record<string, number> = {};
    for (const g of ["monospace", "sans-serif", "serif"]) {
      c.font = `72px ${g}`;
      base[g] = c.measureText(text).width;
    }
    const bits = FONT_PROBES.map((f) =>
      ["monospace", "sans-serif", "serif"].some((g) => {
        c.font = `72px "${f}", ${g}`;
        return c.measureText(text).width !== base[g];
      }),
    );
    return bitsB64(bits);
  }, "");
}

function touchBits(): number {
  let t = 0;
  const mm = (q: string) => safe(() => matchMedia(q).matches, false);
  if (navigator.maxTouchPoints > 0) t |= 1;
  if ("ontouchstart" in window) t |= 2;
  if (mm("(pointer: coarse)")) t |= 4;
  if (mm("(hover: none)")) t |= 8;
  if (mm("(any-pointer: fine)")) t |= 16;
  return t;
}

function mediaBits(): number {
  let m = 0;
  const mm = (q: string) => safe(() => matchMedia(q).matches, false);
  if (mm("(prefers-color-scheme: dark)")) m |= 1;
  if (mm("(prefers-reduced-motion: reduce)")) m |= 2;
  if (mm("(forced-colors: active)")) m |= 4;
  if (mm("(color-gamut: p3)")) m |= 8;
  return m;
}

export interface FPStage1 extends Omit<Payload["fp"], "au" | "fn"> {}

export async function collectFP(seed: string): Promise<FPStage1> {
  const uad = safe(() => {
    const d = (navigator as any).userAgentData;
    return d ? { b: (d.brands || []).map((x: any) => x.brand).slice(0, 6), p: String(d.platform || ""), m: !!d.mobile } : undefined;
  }, undefined);
  return {
    ua: navigator.userAgent,
    uad,
    scr: screenInfo(),
    tz: safe(() => Intl.DateTimeFormat().resolvedOptions().timeZone || "", ""),
    tzo: new Date().getTimezoneOffset(),
    lang: safe(() => Array.from(navigator.languages || [navigator.language]).slice(0, 5), []),
    gl: webgl(),
    cv: await canvas(seed),
    hc: navigator.hardwareConcurrency || 0,
    dm: (navigator as any).deviceMemory,
    tch: touchBits(),
    mq: mediaBits(),
    feat: bitsB64(FEATURE_PROBES.map((p) => safe(p, false))),
    mtp: navigator.maxTouchPoints || 0,
  };
}

/** Deferred stage: run in idle time, sent with the final submit. */
export async function collectFPDeferred(mods: string[]): Promise<{ au?: string; fn?: string }> {
  const out: { au?: string; fn?: string } = {};
  if (mods.includes("audio")) out.au = await audio();
  if (mods.includes("fonts")) out.fn = fonts() || undefined;
  return out;
}
