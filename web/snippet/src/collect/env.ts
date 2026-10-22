// Environment signals and privacy-profile hints (design section 1.2 D).
import type { Payload } from "../schema";
import { isNative, safe, withTimeout } from "../util";

const PERMS = ["notifications", "geolocation", "camera", "microphone", "clipboard-read"];

async function permissions(): Promise<number> {
  if (!navigator.permissions) return 0;
  let bits = 0;
  await Promise.all(
    PERMS.map(async (name, i) => {
      const st = await withTimeout(
        navigator.permissions.query({ name: name as PermissionName }).then((r) => r.state),
        300,
        "",
      ).catch(() => "");
      const v = st === "prompt" ? 1 : st === "granted" ? 2 : st === "denied" ? 3 : 0;
      bits |= v << (2 * i);
    }),
  );
  return bits;
}

async function storage(): Promise<{ sto: number; quota: number }> {
  let sto = 0;
  const k = "__dk_probe";
  try {
    localStorage.setItem(k, "1");
    if (localStorage.getItem(k) === "1") sto |= 1;
    localStorage.removeItem(k);
  } catch {
    sto |= 16;
  }
  try {
    sessionStorage.setItem(k, "1");
    if (sessionStorage.getItem(k) === "1") sto |= 2;
    sessionStorage.removeItem(k);
  } catch {
    sto |= 16;
  }
  if (typeof indexedDB !== "undefined") sto |= 4;
  if (navigator.cookieEnabled) sto |= 8;
  const quota = await withTimeout(
    (navigator.storage?.estimate?.() || Promise.resolve({ quota: 0 })).then((e) => Math.round((e.quota || 0) / 1048576)),
    300,
    0,
  );
  return { sto, quota };
}

function perf(): number[] {
  // Timer precision: RFP rounds performance.now() to 100 ms (or 16.67 ms).
  let coarse = 1;
  for (let i = 0; i < 5; i++) {
    const v = performance.now();
    if (Math.abs(v - Math.round(v / 100) * 100) > 1e-6) { coarse = 0; break; }
  }
  const nav = safe(() => performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined, undefined);
  const domReady = nav ? Math.max(0, Math.round(nav.domContentLoadedEventEnd - nav.fetchStart)) : -1;
  const resources = safe(() => performance.getEntriesByType("resource").length, -1);
  const navType = nav ? (["navigate", "reload", "back_forward", "prerender"].indexOf(nav.type) + 4) % 4 : 0;
  return [coarse, domReady, resources, navType]; // -1 = unknown
}

function integrity(): number {
  const g = globalThis as any;
  const apis = [g.fetch, g.Promise, g.crypto?.subtle?.digest, g.TextEncoder];
  return apis.reduce((m: number, f: unknown, i: number) => (f !== undefined && !isNative(f) ? m | (1 << i) : m), 0);
}

export async function collectEnv(version: number): Promise<Payload["env"]> {
  const [perm, st] = await Promise.all([permissions(), storage()]);
  return { perm, sto: st.sto, perf: perf(), integ: integrity(), quota: st.quota, sv: version };
}

/** Privacy-browser profile hints. These relax rules server-side; never penalties. */
export async function collectProfile(tz: string, hc: number): Promise<Payload["prof"]> {
  const ua = navigator.userAgent;
  const firefox = /Firefox\//.test(ua);
  const nav = navigator as any;
  const brave = await withTimeout(
    Promise.resolve(nav.brave && typeof nav.brave.isBrave === "function" ? nav.brave.isBrave() : false),
    200,
    false,
  );
  const utc = tz === "UTC" || tz === "Etc/UTC" || new Date().getTimezoneOffset() === 0;
  const coarseTimer = perf()[0] === 1;
  // Firefox resistFingerprinting: UTC + spoofed core count or coarse timers.
  const rfp = firefox && utc && (hc === 2 || hc === 4 || coarseTimer);
  // Tor Browser: RFP plus letterboxed inner size (multiples of 200x100).
  const tor = rfp && innerWidth % 200 === 0 && innerHeight % 100 === 0;
  return {
    rfp, brave: !!brave, tor,
    dnt: nav.doNotTrack === "1" || nav.globalPrivacyControl === true,
    fc: safe(() => matchMedia("(forced-colors: active)").matches, false),
  };
}
