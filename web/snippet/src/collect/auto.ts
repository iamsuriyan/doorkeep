// Automation markers (design section 1.2 A).
import type { Payload } from "../schema";
import { isNative, safe } from "../util";

const LEAK_NAMES = [
  "__playwright__binding__", "__pwInitScripts", "__puppeteer_evaluation_script__",
  "callPhantom", "_phantom", "__nightmare", "_selenium", "domAutomation", "domAutomationController",
  "__webdriver_evaluate", "__selenium_unwrapped", "__fxdriver_unwrapped", "__driver_evaluate",
];
const LEAK_RE = /^(cdc_|\$cdc_|__pw|__puppeteer|__selenium|__webdriver|__driver|__lastWatirAlert)/;

function webdriverState(): { wd: 0 | 1 | 2; wdt: number } {
  let wdt = 0;
  const nav = navigator as any;
  const desc = safe(() => Object.getOwnPropertyDescriptor(Navigator.prototype, "webdriver"), undefined);
  if (!desc) wdt |= 1;
  else if (desc.get && !isNative(desc.get)) wdt |= 2;
  if (!isNative(Function.prototype.toString)) wdt |= 8;
  // Realm check: stealth init scripts often patch the top window only.
  safe(() => {
    const f = document.createElement("iframe");
    f.style.display = "none";
    f.setAttribute("aria-hidden", "true");
    (document.body || document.documentElement).appendChild(f);
    const other = (f.contentWindow as any)?.navigator?.webdriver;
    if (other !== undefined && other !== nav.webdriver) wdt |= 4;
    f.remove();
  }, undefined);
  const v = nav.webdriver;
  return { wd: v === true ? 1 : v === false ? 0 : 2, wdt };
}

/** Detects the CDP Runtime domain: console serialisation touches the getter
 * only when a DevTools protocol client (automation or open DevTools) listens. */
function cdpEnabled(): boolean {
  let hit = false;
  safe(() => {
    const e = new Error("");
    Object.defineProperty(e, "stack", { configurable: false, enumerable: false, get() { hit = true; return ""; } });
    // eslint-disable-next-line no-console
    console.debug(e);
  }, undefined);
  return hit;
}

function leaks(): number {
  let n = 0;
  const w = window as any;
  for (const k of LEAK_NAMES) if (safe(() => k in w, false)) n++;
  safe(() => {
    for (const k of Object.getOwnPropertyNames(w)) if (LEAK_RE.test(k)) n++;
    for (const k of Object.getOwnPropertyNames(document)) if (LEAK_RE.test(k)) n++;
  }, undefined);
  return n;
}

function pluginShape(): number[] {
  return safe(() => {
    const p = navigator.plugins as any;
    const len = p ? p.length : 0;
    let shape = 0;
    if (!p) shape = 3;
    else if (Object.getPrototypeOf(p) !== PluginArray.prototype) shape = 2;
    else if (len === 0) shape = 1;
    else if (typeof p.item !== "function" || !isNative(p.item) || p.item(0) !== p[0]) shape = 3;
    return [len, shape];
  }, [0, 3]);
}

function chromeObj(isChromium: boolean): 0 | 1 | 2 | 3 {
  if (!isChromium) return 0;
  const c = (window as any).chrome;
  if (!c) return 2;
  // Real Chrome exposes non-enumerable native functions; fakes are plain objects.
  return safe(() => (c.loadTimes && !isNative(c.loadTimes)) || (c.csi && !isNative(c.csi)) ? 3 : 1, 3);
}

async function notifContradiction(): Promise<boolean> {
  try {
    if (typeof Notification === "undefined" || !navigator.permissions) return false;
    const st = await navigator.permissions.query({ name: "notifications" as PermissionName });
    return Notification.permission === "denied" && st.state === "prompt";
  } catch {
    return false;
  }
}

function engine(): 0 | 1 | 2 | 3 {
  try {
    (null as any)[0];
  } catch (e: any) {
    const m = String(e && e.message);
    if (m.includes("Cannot read prop")) return 0;
    if (m.includes("has no properties")) return 1;
    if (m.includes("is not an object")) return 2;
  }
  return 3;
}

function nonNativeAPIs(): number {
  const g = globalThis as any;
  const apis = [g.fetch, g.Promise, g.crypto?.subtle?.digest, g.TextEncoder, g.XMLHttpRequest?.prototype?.open, g.Function?.prototype?.toString, g.Date?.now];
  return apis.filter((f) => f !== undefined && !isNative(f)).length;
}

export async function collectAuto(): Promise<Payload["auto"]> {
  const ua = navigator.userAgent;
  const { wd, wdt } = webdriverState();
  const conn = (navigator as any).connection;
  let voices = -1;
  safe(() => {
    if (typeof speechSynthesis !== "undefined") voices = speechSynthesis.getVoices().length;
  }, undefined);
  const brands: string[] = safe(() => ((navigator as any).userAgentData?.brands || []).map((b: any) => b.brand), []);
  return {
    wd, wdt,
    cdp: cdpEnabled(),
    leaks: leaks(),
    hua: ua.includes("HeadlessChrome") || brands.some((b) => b.includes("Headless")),
    geo: [innerWidth, innerHeight, outerWidth, outerHeight, document.fullscreenElement ? 1 : 0],
    plg: pluginShape(),
    chr: chromeObj(/Chrome\//.test(ua)),
    notif: await notifContradiction(),
    conn: !conn || typeof conn.rtt !== "number" ? 0 : conn.rtt === 0 ? 2 : 1,
    voices,
    eng: engine(),
    nat: nonNativeAPIs(),
  };
}
