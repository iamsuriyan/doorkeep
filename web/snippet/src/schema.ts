// Wire schema posted to /v1/submit. Mirrors internal/signals/payload/payload.go.
// Positional arrays and bitmasks are documented here and in the Go struct;
// both sides change together and bump `v`.

export interface Payload {
  v: 1;
  n: string; // nonce id
  a: string; // action
  t: { i: number; f: number; s: number; d: number }; // perf.now at session/first-interaction/submit; Date.now() at submit
  prof: { rfp: boolean; brave: boolean; tor: boolean; dnt: boolean; fc: boolean };
  auto: {
    wd: 0 | 1 | 2; // webdriver false / true / undefined
    wdt: number; // tamper bits: 1 descriptor missing, 2 non-native getter, 4 realm mismatch, 8 Function.toString patched
    cdp: boolean;
    leaks: number;
    hua: boolean;
    geo: number[]; // [innerW, innerH, outerW, outerH, fullscreen]
    plg: number[]; // [plugins.length, shape 0 native/1 empty/2 non-native/3 inconsistent]
    chr: 0 | 1 | 2 | 3; // window.chrome: n/a, native, missing, fake
    notif: boolean;
    conn: 0 | 1 | 2; // n/a, rtt>0, rtt==0
    voices: number; // -1 n/a
    eng: 0 | 1 | 2 | 3; // v8, spidermonkey, jsc, other
    nat: number; // non-native core API count
  };
  fp: {
    ua: string;
    uad?: { b: string[]; p: string; m: boolean };
    scr: number[]; // [w, h, availW, availH, colorDepth, dpr, orientation 0 n/a/1 landscape/2 portrait]
    tz: string;
    tzo: number;
    lang: string[];
    gl?: [string, string];
    cv: { h: string; b: boolean };
    au?: string;
    fn?: string;
    hc: number;
    dm?: number;
    tch: number; // 1 mtp>0, 2 ontouchstart, 4 pointer:coarse, 8 hover:none, 16 any-pointer:fine
    mq: number; // 1 dark, 2 reduced-motion, 4 forced-colors, 8 gamut p3
    feat: string;
    mtp: number;
  };
  beh: {
    ptr: number[]; // [samples, pathLen, straightness, speedCV, dirChanges, accelFlips, intervalCV, collinearFrac, untrustedFrac, h0..h5]
    clk: number[]; // [count, durMean, durCV, centerFrac, noMoveClick]
    key: number[]; // [count, holdMean, holdCV, intervalCV, backspaceFrac, inputNoKeyFrac(-1 n/a), pasteCount]
    scr: number[]; // [count, wheelClass, scrolledBeforeFirstInteraction]
    foc: number[]; // [focusStart, focusSubmit, visibilityChanges, hiddenAtSubmit]
    raf?: number[]; // [median, cv]
  };
  env: {
    perm: number; // 2 bits each: notifications, geolocation, camera, microphone, clipboard-read; 0 n/a 1 prompt 2 granted 3 denied
    sto: number; // 1 localStorage, 2 sessionStorage, 4 indexedDB, 8 cookies, 16 threw
    perf: number[]; // [timerPrecision 0 fine/1 coarse, domReadyMs, resourceCount, navType]
    integ: number;
    quota: number; // MB, 0 n/a
    sv: number;
  };
}

export interface SessionResp {
  nonce: string;
  exp: number;
  seed: string;
  now: number;
  mod: string[];
  deferMs: number;
}

export interface SubmitResp {
  status: "ok" | "challenge" | "error";
  token?: string;
  kind?: "pow";
  pow?: { salt: string; bits: number; n: number };
  error?: string;
}

// Feature probes. ORDER MUST MATCH `probes` in internal/signals/payload/normalise.go.
export const FEATURE_PROBES: Array<() => boolean> = [
  () => typeof (Array.prototype as any).at === "function",
  () => typeof (Object as any).hasOwn === "function",
  () => typeof (globalThis as any).structuredClone === "function",
  () => typeof (Array.prototype as any).findLast === "function",
  () => typeof (navigator as any).userAgentData === "object" && (navigator as any).userAgentData !== null,
  () => typeof (Array.prototype as any).toSorted === "function",
  () => typeof (URL as any).canParse === "function",
  () => typeof (Promise as any).withResolvers === "function",
  () => typeof (Object as any).groupBy === "function",
  () => typeof (Set.prototype as any).union === "function",
  () => typeof CSS !== "undefined" && typeof (CSS as any).registerProperty === "function",
  () => typeof (globalThis as any).Iterator === "function" && typeof (globalThis as any).Iterator.prototype.map === "function",
];

// Font probes. BIT ORDER MUST MATCH the font masks in normalise.go.
export const FONT_PROBES = [
  // 0-5 Windows
  "Segoe UI", "Calibri", "Cambria", "Consolas", "Tahoma", "Segoe UI Emoji",
  // 6-11 macOS
  "Helvetica Neue", "Menlo", "SF Pro Text", "Apple Color Emoji", "Avenir", "Geneva",
  // 12-15 Android
  "Roboto", "Noto Color Emoji", "Droid Sans", "Noto Sans",
  // 16-19 Linux
  "DejaVu Sans", "Liberation Sans", "Ubuntu", "Cantarell",
];
