// doorkeep browser snippet.
//
//   <script src="/_dk/v1/dk.js" data-sitekey="dk_pk_..." async defer></script>
//   <form> ... <div class="doorkeep" data-action="signup"></div> ... </form>
//
// On submit the snippet obtains a token and puts it in a hidden
// `dk-response` field (plus `cf-turnstile-response` / `g-recaptcha-response`
// with data-compat="turnstile|recaptcha"). Your backend posts it to
// /v1/siteverify. The page never learns the score.
import { collectAuto } from "./collect/auto";
import { Behaviour, rafCadence } from "./collect/beh";
import { collectEnv, collectProfile } from "./collect/env";
import { collectFP, collectFPDeferred } from "./collect/fp";
import { solvePoW } from "./pow";
import type { Payload, SessionResp, SubmitResp } from "./schema";
import { safe } from "./util";

declare const __DK_VERSION__: number;

interface Options {
  sitekey?: string;
  action?: string;
  callback?: (token: string) => void;
  "error-callback"?: (err: unknown) => void;
}

interface Session extends SessionResp {
  action: string;
  receivedAt: number; // performance.now() when the response arrived
  used: boolean;
}

const script = document.currentScript as HTMLScriptElement | null;
const cfg = {
  sitekey: script?.dataset.sitekey || "",
  compat: script?.dataset.compat || "",
  endpoint: script?.dataset.endpoint || deriveEndpoint(script?.src || ""),
};

function deriveEndpoint(src: string): string {
  const i = src.lastIndexOf("/v1/dk.js");
  return i >= 0 ? src.slice(0, i) : "";
}

const beh = new Behaviour();
beh.start();
let session: Promise<Session> | null = null;

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(cfg.endpoint + path, {
    method: "POST",
    body: JSON.stringify(body),
    headers: { "Content-Type": "text/plain;charset=UTF-8" },
    credentials: "omit",
    keepalive: true,
  });
  const data = (await res.json().catch(() => ({}))) as T & { error?: string };
  if (!res.ok) throw new Error("doorkeep: " + (data.error || res.status));
  return data;
}

function newSession(sitekey: string, action: string): Promise<Session> {
  return post<SessionResp>("/v1/session", { sk: sitekey, a: action }).then((s) => ({
    ...s, action, receivedAt: performance.now(), used: false,
  }));
}

/** Reuse the prefetched session when it matches and has at least 10 s left. */
async function getSession(sitekey: string, action: string): Promise<Session> {
  if (session) {
    const s = await session.catch(() => null);
    if (s && !s.used && s.action === action && s.exp - s.now - (performance.now() - s.receivedAt) > 10_000) return s;
  }
  session = newSession(sitekey, action);
  return session;
}

async function buildPayload(s: Session): Promise<Payload> {
  const mods = s.mod || [];
  const [auto, fp, env, deferred, raf] = await Promise.all([
    collectAuto(),
    collectFP(s.seed),
    collectEnv(__DK_VERSION__),
    collectFPDeferred(mods),
    mods.includes("raf") ? rafCadence() : Promise.resolve(undefined),
  ]);
  const prof = await collectProfile(fp.tz, fp.hc);
  const b = beh.snapshot();
  if (raf) b.raf = raf;
  const now = performance.now();
  return {
    v: 1, n: s.nonce, a: s.action,
    t: { i: s.receivedAt, f: beh.firstInteraction, s: now, d: Date.now() },
    prof, auto,
    fp: { ...fp, ...deferred },
    beh: b,
    env,
  };
}

/** Obtain a token for `action`. Resolves with the token string. */
async function execute(sitekey = cfg.sitekey, opts: { action?: string } = {}): Promise<string> {
  if (!sitekey) throw new Error("doorkeep: missing sitekey");
  const action = opts.action || "default";
  const s = await getSession(sitekey, action);
  s.used = true;
  session = null;
  const res = await post<SubmitResp>("/v1/submit", await buildPayload(s));
  if (res.status === "ok" && res.token) {
    prefetch(sitekey, action);
    return res.token;
  }
  let cur = res;
  if (cur.status === "challenge" && cur.kind === "pow" && cur.pow) {
    const sol = await solvePoW(s.nonce, cur.pow.salt, cur.pow.bits, cur.pow.n);
    cur = await post<SubmitResp>("/v1/challenge", { n: s.nonce, kind: "pow", sol });
  }
  if (cur.status === "challenge" && cur.kind === "visual" && cur.visual) {
    const token = await visualChallenge(s.nonce, cur.visual);
    prefetch(sitekey, action);
    return token;
  }
  if (cur.token) {
    prefetch(sitekey, action);
    return cur.token;
  }
  throw new Error("doorkeep: no token");
}

let uiLoad: Promise<any> | null = null;

/** Load the challenge dialog bundle once, on demand. */
function loadUI(): Promise<any> {
  if ((window as any).__doorkeepUI) return Promise.resolve((window as any).__doorkeepUI);
  uiLoad ||= new Promise((resolve, reject) => {
    const sc = document.createElement("script");
    sc.src = cfg.endpoint + "/v1/dk-ui.js";
    sc.async = true;
    sc.onload = () => resolve((window as any).__doorkeepUI);
    sc.onerror = () => { uiLoad = null; reject(new Error("doorkeep: challenge UI failed to load")); };
    document.head.appendChild(sc);
  });
  return uiLoad;
}

async function visualChallenge(nonce: string, v: import("./schema").VisualInfo): Promise<string> {
  const ui = await loadUI();
  const abs = (p: string) => cfg.endpoint + p;
  return ui.open({
    image: abs(v.image), audio: abs(v.audio), audioSlow: abs(v.audio_slow),
    length: v.length, attemptsLeft: v.attempts_left, accessibilityUrl: v.accessibility_url,
    submit: async (answer: string) => {
      try {
        const r = await post<SubmitResp>("/v1/challenge", { n: nonce, kind: "visual", answer });
        if (r.status === "ok" && r.token) return { ok: true, token: r.token };
        return { ok: false, attemptsLeft: r.visual?.attempts_left };
      } catch (e) {
        if (String(e).includes("challenge-exhausted")) return { ok: false, exhausted: true };
        throw e;
      }
    },
  });
}

function prefetch(sitekey: string, action: string): void {
  if (!sitekey) return;
  session = newSession(sitekey, action);
  session.catch(() => { session = null; });
}

// ---------- form widgets ----------

interface Widget {
  el: HTMLElement;
  form: HTMLFormElement | null;
  sitekey: string;
  action: string;
  inputs: HTMLInputElement[];
  opts: Options;
}

const widgets: Widget[] = [];

function fieldNames(): string[] {
  const names = ["dk-response"];
  if (cfg.compat.includes("turnstile")) names.push("cf-turnstile-response");
  if (cfg.compat.includes("recaptcha")) names.push("g-recaptcha-response");
  return names;
}

function render(target: string | HTMLElement, opts: Options = {}): number {
  const el = typeof target === "string" ? (document.querySelector(target) as HTMLElement) : target;
  if (!el) throw new Error("doorkeep: render target not found");
  const existing = widgets.findIndex((w) => w.el === el);
  if (existing >= 0) return existing;
  const sitekey = opts.sitekey || el.dataset.sitekey || cfg.sitekey;
  const action = opts.action || el.dataset.action || "default";
  const inputs = fieldNames().map((name) => {
    const i = document.createElement("input");
    i.type = "hidden";
    i.name = name;
    el.appendChild(i);
    return i;
  });
  const w: Widget = { el, form: el.closest("form"), sitekey, action, inputs, opts };
  widgets.push(w);
  if (w.form) bindForm(w);
  prefetch(sitekey, action);
  return widgets.length - 1;
}

const bound = new WeakSet<HTMLFormElement>();

function bindForm(w: Widget): void {
  const form = w.form!;
  if (bound.has(form)) return;
  bound.add(form);
  let pass = false;
  form.addEventListener(
    "submit",
    (e) => {
      if (pass) { pass = false; return; }
      e.preventDefault();
      e.stopImmediatePropagation();
      const submitter = (e as SubmitEvent).submitter as HTMLElement | null;
      execute(w.sitekey, { action: w.action })
        .then((tok) => {
          w.inputs.forEach((i) => (i.value = tok));
          w.opts.callback?.(tok);
        })
        .catch((err) => {
          w.inputs.forEach((i) => (i.value = ""));
          w.opts["error-callback"]?.(err);
        })
        .finally(() => {
          pass = true;
          if (typeof form.requestSubmit === "function") form.requestSubmit(submitter && (submitter as any).form === form ? (submitter as HTMLButtonElement) : undefined);
          else form.submit();
        });
    },
    true,
  );
}

function reset(id = 0): void {
  widgets[id]?.inputs.forEach((i) => (i.value = ""));
}

function getResponse(id = 0): string {
  return widgets[id]?.inputs[0]?.value || "";
}

const readyQ: Array<() => void> = [];
let isReady = false;
function ready(fn: () => void): void {
  if (isReady) safe(fn, undefined);
  else readyQ.push(fn);
}

function autoRender(): void {
  document.querySelectorAll<HTMLElement>(".doorkeep, [data-doorkeep]").forEach((el) => safe(() => render(el), 0));
  isReady = true;
  readyQ.splice(0).forEach((f) => safe(f, undefined));
}

const api = { render, execute, reset, getResponse, ready, version: __DK_VERSION__ };
(window as any).doorkeep = api;

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", autoRender, { once: true });
else autoRender();

export default api;
