"use client";
// Client side: <Doorkeep /> inside a form, or useDoorkeep() for fetch-based
// forms. The snippet loads once from the same-origin /_dk/ proxy.
import { useCallback, useEffect } from "react";

declare global {
  interface Window {
    doorkeep?: { execute(sitekey?: string, opts?: { action?: string }): Promise<string>; render(el: HTMLElement, o?: object): number };
  }
}

const SRC = "/_dk/v1/dk.js";

const LOAD_TIMEOUT_MS = 15_000;
let loading: Promise<NonNullable<Window["doorkeep"]>> | null = null;

/** Load the snippet once. Rejects on a network error or after a timeout. */
function load(sitekey: string): Promise<NonNullable<Window["doorkeep"]>> {
  if (window.doorkeep) return Promise.resolve(window.doorkeep);
  if (loading) return loading;
  loading = new Promise<NonNullable<Window["doorkeep"]>>((resolve, reject) => {
    let s = document.querySelector<HTMLScriptElement>(`script[src="${SRC}"]`);
    const fresh = !s;
    if (!s) {
      s = document.createElement("script");
      s.src = SRC;
      s.async = true;
      s.dataset.sitekey = sitekey;
    }
    let timer = 0;
    let failed = false;
    const fail = (msg: string) => {
      failed = true;
      clearTimeout(timer);
      loading = null; // allow a retry, e.g. after the network comes back
      if (fresh) s!.remove();
      reject(new Error(msg));
    };
    const ready = () => {
      if (failed) return;
      if (window.doorkeep) {
        clearTimeout(timer);
        resolve(window.doorkeep);
      } else setTimeout(ready, 30);
    };
    // Listeners go on before the element is inserted, so an immediate
    // failure is never missed; an element some other code inserted earlier
    // may have failed already, which the timeout covers.
    s.addEventListener("error", () => fail("doorkeep snippet failed to load"), { once: true });
    timer = window.setTimeout(() => fail("doorkeep snippet did not load in time"), LOAD_TIMEOUT_MS);
    if (fresh) document.head.appendChild(s);
    ready();
  });
  return loading;
}

/** Place inside a <form>. Adds a hidden dk-response field on submit. */
export function Doorkeep({ action = "default", sitekey = process.env.NEXT_PUBLIC_DOORKEEP_SITE_KEY || "" }: { action?: string; sitekey?: string }) {
  useEffect(() => {
    load(sitekey).then((dk) => {
      const el = document.querySelector<HTMLElement>(`[data-doorkeep-action="${action}"]`);
      if (el) dk.render(el, { sitekey, action });
    });
  }, [action, sitekey]);
  return <div data-doorkeep-action={action} />;
}

/** For fetch-based forms: const execute = useDoorkeep(); const token = await execute("signup"). */
export function useDoorkeep(sitekey = process.env.NEXT_PUBLIC_DOORKEEP_SITE_KEY || "") {
  useEffect(() => { load(sitekey).catch(() => {}); }, [sitekey]);
  return useCallback(async (action = "default") => (await load(sitekey)).execute(sitekey, { action }), [sitekey]);
}
