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

function load(sitekey: string): Promise<NonNullable<Window["doorkeep"]>> {
  if (window.doorkeep) return Promise.resolve(window.doorkeep);
  let s = document.querySelector<HTMLScriptElement>(`script[src="${SRC}"]`);
  if (!s) {
    s = document.createElement("script");
    s.src = SRC;
    s.async = true;
    s.dataset.sitekey = sitekey;
    document.head.appendChild(s);
  }
  return new Promise((resolve, reject) => {
    const check = () => (window.doorkeep ? resolve(window.doorkeep) : setTimeout(check, 30));
    s!.addEventListener("error", () => reject(new Error("doorkeep snippet failed to load")));
    check();
  });
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
