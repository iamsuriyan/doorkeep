// Visual/audio challenge dialog, loaded on demand from /v1/dk-ui.js only
// when a visual challenge is needed. Rendered in a shadow root so the
// host page's CSS cannot break it and it cannot leak styles.
//
// Accessibility: labelled modal dialog, focus moved in and kept inside,
// Escape cancels, image has alt text that points to the audio option,
// audio at normal and slower speed, errors announced via aria-live,
// works with forced colours, and the site's accessibility link (if any) is
// offered as an escape hatch. No time pressure: the challenge lasts 10 min.

export interface UIOptions {
  image: string;
  audio: string;
  audioSlow: string;
  length: number;
  attemptsLeft: number;
  accessibilityUrl?: string;
  submit: (answer: string) => Promise<{ ok: true; token: string } | { ok: false; attemptsLeft?: number; image?: string; audio?: string; exhausted?: boolean }>;
}

const CSS = `
:host { all: initial; }
.backdrop { position: fixed; inset: 0; background: rgba(0,0,0,.45); display: flex; align-items: center; justify-content: center; z-index: 2147483647; font: 15px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
.box { background: #fff; color: #1a1a1a; border-radius: 10px; padding: 20px; width: min(360px, calc(100vw - 32px)); box-shadow: 0 10px 40px rgba(0,0,0,.3); }
h2 { margin: 0 0 6px; font-size: 18px; }
p { margin: 0 0 12px; color: #444; }
img { display: block; width: 100%; height: auto; border: 1px solid #ccc; border-radius: 6px; background: #f4f4f4; }
.row { display: flex; gap: 8px; margin: 10px 0; flex-wrap: wrap; }
button { font: inherit; padding: 8px 12px; border-radius: 6px; border: 1px solid #888; background: #f6f6f6; color: #1a1a1a; cursor: pointer; min-height: 40px; }
button.primary { background: #1f4fd6; border-color: #1f4fd6; color: #fff; }
button:focus-visible, input:focus-visible, a:focus-visible { outline: 3px solid #f0a500; outline-offset: 2px; }
label { display: block; font-weight: 600; margin: 8px 0 4px; }
input { font: inherit; font-size: 20px; letter-spacing: 4px; text-transform: uppercase; width: 100%; box-sizing: border-box; padding: 8px 10px; border: 1px solid #888; border-radius: 6px; }
.err { color: #b00020; min-height: 1.4em; margin: 6px 0 0; }
.foot { margin-top: 12px; font-size: 13px; }
a { color: #1f4fd6; }
@media (forced-colors: active) { .box { border: 2px solid CanvasText; } button.primary { forced-color-adjust: auto; } }
@media (prefers-color-scheme: dark) { .box { background: #1e1e1e; color: #eee; } p { color: #bbb; } button { background: #2b2b2b; color: #eee; } input { background: #111; color: #eee; } a { color: #8fb0ff; } .err { color: #ff8a8a; } }
@media (prefers-reduced-motion: no-preference) { .box { animation: in .15s ease-out; } @keyframes in { from { transform: translateY(6px); opacity: 0; } } }
`;

export function open(opts: UIOptions): Promise<string> {
  return new Promise((resolve, reject) => {
    const host = document.createElement("div");
    // Open shadow root: isolation from page CSS, while staying inspectable by
    // assistive-technology test tools (a closed root protects nothing here).
    const root = host.attachShadow({ mode: "open" });
    host.setAttribute("data-doorkeep-challenge", "");
    const previous = document.activeElement as HTMLElement | null;
    const id = (s: string) => "dk-" + s;
    root.innerHTML = `<style>${CSS}</style>
<div class="backdrop">
  <div class="box" role="dialog" aria-modal="true" aria-labelledby="${id("t")}" aria-describedby="${id("d")}">
    <h2 id="${id("t")}">Quick check</h2>
    <p id="${id("d")}">Type the ${opts.length} characters shown below, or listen to them. Letters are not case-sensitive.</p>
    <img alt="Characters to type. If you cannot see them, use the Listen button." />
    <div class="row">
      <button type="button" data-a="listen">Listen</button>
      <button type="button" data-a="slow">Listen slowly</button>
    </div>
    <label for="${id("i")}">Characters</label>
    <input id="${id("i")}" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="${opts.length + 4}" inputmode="text" />
    <p class="err" role="status" aria-live="polite"></p>
    <div class="row">
      <button type="button" class="primary" data-a="submit">Continue</button>
      <button type="button" data-a="cancel">Cancel</button>
    </div>
    ${opts.accessibilityUrl ? `<p class="foot">Having trouble? <a href="${encodeURI(opts.accessibilityUrl)}" target="_blank" rel="noopener">Use another way to continue</a>.</p>` : ""}
  </div>
</div>`;
    const $ = <T extends Element>(q: string) => root.querySelector(q) as T;
    const img = $<HTMLImageElement>("img");
    const input = $<HTMLInputElement>("input");
    const err = $<HTMLParagraphElement>(".err");
    const dialog = $<HTMLDivElement>("[role=dialog]");
    let audio = opts.audio, audioSlow = opts.audioSlow;
    img.src = opts.image;
    let player: HTMLAudioElement | null = null;
    const play = (src: string) => {
      player?.pause();
      player = new Audio(src);
      player.play().catch(() => { err.textContent = "Audio could not play. Check that sound is allowed."; });
    };
    const close = () => {
      player?.pause();
      document.removeEventListener("keydown", onKey, true);
      host.remove();
      previous?.focus?.();
    };
    let busy = false;
    const submit = async () => {
      const v = input.value.trim();
      if (busy) return;
      if (v.length < opts.length) {
        err.textContent = `Please type all ${opts.length} characters.`;
        input.focus();
        return;
      }
      busy = true;
      err.textContent = "Checking…";
      try {
        const r = await opts.submit(v);
        if (r.ok) { close(); resolve(r.token); return; }
        if (r.exhausted) { close(); reject(new Error("doorkeep: challenge exhausted")); return; }
        if (r.image) img.src = r.image;
        if (r.audio) audio = r.audio;
        err.textContent = `That did not match. ${r.attemptsLeft ?? ""} ${r.attemptsLeft === 1 ? "try" : "tries"} left.`.replace("  ", " ");
        input.value = "";
        input.focus();
      } catch {
        err.textContent = "Something went wrong. Please try again.";
      } finally {
        busy = false;
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); close(); reject(new Error("doorkeep: challenge cancelled")); return; }
      if (e.key === "Enter" && root.activeElement === input) { e.preventDefault(); submit(); return; }
      if (e.key === "Tab") {
        const f = Array.from(dialog.querySelectorAll<HTMLElement>("button, input, a[href]"));
        const i = f.indexOf(root.activeElement as HTMLElement);
        const next = e.shiftKey ? (i <= 0 ? f.length - 1 : i - 1) : (i === f.length - 1 ? 0 : i + 1);
        e.preventDefault();
        f[next].focus();
      }
    };
    dialog.addEventListener("click", (e) => {
      const a = (e.target as HTMLElement).closest("button")?.dataset.a;
      if (a === "listen") play(audio);
      else if (a === "slow") play(audioSlow);
      else if (a === "submit") submit();
      else if (a === "cancel") { close(); reject(new Error("doorkeep: challenge cancelled")); }
    });
    document.addEventListener("keydown", onKey, true);
    document.body.appendChild(host);
    input.focus();
  });
}

(window as any).__doorkeepUI = { open };
