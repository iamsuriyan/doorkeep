// Behaviour aggregates (design section 1.2 C). Raw coordinates, key
// identities and element identities never leave this module; only counts and
// statistics do. Absence of data is neutral on the server.
import type { Payload } from "../schema";
import { Stat, round, safe } from "../util";

const MAX_PTR = 200;
const HIST = [4, 8, 12, 20, 50]; // ms bucket edges for inter-sample intervals

export class Behaviour {
  private ptrN = 0;
  private path = 0;
  private first: [number, number] | null = null;
  private last: [number, number, number] | null = null; // x, y, t
  private prev: [number, number] | null = null; // previous point for collinearity
  private lastSpeed = 0;
  private lastAccelSign = 0;
  private lastAngle: number | null = null;
  private speed = new Stat();
  private interval = new Stat();
  private dirChanges = 0;
  private accelFlips = 0;
  private triples = 0;
  private collinear = 0;
  private hist = [0, 0, 0, 0, 0, 0];
  private events = 0;
  private untrusted = 0;

  private downAt = new Map<number, number>();
  private clickDur = new Stat();
  private clicks = 0;
  private centerHits = 0;
  private noMoveClick = 0;

  private keyDown = new Map<string, number>();
  private hold = new Stat();
  private keyInterval = new Stat();
  private lastKeyAt = 0;
  private keys = 0;
  private backspace = 0;
  private keyedFields = new WeakSet<EventTarget>();
  private inputFields = new Set<EventTarget>();
  private inputNoKey = new Set<EventTarget>();
  private pastes = 0;

  private scrolls = 0;
  private wheelClass = 0;
  private scrolledBeforeInteraction = 0;

  private focusStart = safe(() => document.hasFocus(), false);
  private visChanges = 0;

  firstInteraction = 0;

  start(): () => void {
    const opts: AddEventListenerOptions = { capture: true, passive: true };
    const on = <K extends keyof DocumentEventMap>(t: K, f: (e: DocumentEventMap[K]) => void) => {
      document.addEventListener(t, f as EventListener, opts);
      return () => document.removeEventListener(t, f as EventListener, opts);
    };
    const offs = [
      on("pointermove", (e) => this.onMove(e)),
      on("pointerdown", (e) => this.onDown(e)),
      on("pointerup", (e) => this.onUp(e)),
      on("keydown", (e) => this.onKeyDown(e)),
      on("keyup", (e) => this.onKeyUp(e)),
      on("input", (e) => this.onInput(e)),
      on("paste", () => { this.pastes++; }),
      on("wheel", (e) => this.onWheel(e)),
      on("scroll", () => this.onScroll()),
      on("visibilitychange", () => { this.visChanges++; }),
    ];
    const blur = () => { this.visChanges++; };
    window.addEventListener("blur", blur, opts);
    window.addEventListener("focus", blur, opts);
    return () => {
      offs.forEach((f) => f());
      window.removeEventListener("blur", blur, opts);
      window.removeEventListener("focus", blur, opts);
    };
  }

  private mark(e: Event): void {
    this.events++;
    if (!e.isTrusted) this.untrusted++;
    if (!this.firstInteraction && e.isTrusted) this.firstInteraction = performance.now();
  }

  private onMove(e: PointerEvent): void {
    this.mark(e);
    if (this.ptrN >= MAX_PTR) return;
    const x = e.clientX, y = e.clientY, t = e.timeStamp;
    this.ptrN++;
    if (!this.first) this.first = [x, y];
    if (this.last) {
      const [lx, ly, lt] = this.last;
      const dx = x - lx, dy = y - ly, dt = t - lt;
      const dist = Math.hypot(dx, dy);
      this.path += dist;
      if (dt > 0) {
        this.interval.push(dt);
        let b = HIST.findIndex((edge) => dt < edge);
        if (b < 0) b = HIST.length;
        this.hist[b]++;
        const sp = dist / dt;
        this.speed.push(sp);
        const acc = Math.sign(sp - this.lastSpeed);
        if (acc !== 0 && this.lastAccelSign !== 0 && acc !== this.lastAccelSign) this.accelFlips++;
        if (acc !== 0) this.lastAccelSign = acc;
        this.lastSpeed = sp;
      }
      if (dist > 0) {
        const ang = Math.atan2(dy, dx);
        if (this.lastAngle !== null) {
          let d = Math.abs(ang - this.lastAngle);
          if (d > Math.PI) d = 2 * Math.PI - d;
          if (d > Math.PI / 4) this.dirChanges++;
        }
        this.lastAngle = ang;
      }
      if (this.prev) {
        this.triples++;
        const [px, py] = this.prev;
        const cross = (lx - px) * (y - py) - (ly - py) * (x - px);
        if (Math.abs(cross) < 1e-6) this.collinear++;
      }
      this.prev = [lx, ly];
    }
    this.last = [x, y, t];
  }

  private onDown(e: PointerEvent): void {
    this.mark(e);
    this.downAt.set(e.pointerId, e.timeStamp);
    if (e.pointerType === "mouse" && this.ptrN === 0) this.noMoveClick = 1;
    safe(() => {
      const el = e.target as Element;
      const r = el.getBoundingClientRect();
      if (r.width > 4 && Math.abs(e.clientX - (r.left + r.width / 2)) < 1 && Math.abs(e.clientY - (r.top + r.height / 2)) < 1) this.centerHits++;
    }, undefined);
  }

  private onUp(e: PointerEvent): void {
    this.mark(e);
    const d = this.downAt.get(e.pointerId);
    if (d !== undefined) {
      this.clicks++;
      this.clickDur.push(e.timeStamp - d);
      this.downAt.delete(e.pointerId);
    }
  }

  private onKeyDown(e: KeyboardEvent): void {
    this.mark(e);
    if (e.repeat) return;
    this.keys++;
    if (e.key === "Backspace") this.backspace++;
    if (e.target) this.keyedFields.add(e.target);
    const t = e.timeStamp;
    if (this.lastKeyAt) this.keyInterval.push(t - this.lastKeyAt);
    this.lastKeyAt = t;
    this.keyDown.set(e.code || e.key, t);
  }

  private onKeyUp(e: KeyboardEvent): void {
    this.mark(e);
    const k = e.code || e.key;
    const d = this.keyDown.get(k);
    if (d !== undefined) {
      this.hold.push(e.timeStamp - d);
      this.keyDown.delete(k);
    }
  }

  private onInput(e: Event): void {
    if (!e.target) return;
    this.inputFields.add(e.target);
    if (!this.keyedFields.has(e.target)) this.inputNoKey.add(e.target);
    else this.inputNoKey.delete(e.target);
  }

  private onWheel(e: WheelEvent): void {
    this.mark(e);
    this.scrolls++;
    if (!this.firstInteraction) this.scrolledBeforeInteraction = 1;
    const dy = Math.abs(e.deltaY);
    if (e.deltaMode === 0 && dy > 0) {
      if (dy % 120 === 0 || dy % 100 === 0) this.wheelClass = this.wheelClass || 1;
      else if (dy % 1 !== 0) this.wheelClass = 2;
      else if (!this.wheelClass) this.wheelClass = 3;
    }
  }

  private onScroll(): void {
    this.scrolls++;
  }

  snapshot(): Payload["beh"] {
    const straight = this.first && this.last && this.path > 0
      ? Math.hypot(this.last[0] - this.first[0], this.last[1] - this.first[1]) / this.path
      : 0;
    const fields = this.inputFields.size;
    return {
      ptr: this.ptrN === 0 ? [] : [
        this.ptrN, round(this.path, 1), round(straight), round(this.speed.cv), this.dirChanges, this.accelFlips,
        round(this.interval.cv), round(this.triples ? this.collinear / this.triples : 0), round(this.events ? this.untrusted / this.events : 0),
        ...this.hist,
      ],
      clk: this.clicks === 0 ? [] : [this.clicks, round(this.clickDur.mean, 1), round(this.clickDur.cv), round(this.centerHits / this.clicks), this.noMoveClick],
      key: [
        this.keys, round(this.hold.mean, 1), round(this.hold.cv), round(this.keyInterval.cv),
        round(this.keys ? this.backspace / this.keys : 0), fields ? round(this.inputNoKey.size / fields) : -1, this.pastes,
      ],
      scr: [this.scrolls, this.wheelClass, this.scrolledBeforeInteraction],
      foc: [this.focusStart ? 1 : 0, safe(() => document.hasFocus(), false) ? 1 : 0, this.visChanges, document.visibilityState === "hidden" ? 1 : 0],
    };
  }
}

/** Measure 10 animation frames; resolves with [median, cv] or undefined. */
export function rafCadence(): Promise<number[] | undefined> {
  return new Promise((resolve) => {
    if (typeof requestAnimationFrame !== "function" || document.visibilityState === "hidden") return resolve(undefined);
    const ts: number[] = [];
    const timer = setTimeout(() => resolve(undefined), 600);
    const step = (t: number) => {
      ts.push(t);
      if (ts.length < 11) return void requestAnimationFrame(step);
      clearTimeout(timer);
      const d = ts.slice(1).map((v, i) => v - ts[i]).sort((a, b) => a - b);
      const s = new Stat();
      d.forEach((x) => s.push(x));
      resolve([round(d[d.length >> 1], 2), round(s.cv, 4)]);
    };
    requestAnimationFrame(step);
  });
}
