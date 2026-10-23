// Advanced automation tools (design section 10: patchright, Camoufox,
// Nodriver). Each drives the fixture signup form; the verdict comes from the
// fixture backend's siteverify call. Expectations live in advanced.json:
// "caught" cases fail the suite if they get through (a regression), "miss"
// cases are reported only (tracked in known_misses.yaml).
import { expect, test, chromium as pwChromium, type Page } from "@playwright/test";
import { execFile, execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const BASE = "http://localhost:18182";
const STEALTH = join(here, "../../stealth");
const expectations: Record<string, "caught" | "miss" | "unmeasured"> = JSON.parse(readFileSync(join(here, "../advanced.json"), "utf8"));

type Verdict = { status: "allowed" | "refused" | "stopped"; risk?: number; reasons?: string[] };

async function verdict(run: string, ms = 40_000): Promise<Verdict> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const r = await fetch(`${BASE}/result?run=${run}`);
    if (r.status === 200) {
      const v = await r.json();
      return { status: v.success ? "allowed" : "refused", risk: v.doorkeep?.risk, reasons: v.doorkeep?.reasons };
    }
    await new Promise((res) => setTimeout(res, 500));
  }
  return { status: "stopped" }; // never posted: held at the challenge
}

// For runs that never posted: the latest scored event, through the admin API.
let adminToken = "";
async function latestEvent(): Promise<{ risk: number; reasons: string[] } | null> {
  try {
    if (!adminToken) {
      adminToken = execFileSync(join(here, "../../../bin/doorkeep"), ["admin", "token", "--name", "advanced-spec", "--ttl", "1d"],
        { env: { ...process.env, DOORKEEP_DATA_DIR: process.env.DK_DATA } }).toString().trim();
    }
    const h = { Authorization: `Bearer ${adminToken}` };
    const sites = await (await fetch("http://127.0.0.1:18181/admin/v1/sites", { headers: h })).json();
    const site = sites.find((s: any) => s.name === "e2e");
    const [e] = await (await fetch(`http://127.0.0.1:18181/admin/v1/sites/${site.id}/events?limit=1`, { headers: h })).json();
    if (process.env.DK_ADVANCED_DEBUG && e) {
      const d = await (await fetch(`http://127.0.0.1:18181/admin/v1/sites/${site.id}/events/${e.id}`, { headers: h })).json();
      console.log("beh:", JSON.stringify(Object.fromEntries((d.feature_groups.beh || []).map((f: any) => [f.key, f.value]))));
    }
    return e ? { risk: e.risk, reasons: e.reasons.filter((r: any) => r.w !== 0).map((r: any) => r.code) } : null;
  } catch {
    return null;
  }
}

async function judge(run: string, v: Verdict) {
  if (v.status === "stopped" || process.env.DK_ADVANCED_DEBUG) {
    const e = await latestEvent();
    if (e) Object.assign(v, e);
  }
  console.log(`${run}: ${v.status}${v.risk !== undefined ? ` risk=${v.risk}` : ""}${v.reasons ? ` reasons=${v.reasons.join(",")}` : ""} (expected ${expectations[run]})`);
  if (expectations[run] === "caught") expect(v.status, `${run} used to be caught`).not.toBe("allowed");
}

const rnd = (a: number, z: number) => a + Math.random() * (z - a);
async function humanInput(page: Page) {
  for (const [sel, text] of [["#name", "Asha Kumar"], ["#email", "asha.kumar@example.com"]]) {
    const b = (await page.locator(sel).boundingBox())!;
    for (let i = 1; i <= 20; i++) { await page.mouse.move(b.x + b.width * (0.2 + 0.3 * Math.sin(i / 4)), b.y + b.height / 2 + rnd(-4, 4)); await page.waitForTimeout(rnd(8, 25)); }
    await page.mouse.down(); await page.waitForTimeout(rnd(70, 140)); await page.mouse.up();
    for (const ch of text) { await page.keyboard.down(ch); await page.waitForTimeout(rnd(40, 110)); await page.keyboard.up(ch); await page.waitForTimeout(rnd(50, 170)); }
  }
  const g = (await page.locator("#go").boundingBox())!;
  for (let i = 1; i <= 16; i++) { await page.mouse.move(g.x + g.width * (0.3 + i / 60), g.y + g.height * (0.4 + i / 90)); await page.waitForTimeout(rnd(10, 25)); }
  await page.mouse.down(); await page.waitForTimeout(rnd(80, 130)); await page.mouse.up();
}

async function patchright(run: string, human: boolean) {
  let pr: typeof import("patchright");
  try { pr = await import("patchright"); } catch { test.skip(true, "patchright not installed"); return; }
  const profile = mkdtempSync(join(tmpdir(), "dk-pr-"));
  const ctx = await pr.chromium.launchPersistentContext(profile, { headless: false, viewport: null });
  try {
    const page = ctx.pages()[0] ?? (await ctx.newPage());
    await page.goto(`${BASE}/?run=${run}`);
    await page.waitForFunction(() => (window as any).doorkeep !== undefined);
    await page.waitForTimeout(1500);
    if (human) await humanInput(page as unknown as Page);
    else { await page.fill("#name", "Asha"); await page.fill("#email", "asha@example.com"); await page.click("#go"); }
    await judge(run, await verdict(run));
  } finally {
    await ctx.close();
    rmSync(profile, { recursive: true, force: true });
  }
}

// Runs a Python driver; returns the page state it reports ("challenge",
// "posted", ...). A driver that fails to report fails the test, so a broken
// driver can never pass as "stopped at the challenge".
function uvDriver(run: string, script: string, args: string[] = []) {
  return new Promise<string>((resolve, reject) => {
    execFile("uv", ["run", "--quiet", "--script", join(STEALTH, script), `${BASE}/?run=${run}`, ...args], { timeout: 150_000 }, (err, out, stderr) => {
      const m = /^PAGE (\S+)/m.exec(String(out));
      if (m) return resolve(m[1]);
      reject(new Error(`${run} driver did not finish: ${String(stderr || err).slice(-400)}`));
    });
  });
}

function hasUv(): boolean {
  try { return !!process.env.PATH?.split(":").some((d) => existsSync(join(d, "uv"))); } catch { return false; }
}

test.describe("advanced automation", () => {
  test.skip(() => !process.env.DK_ADVANCED, "set DK_ADVANCED=1 (downloads patched browsers)");
  test.setTimeout(180_000);

  test("patchright, default input", async () => { await patchright("patchright-default", false); });
  test("patchright, human-like input", async () => { await patchright("patchright-human", true); });

  test("Camoufox, humanized", async () => {
    test.skip(!hasUv(), "uv not installed");
    test.skip(!process.env.DK_CAMOUFOX, "set DK_CAMOUFOX=1 after `uv run --with camoufox python -m camoufox fetch` (1.3 GB)");
    test.setTimeout(300_000); // first launch unpacks the browser
    const page = await uvDriver("camoufox-human", "camoufox_run.py");
    console.log(`camoufox-human page: ${page}`);
    await judge("camoufox-human", await verdict("camoufox-human", 5_000));
  });

  test("Nodriver, CDP input", async () => {
    test.skip(!hasUv(), "uv not installed");
    const page = await uvDriver("nodriver", "nodriver_run.py", [pwChromium.executablePath()]);
    console.log(`nodriver page: ${page}`);
    await judge("nodriver", await verdict("nodriver", 5_000));
  });
});
