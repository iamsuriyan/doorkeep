// End-to-end detection matrix (design section 10.4, M1 subset).
// Assertions are on the siteverify response the customer backend receives,
// never on UI. Each test logs risk and reasons so drift is visible in CI.
import { chromium, expect, firefox, test, type Page } from "@playwright/test";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BASE = "http://localhost:18182";

interface Verify {
  success: boolean;
  "error-codes": string[];
  score?: number;
  doorkeep?: { risk: number; outcome: string; reasons: string[]; challenge: string };
}

async function signup(page: Page, run: string): Promise<Verify> {
  await page.goto(`${BASE}/?run=${run}`);
  await page.waitForFunction(() => (window as any).doorkeep !== undefined);
  await page.fill("#name", "Asha");
  await page.fill("#email", "asha@example.com");
  await page.click("#go");
  const txt = await page.locator("#result").textContent({ timeout: 30_000 });
  return JSON.parse(txt || "{}");
}

function log(name: string, v: Verify) {
  console.log(`${name}: success=${v.success} risk=${v.doorkeep?.risk} outcome=${v.doorkeep?.outcome} challenge=${v.doorkeep?.challenge} reasons=${v.doorkeep?.reasons.join(",")}`);
}

async function poll(run: string, ms = 45_000): Promise<Verify> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const r = await fetch(`${BASE}/result?run=${run}`);
    if (r.status === 200) return r.json();
    await new Promise((res) => setTimeout(res, 500));
  }
  throw new Error("no result for " + run);
}

test("default headless Chromium is not allowed", async () => {
  const b = await chromium.launch({ headless: true });
  const v = await signup(await b.newPage(), "chromium-headless");
  log("chromium-headless", v);
  await b.close();
  expect(v.success).toBe(false);
  expect(v.doorkeep!.risk).toBeGreaterThanOrEqual(35);
  expect(v.doorkeep!.reasons.some((r) => ["HEADLESS_UA", "AUTOMATION_WEBDRIVER"].includes(r))).toBe(true);
});

test("default headless Firefox is not allowed", async () => {
  const b = await firefox.launch({ headless: true });
  const v = await signup(await b.newPage(), "firefox-headless");
  log("firefox-headless", v);
  await b.close();
  expect(v.success).toBe(false);
  expect(v.doorkeep!.reasons).toContain("AUTOMATION_WEBDRIVER");
});

test("headed Chromium driven over CDP does not get through", async () => {
  // Headed, webdriver flag removed: the hardest Playwright configuration
  // without stealth plugins. Detection rests on behaviour (fill without
  // keys, exact-centre zero-duration clicks): risk 70. The snippet solves the
  // proof of work automatically, which leaves risk 50, still in the
  // challenge band, so the visual challenge opens and the form never posts.
  // When earlier runs from this machine have already raised velocity
  // signals, it is blocked outright instead. Either way it must not pass.
  const b = await chromium.launch({
    headless: false,
    ignoreDefaultArgs: ["--enable-automation"],
    args: ["--disable-blink-features=AutomationControlled"],
  });
  const run = "chromium-headed-cdp";
  const page = await b.newPage();
  await page.goto(`${BASE}/?run=${run}`);
  await page.waitForFunction(() => (window as any).doorkeep !== undefined);
  await page.fill("#name", "Asha");
  await page.fill("#email", "asha@example.com");
  await page.click("#go");
  let dialog = false;
  let v: Verify | null = null;
  const end = Date.now() + 25_000;
  while (Date.now() < end && !dialog && !v) {
    dialog = await page.evaluate(() => !!document.querySelector("[data-doorkeep-challenge]")).catch(() => false);
    const r = await fetch(`${BASE}/result?run=${run}`);
    if (r.status === 200) v = await r.json();
    await new Promise((res) => setTimeout(res, 300));
  }
  if (dialog) {
    await page.waitForTimeout(1500);
    const r = await fetch(`${BASE}/result?run=${run}`);
    console.log(`${run}: visual challenge shown, form posted=${r.status === 200}`);
    expect(r.status).toBe(404);
  } else {
    expect(v).not.toBeNull();
    log(run, v!);
    expect(v!.success).toBe(false);
  }
  await b.close();
});

test("a real Chromium with no automation is allowed", async () => {
  // Launch the browser binary directly, no CDP, no webdriver. The page
  // submits itself after 4 s. This is the false-positive baseline.
  const exe = chromium.executablePath();
  const profile = mkdtempSync(join(tmpdir(), "dk-chrome-"));
  const run = "chromium-real";
  const p = spawn("xvfb-run", ["-a", "-s", "-screen 0 1920x1080x24", exe,
    // --no-sandbox matches what Playwright passes; Ubuntu's AppArmor blocks the
    // sandbox for unpacked Chromium builds. It does not change any signal.
    `--user-data-dir=${profile}`, "--no-sandbox", "--no-first-run", "--no-default-browser-check", "--password-store=basic",
    "--window-size=1366,900", `${BASE}/?run=${run}&auto=4000`], { stdio: "ignore", detached: true });
  try {
    const v = await poll(run);
    log(run, v);
    expect(v.success).toBe(true);
    expect(v.doorkeep!.outcome).toBe("allow");
    expect(v.doorkeep!.reasons).not.toContain("CDP_RUNTIME_LEAK");
    expect(v.doorkeep!.reasons).not.toContain("AUTOMATION_WEBDRIVER");
  } finally {
    try { process.kill(-p.pid!, "SIGTERM"); } catch {}
    rmSync(profile, { recursive: true, force: true });
  }
});
