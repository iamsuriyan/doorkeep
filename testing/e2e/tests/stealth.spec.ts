// Stealth tooling, measured (design section 10.4). These tests assert the
// detection set does not shrink; gaps are recorded in known_misses.yaml.
import { expect, test } from "@playwright/test";
import { chromium as chromiumExtra } from "playwright-extra";
import stealth from "puppeteer-extra-plugin-stealth";

const BASE = "http://localhost:18182";

test("playwright-extra + stealth plugin, headless", async () => {
  chromiumExtra.use(stealth());
  const b = await chromiumExtra.launch({ headless: true });
  const page = await b.newPage();
  await page.goto(`${BASE}/?run=stealth-headless`);
  await page.waitForFunction(() => (window as any).doorkeep !== undefined);
  await page.fill("#name", "Asha");
  await page.fill("#email", "asha@example.com");
  await page.click("#go");
  const v = JSON.parse((await page.locator("#result").textContent({ timeout: 30_000 })) || "{}");
  await b.close();
  console.log(`stealth-headless: success=${v.success} risk=${v.doorkeep?.risk} outcome=${v.doorkeep?.outcome} challenge=${v.doorkeep?.challenge} reasons=${v.doorkeep?.reasons.join(",")}`);
  // Must at least be challenged; record exactly what fired.
  expect(v.doorkeep.challenge === "pow" || !v.success).toBe(true);
});

test("playwright-extra + stealth, headed, human-like input", async () => {
  // The hard case: no automation flags, real keystrokes with jitter, curved
  // mouse paths, real press durations. Recorded, not asserted beyond "the
  // run completes"; see known_misses.yaml.
  chromiumExtra.use(stealth());
  const b = await chromiumExtra.launch({ headless: false, ignoreDefaultArgs: ["--enable-automation"], args: ["--disable-blink-features=AutomationControlled"] });
  const page = await b.newPage();
  await page.goto(`${BASE}/?run=stealth-human`);
  await page.waitForFunction(() => (window as any).doorkeep !== undefined);
  const rnd = (a: number, b: number) => a + Math.random() * (b - a);
  async function moveTo(sel: string) {
    const box = (await page.locator(sel).boundingBox())!;
    const tx = box.x + rnd(0.2, 0.8) * box.width, ty = box.y + rnd(0.3, 0.7) * box.height;
    const steps = Math.round(rnd(18, 35));
    const sx = rnd(50, 400), sy = rnd(50, 300), cx = rnd(0, 800), cy = rnd(0, 600);
    for (let i = 1; i <= steps; i++) {
      const t = i / steps, u = 1 - t;
      await page.mouse.move(u * u * sx + 2 * u * t * cx + t * t * tx + rnd(-1, 1), u * u * sy + 2 * u * t * cy + t * t * ty + rnd(-1, 1));
      await page.waitForTimeout(rnd(8, 28));
    }
  }
  async function click(sel: string) {
    await moveTo(sel);
    await page.mouse.down();
    await page.waitForTimeout(rnd(60, 140));
    await page.mouse.up();
  }
  async function type(text: string) {
    for (const ch of text) {
      await page.keyboard.down(ch);
      await page.waitForTimeout(rnd(50, 120));
      await page.keyboard.up(ch);
      await page.waitForTimeout(rnd(60, 220));
    }
  }
  await click("#name");
  await type("Asha");
  await click("#email");
  await type("asha@example.com");
  await page.waitForTimeout(rnd(500, 1200));
  await click("#go");
  const v = JSON.parse((await page.locator("#result").textContent({ timeout: 30_000 })) || "{}");
  await b.close();
  console.log(`stealth-human: success=${v.success} risk=${v.doorkeep?.risk} outcome=${v.doorkeep?.outcome} challenge=${v.doorkeep?.challenge} reasons=${v.doorkeep?.reasons.join(",")}`);
  expect(v.doorkeep).toBeDefined();
});
