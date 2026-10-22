// @doorkeep/next end to end: <Doorkeep> in a form, verifyDoorkeep() in a
// Server Action, snippet served through withDoorkeepProxy.
import { chromium, expect, test } from "@playwright/test";

test.skip(() => !process.env.DK_NEXT, "Next.js example not available");

const BASE = "http://localhost:18185";

test("a person signs up through the Next.js Server Action", async () => {
  const b = await chromium.launch({ headless: false, ignoreDefaultArgs: ["--enable-automation"], args: ["--disable-blink-features=AutomationControlled"] });
  const page = await b.newPage();
  await page.goto(BASE);
  await page.waitForFunction(() => (window as any).doorkeep !== undefined);
  const rnd = (a: number, z: number) => a + Math.random() * (z - a);
  for (const [sel, text] of [["#name", "Asha"], ["#email", "asha@example.com"]] as const) {
    const box = (await page.locator(sel).boundingBox())!;
    for (let i = 1; i <= 20; i++) { await page.mouse.move(box.x + box.width * (0.3 + 0.3 * Math.sin(i / 3)) , box.y + box.height / 2 + rnd(-3, 3)); await page.waitForTimeout(rnd(8, 25)); }
    await page.mouse.down(); await page.waitForTimeout(rnd(70, 130)); await page.mouse.up();
    for (const ch of text) { await page.keyboard.down(ch); await page.waitForTimeout(rnd(50, 110)); await page.keyboard.up(ch); await page.waitForTimeout(rnd(60, 180)); }
  }
  const go = (await page.locator("#go").boundingBox())!;
  for (let i = 1; i <= 15; i++) { await page.mouse.move(go.x + go.width * (0.2 + i / 40), go.y + go.height * (0.3 + i / 60)); await page.waitForTimeout(rnd(10, 25)); }
  await page.mouse.down(); await page.waitForTimeout(rnd(80, 120)); await page.mouse.up();
  const result = page.locator("#result");
  await result.waitFor({ timeout: 30_000 });
  console.log(`nextjs-human-detail: ok=${await result.getAttribute("data-ok")} risk=${await result.getAttribute("data-risk")} reasons=${await result.getAttribute("data-reasons")}`);
  await expect(result).toHaveAttribute("data-ok", "true", { timeout: 30_000 });
  console.log(`nextjs-human: ${await result.textContent()} risk=${await result.getAttribute("data-risk")}`);
  await b.close();
});

test("default headless Chromium is refused by the Server Action", async () => {
  const b = await chromium.launch({ headless: true });
  const page = await b.newPage();
  await page.goto(BASE);
  await page.waitForFunction(() => (window as any).doorkeep !== undefined);
  await page.fill("#name", "Bot");
  await page.fill("#email", "bot@example.com");
  await page.click("#go");
  const result = page.locator("#result");
  await expect(result).toHaveAttribute("data-ok", "false", { timeout: 30_000 });
  console.log(`nextjs-headless: ${await result.textContent()} risk=${await result.getAttribute("data-risk")}`);
  await b.close();
});
