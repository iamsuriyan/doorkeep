// The WordPress plugin on a real WordPress (opt-in: DK_WP=1).
import { chromium, expect, test, type Page } from "@playwright/test";

test.skip(() => !process.env.DK_WP_READY, "set DK_WP=1 to run the WordPress tests");

const WP = "http://localhost:18186";
const rnd = (a: number, z: number) => a + Math.random() * (z - a);

async function humanType(page: Page, sel: string, text: string) {
  await page.locator(sel).scrollIntoViewIfNeeded();
  const box = (await page.locator(sel).boundingBox())!;
  for (let i = 1; i <= 18; i++) { await page.mouse.move(box.x + box.width * (0.3 + 0.2 * Math.sin(i / 3)), box.y + box.height / 2 + rnd(-3, 3)); await page.waitForTimeout(rnd(8, 25)); }
  await page.mouse.down(); await page.waitForTimeout(rnd(70, 130)); await page.mouse.up();
  for (const ch of text) { await page.keyboard.down(ch); await page.waitForTimeout(rnd(40, 100)); await page.keyboard.up(ch); await page.waitForTimeout(rnd(50, 160)); }
}

async function humanClick(page: Page, sel: string) {
  await page.locator(sel).scrollIntoViewIfNeeded();
  const b = (await page.locator(sel).boundingBox())!;
  for (let i = 1; i <= 14; i++) { await page.mouse.move(b.x + b.width * (0.25 + i / 50), b.y + b.height * (0.35 + i / 80)); await page.waitForTimeout(rnd(10, 25)); }
  await page.mouse.down(); await page.waitForTimeout(rnd(80, 120)); await page.mouse.up();
}

const headed = { headless: false, ignoreDefaultArgs: ["--enable-automation"], args: ["--disable-blink-features=AutomationControlled"] };

test("a person logs in to WordPress", async () => {
  const b = await chromium.launch(headed);
  const page = await b.newPage();
  await page.goto(`${WP}/wp-login.php`);
  await page.waitForFunction(() => (window as any).doorkeep !== undefined);
  await humanType(page, "#user_login", "admin");
  await humanType(page, "#user_pass", "correct horse battery staple");
  await humanClick(page, "#wp-submit");
  await page.waitForURL(/wp-admin/, { timeout: 30_000 });
  console.log("wordpress-login-human: reached", new URL(page.url()).pathname);
  await b.close();
});

test("default headless Chromium cannot log in, even with the right password", async () => {
  const b = await chromium.launch({ headless: true });
  const page = await b.newPage();
  await page.goto(`${WP}/wp-login.php`);
  await page.waitForFunction(() => (window as any).doorkeep !== undefined);
  await page.fill("#user_login", "admin");
  await page.fill("#user_pass", "correct horse battery staple");
  await page.click("#wp-submit");
  await expect(page.locator("#login_error")).toContainText("could not verify", { timeout: 30_000 });
  console.log("wordpress-login-headless: refused");
  await b.close();
});

test("comments: a person can comment, headless Chromium cannot", async () => {
  const b = await chromium.launch(headed);
  const page = await b.newPage();
  await page.goto(`${WP}/?p=1`);
  await page.waitForFunction(() => (window as any).doorkeep !== undefined);
  await humanType(page, "#comment", "Lovely post, thanks");
  await humanType(page, "#author", "Asha");
  await humanType(page, "#email", "asha@example.com");
  await humanClick(page, "#submit");
  await expect(page.locator("body")).toContainText(/awaiting moderation|Lovely post/, { timeout: 30_000 });
  await b.close();

  const h = await chromium.launch({ headless: true });
  const p2 = await h.newPage();
  await p2.goto(`${WP}/?p=1`);
  await p2.waitForFunction(() => (window as any).doorkeep !== undefined);
  await p2.fill("#comment", "Buy cheap pills");
  await p2.fill("#author", "Spam");
  await p2.fill("#email", "spam@example.com");
  await p2.click("#submit");
  await expect(p2.locator("body")).toContainText("could not verify", { timeout: 30_000 });
  console.log("wordpress-comment: human posted, headless refused");
  await h.close();
});
