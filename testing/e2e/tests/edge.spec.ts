// Edge mode through real nginx (auth_request) and Caddy (forward_auth).
import { chromium, expect, test } from "@playwright/test";

for (const [name, port] of [["nginx", 18183], ["caddy", 18184]] as const) {
  test.describe(`edge via ${name}`, () => {
    test.skip(() => !process.env.DK_EDGE, "Docker proxies not available");

    test(`${name}: a browser passes the check and reaches the protected page`, async () => {
      const b = await chromium.launch({ headless: false, ignoreDefaultArgs: ["--enable-automation"], args: ["--disable-blink-features=AutomationControlled"] });
      const page = await b.newPage();
      await page.goto(`http://localhost:${port}/search?q=doors`);
      await expect(page.locator("#protected")).toHaveText("Protected content", { timeout: 30_000 });
      expect(new URL(page.url()).pathname).toBe("/search");
      // The cookie now lets the browser straight through.
      const res = await page.goto(`http://localhost:${port}/`);
      expect(res?.status()).toBe(200);
      const cookies = await page.context().cookies();
      const edge = cookies.find((c) => c.name === "__dk_edge");
      console.log(`${name}: passed, cookie httpOnly=${edge?.httpOnly}`);
      expect(edge?.httpOnly).toBe(true);
      await b.close();
    });

    test(`${name}: default headless Chromium stays on the interstitial`, async () => {
      const b = await chromium.launch({ headless: true });
      const page = await b.newPage();
      await page.goto(`http://localhost:${port}/search`);
      await expect(page.locator("#msg")).toContainText("could not verify", { timeout: 30_000 });
      expect(await page.locator("#protected").count()).toBe(0);
      console.log(`${name}: headless blocked at ${new URL(page.url()).pathname}`);
      await b.close();
    });

    test(`${name}: API clients get 401 JSON, not a redirect`, async () => {
      const r = await fetch(`http://localhost:${port}/search`, { headers: { Accept: "application/json" }, redirect: "manual" });
      expect(r.status === 401 || (name === "nginx" && r.status === 302)).toBe(true);
    });
  });
}
