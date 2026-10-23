// The dashboard: sign-in, rendering with real data, accessibility.
import AxeBuilder from "@axe-core/playwright";
import { chromium, expect, test } from "@playwright/test";

const DK = "http://127.0.0.1:18181";

// One scored event, so the events page always has something to label.
async function seedEvent() {
  const sitekey = /data-sitekey="([^"]+)"/.exec(await (await fetch("http://localhost:18182/")).text())![1];
  const hdr = { "Content-Type": "text/plain", Origin: "http://localhost:18182", "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/130.0.0.0 Safari/537.36" };
  const s = await (await fetch(`${DK}/v1/session`, { method: "POST", headers: hdr, body: JSON.stringify({ sk: sitekey, a: "signup" }) })).json();
  const r = await fetch(`${DK}/v1/submit`, { method: "POST", headers: hdr, body: JSON.stringify({ v: 1, n: s.nonce, a: "signup" }) });
  expect(r.status).toBe(200);
}

test("dashboard signs in, renders the overview and passes axe", async () => {
  await seedEvent();
  const b = await chromium.launch();
  const ctx = await b.newContext({ viewport: { width: 1360, height: 1000 } });
  const page = await ctx.newPage();
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(`${DK}/admin/`);
  const axe = async (name: string) => {
    const r = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
    for (const v of r.violations) console.log(`axe ${name}: ${v.id} (${v.impact}) ${v.help} x${v.nodes.length}`);
    return r.violations;
  };
  expect(await axe("login")).toEqual([]);
  await page.fill("input[autocomplete=username]", "ops");
  await page.fill("input[type=password]", "wrong password!!");
  await page.click("button.primary");
  await expect(page.getByRole("alert")).toContainText("Wrong user or password");
  await page.fill("input[type=password]", "correct horse battery staple");
  await page.click("button.primary");
  await page.getByRole("link", { name: "e2e" }).first().click();
  await expect(page.getByRole("heading", { name: "Requests per hour" })).toBeVisible();
  await expect(page.getByText("Requests scored")).toBeVisible();
  expect(await axe("overview")).toEqual([]);
  await page.getByRole("link", { name: "Events", exact: true }).click();
  await page.waitForSelector("table, .empty");
  expect(await axe("events")).toEqual([]);
  // Bulk labelling.
  await page.getByRole("checkbox", { name: "Select all shown events" }).check();
  const toolbar = page.getByRole("toolbar", { name: "Label events" });
  await expect(toolbar).toContainText("selected");
  expect(await axe("events-selected")).toEqual([]);
  await toolbar.getByRole("button", { name: "Label bot" }).click();
  await expect(page.getByRole("status").filter({ hasText: /Labelled \d+ events? as bot/ })).toBeVisible();
  await expect(page.locator("tbody .badge", { hasText: "bot" }).first()).toBeVisible();
  // The API tokens page renders and passes axe.
  await page.getByRole("link", { name: "API tokens" }).click();
  await expect(page.getByRole("heading", { name: "API tokens" })).toBeVisible();
  expect(await axe("tokens")).toEqual([]);
  expect(errors).toEqual([]);
  await b.close();
});
