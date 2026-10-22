// The dashboard: sign-in, rendering with real data, accessibility.
import AxeBuilder from "@axe-core/playwright";
import { chromium, expect, test } from "@playwright/test";

const DK = "http://127.0.0.1:18181";

test("dashboard signs in, renders the overview and passes axe", async () => {
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
  expect(errors).toEqual([]);
  await b.close();
});
