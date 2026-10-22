// Accessibility and keyboard behaviour of the visual/audio challenge dialog.
import AxeBuilder from "@axe-core/playwright";
import { chromium, expect, test } from "@playwright/test";

const BASE = "http://localhost:18182";

test("challenge dialog has no axe-core violations", async () => {
  const b = await chromium.launch();
  const page = await (await b.newContext()).newPage();
  await page.goto(`${BASE}/ui-harness`);
  await page.click("#opener");
  await page.waitForSelector("[data-doorkeep-challenge]", { state: "attached" });
  const results = await new AxeBuilder({ page }).include("[data-doorkeep-challenge]").withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  for (const v of results.violations) console.log(`axe: ${v.id} ${v.impact} ${v.help}`);
  await b.close();
  expect(results.violations).toEqual([]);
});

test("challenge dialog is fully keyboard operable", async () => {
  const b = await chromium.launch();
  const page = await b.newPage();
  await page.goto(`${BASE}/ui-harness`);
  await page.click("#opener");
  await page.waitForSelector("[data-doorkeep-challenge]", { state: "attached" });
  // Focus starts in the input; typing and Enter submit.
  const focused = () => page.evaluate(() => {
    const host = document.querySelector("[data-doorkeep-challenge]")!;
    const el = host.shadowRoot!.activeElement as HTMLElement | null;
    return el ? el.tagName + ":" + (el.textContent || (el as HTMLInputElement).id) : "none";
  });
  expect(await focused()).toContain("INPUT");
  await page.keyboard.type("wrong");
  await page.keyboard.press("Enter");
  await expect.poll(() => page.evaluate(() => document.querySelector("[data-doorkeep-challenge]")!.shadowRoot!.querySelector(".err")!.textContent)).toContain("2 tries left");
  // Tab cycles within the dialog and never escapes to the page.
  for (let i = 0; i < 12; i++) {
    await page.keyboard.press("Tab");
    expect(await focused()).not.toBe("none");
  }
  // Correct answer, case-insensitive.
  await page.evaluate(() => (document.querySelector("[data-doorkeep-challenge]")!.shadowRoot!.querySelector("input") as HTMLInputElement).focus());
  await page.keyboard.type("acdef");
  await page.keyboard.press("Enter");
  await expect.poll(() => page.evaluate(() => (window as any).result)).toBe("token:tok");
  // Escape cancels and returns focus to the opener.
  await page.click("#opener");
  await page.waitForSelector("[data-doorkeep-challenge]", { state: "attached" });
  await page.keyboard.press("Escape");
  await expect.poll(() => page.evaluate(() => (window as any).result)).toContain("cancelled");
  expect(await page.evaluate(() => document.activeElement?.id)).toBe("opener");
  await b.close();
});
