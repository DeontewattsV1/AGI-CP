import { expect, test } from "@playwright/test";

test("TRACT Monument renders at accepted 1000x1000 viewport", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "TRACT v0.2 RUNTIME" })).toBeVisible();
  await expect(page.getByText("DEMO FIXTURE")).toBeVisible();
  await page.screenshot({ path: "artifacts/tract-console-1000.png", fullPage: true });
});
