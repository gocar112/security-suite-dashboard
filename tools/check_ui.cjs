/* Read-only browser QA against a running suite. Install Playwright to use. */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require(process.env.SUITE_PLAYWRIGHT || "playwright");
const url = process.env.SUITE_URL || "http://127.0.0.1:8787";
const output = path.resolve(__dirname, "../docs/images");

(async () => {
  fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ headless: true, channel: process.env.SUITE_BROWSER || undefined });
  try {
    const errors = [];
    let automaticScans = 0;
    const page = await browser.newPage();
    page.setDefaultTimeout(15000);
    page.on("pageerror", error => errors.push(error.message));
    page.on("console", message => { if (message.type() === "error") errors.push(message.text()); });
    page.on("request", request => {
      if (request.method() === "POST" && /\/api\/(jobs|inventory)$/.test(new URL(request.url()).pathname)) automaticScans++;
    });
    const tabs = ["overview", "antivirus", "ids", "response", "inventory", "playbooks", "analysis", "training", "integrations", "audit"];
    for (const width of [390, 768, 1440, 1920]) {
      await page.setViewportSize({ width, height: width >= 1440 ? 1000 : 900 });
      await page.goto(url);
      await page.waitForSelector("#console-nav button");
      assert.equal(await page.locator("#console-nav button").count(), 10);
      for (const tab of tabs) {
        await page.locator("#tab-" + tab).click();
        await page.waitForTimeout(130);
        assert.equal(await page.locator(".console-view:visible").count(), 1);
        const dimensions = await page.evaluate(() => ({
          viewport: window.innerWidth, width: document.documentElement.scrollWidth,
          height: document.documentElement.scrollHeight
        }));
        assert.ok(dimensions.width <= dimensions.viewport + 1, `${tab} overflows at ${width}: ${dimensions.width}`);
        assert.ok(dimensions.height < 7000, `${tab} unbounded height: ${dimensions.height}`);
      }
      await page.locator("#tab-overview").click();
      await page.screenshot({ path: path.join(output, `console-${width}.png`), fullPage: true });
    }
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.locator("#tab-antivirus").click();
    await page.waitForSelector("#drive-select option:nth-child(2)", { state: "attached" });
    await page.screenshot({ path: path.join(output, "console-antivirus.png"), fullPage: true });
    await page.locator("#tab-playbooks").click();
    await page.waitForSelector("#book-skills [data-skill]");
    await page.locator('[data-skill="guidance"]').click();
    await page.locator('[data-skill="annotate"]').click();
    assert.equal(await page.locator("#book-steps .step").count(), 2);
    await page.locator("#book-steps [data-note]").fill("Review evidence before containment.");
    await page.locator("#book-validate").click();
    await page.waitForFunction(() => document.getElementById("book-result").textContent.includes("Valid version"));
    assert.equal(await page.locator("#book-execute").isDisabled(), true);
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: path.join(output, "console-playbooks.png"), fullPage: true });
    await page.locator("#tab-analysis").click();
    await page.locator("#analysis-text").fill("Harmless text-only inspection sample.");
    await page.locator("#analysis-run").click();
    await page.waitForFunction(() => document.getElementById("analysis-result").textContent.includes('"executed": false'));
    await page.locator("#tab-training").click();
    await page.waitForSelector("[data-answer]");
    await page.locator("[data-answer]").first().click();
    await page.waitForFunction(() => !document.getElementById("training-next").hidden);
    await page.locator("#training-next").click();
    await page.waitForSelector("[data-answer]");
    await page.locator("[data-answer]").first().click();
    await page.waitForFunction(() => document.getElementById("training-result").textContent.includes("Correct response"));
    await page.screenshot({ path: path.join(output, "console-training.png"), fullPage: true });
    await page.locator("#density-toggle").click();
    assert.equal(await page.locator("body.density-tv").count(), 1);
    assert.equal(automaticScans, 0);
    assert.deepEqual(errors, []);
    console.log("Browser QA passed: ten tabs at 390/768/1440/1920; live analysis, playbook validation, training, TV density; no automatic scans.");
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
