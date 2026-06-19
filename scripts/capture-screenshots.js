const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

async function main() {
  const outDir = path.join(__dirname, '../docs/screenshots');
  fs.mkdirSync(outDir, { recursive: true });

  const scanResult = JSON.parse(
    fs.readFileSync(path.join(__dirname, '../test-apks/scan-result.json'), 'utf8'),
  );

  const browser = await chromium.launch();
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 2,
  });
  const page = await context.newPage();

  // Homepage
  await page.goto('http://localhost:3000', { waitUntil: 'networkidle' });
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(outDir, '01-homepage.png'), fullPage: false });

  // Scan results — inject history
  await page.goto('http://localhost:3000');
  await page.evaluate((result) => {
    localStorage.setItem('apkbugfinder-scans', JSON.stringify([result]));
  }, scanResult);
  await page.goto(`http://localhost:3000/scan/${scanResult.id}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(2000);
  await page.screenshot({ path: path.join(outDir, '02-scan-dashboard.png'), fullPage: false });

  // Expanded finding
  const findingBtn = page.locator('button').filter({ hasText: 'Debuggable application' }).first();
  if (await findingBtn.count()) {
    await findingBtn.click();
    await page.waitForTimeout(500);
  }
  await page.screenshot({ path: path.join(outDir, '03-finding-detail.png'), fullPage: false });

  // Full page scroll capture
  await page.screenshot({ path: path.join(outDir, '04-full-report.png'), fullPage: true });

  await browser.close();
  console.log('Screenshots saved to docs/screenshots/');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
