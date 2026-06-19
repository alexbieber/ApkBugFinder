const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const assetsDir = path.join(__dirname, '../docs/assets');
const svgs = [
  'severity-chart.svg',
  'masvs-coverage.svg',
  'architecture.svg',
  'comparison-chart.svg',
  'hero-banner.svg',
];

async function main() {
  const browser = await chromium.launch();
  const page = await browser.newPage();

  for (const svg of svgs) {
    const svgPath = path.join(assetsDir, svg);
    const pngPath = path.join(assetsDir, svg.replace('.svg', '.png'));
    const content = fs.readFileSync(svgPath, 'utf8');
    const match = content.match(/viewBox="0 0 (\d+) (\d+)"/);
    const width = match ? parseInt(match[1], 10) : 960;
    const height = match ? parseInt(match[2], 10) : 420;

    await page.setViewportSize({ width, height });
    await page.setContent(
      `<html><body style="margin:0;background:#09090b">${content}</body></html>`,
      { waitUntil: 'load' },
    );
    await page.screenshot({ path: pngPath, type: 'png' });
    console.log('Created', pngPath);
  }

  await browser.close();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
