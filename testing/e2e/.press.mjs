import { chromium } from "@playwright/test";
const b = await chromium.launch({ headless: false, ignoreDefaultArgs: ["--enable-automation"], args: ["--disable-blink-features=AutomationControlled"] });
const p = await b.newPage();
await p.setContent(`<button id=b style="width:200px;height:60px">x</button><script>
  window.d=[]; let t=0; b.addEventListener('pointerdown',e=>t=e.timeStamp); b.addEventListener('pointerup',e=>d.push(e.timeStamp-t));</script>`);
for (let i = 0; i < 40; i++) await p.click("#b");
const d = (await p.evaluate(() => d)).sort((a, b) => a - b);
console.log(process.argv[2], "n", d.length, "min", d[0].toFixed(2), "median", d[d.length >> 1].toFixed(2), "p90", d[Math.floor(d.length * 0.9)].toFixed(2), "max", d[d.length - 1].toFixed(2));
await b.close();
