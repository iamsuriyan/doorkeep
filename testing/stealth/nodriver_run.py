# /// script
# requires-python = ">=3.10"
# dependencies = ["nodriver>=0.38"]
# ///
"""Drive the e2e fixture's signup form with Nodriver (CDP without
WebDriver or Playwright), headed, with CDP key and mouse events.

    uv run --script nodriver_run.py <fixture-url> <chromium-executable>
"""
import asyncio
import random
import sys

import nodriver as uc


async def main(url: str, exe: str) -> None:
    browser = await uc.start(headless=False, browser_executable_path=exe, sandbox=False)
    tab = await browser.get(url)
    await tab.wait_for("#go", timeout=30)
    await asyncio.sleep(1.5)
    for sel, text in (("#name", "Asha Kumar"), ("#email", "asha.kumar@example.com")):
        el = await tab.select(sel)
        await el.mouse_click()
        for ch in text:
            await el.send_keys(ch)
            await asyncio.sleep(random.uniform(0.06, 0.18))
        await asyncio.sleep(random.uniform(0.3, 0.8))
    go = await tab.select("#go")
    await go.mouse_move()
    await asyncio.sleep(0.3)
    await go.mouse_click()
    await asyncio.sleep(12)
    state = await tab.evaluate(
        "document.querySelector('[data-doorkeep-challenge]') ? 'challenge' : (location.pathname === '/signup' ? 'posted' : 'form:' + location.pathname)"
    )
    print("PAGE", state, flush=True)
    browser.stop()


uc.loop().run_until_complete(main(sys.argv[1], sys.argv[2]))
