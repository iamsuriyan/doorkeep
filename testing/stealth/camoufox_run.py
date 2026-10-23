# /// script
# requires-python = ">=3.10"
# dependencies = ["camoufox[geoip]>=0.4"]
# ///
"""Drive the e2e fixture's signup form with Camoufox (a Firefox build that
spoofs its fingerprint at the C++ level), headed, with Camoufox's humanized
cursor and per-key typing delays.

    uv run --script camoufox_run.py <fixture-url-with-run-param>
"""
import random
import sys
import time

from camoufox.sync_api import Camoufox

url = sys.argv[1]
with Camoufox(headless=False, humanize=True, os="linux") as browser:
    page = browser.new_page()
    page.goto(url)
    page.wait_for_function("window.doorkeep !== undefined", timeout=30000)
    time.sleep(1.5)
    for sel, text in (("#name", "Asha Kumar"), ("#email", "asha.kumar@example.com")):
        page.click(sel)
        for ch in text:
            page.keyboard.type(ch)
            time.sleep(random.uniform(0.06, 0.18))
        time.sleep(random.uniform(0.3, 0.8))
    page.click("#go")
    time.sleep(12)  # PoW, if any, runs in the page
    state = page.evaluate(
        "document.querySelector('[data-doorkeep-challenge]') ? 'challenge' : (location.pathname === '/signup' ? 'posted' : 'form:' + location.pathname)"
    )
    print("PAGE", state, flush=True)
