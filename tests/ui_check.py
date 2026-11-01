"""Headless-browser check of the UI against a running server (real or harness).
Usage:  python -m tests.ui_check http://127.0.0.1:8765
Requires: pip install playwright && playwright install chromium
"""
import sys
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
SHOTS = "docs/screenshots"
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail and not ok else ""))


with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1440, "height": 1000})
    console_errors, external = [], []
    page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: console_errors.append(str(e)))
    host = urlparse(BASE).netloc
    page.on("request", lambda r: external.append(r.url) if urlparse(r.url).netloc not in (host, "") and not r.url.startswith("data:") else None)

    page.goto(BASE)
    page.wait_for_selector("#health.ok", timeout=15000)
    check("health indicator turns ready", True)
    check("limit chips rendered", page.locator("#limits .chip").count() >= 5)
    check("gallery rendered with hostile group", page.locator(".ex").count() >= 8)
    check("editor preloaded with first example", "primes" in page.input_value("#editor"))
    page.screenshot(path=f"{SHOTS}/01-initial.png")

    # --- run via button
    page.click("#runBtn")
    page.wait_for_selector(".verdict", timeout=15000)
    check("normal run shows Completed", "Completed" in page.inner_text(".verdict"))
    check("stdout shown", "9592 primes" in page.inner_text("pre.out"))
    check("timeline has segments", page.locator(".timeline .seg").count() >= 3)
    page.screenshot(path=f"{SHOTS}/02-run-success.png")

    # --- keyboard shortcut + hostile example: infinite loop
    page.click('.ex[data-id="infinite_loop"]')
    check("clicking an example loads code", "while True" in page.input_value("#editor"))
    page.focus("#editor")
    page.keyboard.press("Control+Enter")
    page.wait_for_function("document.querySelector('.verdict .v-title') && document.querySelector('.verdict .v-title').textContent.includes('time limit')", timeout=15000)
    check("Ctrl+Enter runs; infinite loop killed at time limit", True)
    hit = page.locator(".seal.hit .n").all_inner_texts()
    check("Time seal marked as hit", hit == ["Time"], str(hit))
    page.screenshot(path=f"{SHOTS}/03-timeout.png")

    # --- XSS: output must be inert text
    page.fill("#editor", "print('<img src=x onerror=window.__xss=1>')\nprint('<script>window.__xss=2</script>')")
    page.click("#runBtn")
    page.wait_for_selector(".verdict", timeout=15000)
    page.wait_for_timeout(300)
    check("HTML in program output is not executed", page.evaluate("window.__xss === undefined"))
    check("HTML in output displayed literally", "<img src=x" in page.inner_text("pre.out"))

    # --- policy findings visible
    page.click('.ex[data-id="shell_escape"]')
    page.click("#runBtn")
    page.wait_for_selector(".findings", timeout=15000)
    check("policy findings rendered for subprocess import", "subprocess" in page.inner_text(".findings"))

    # --- full suite
    page.click("#suiteBtn")
    page.wait_for_function("(() => { const s = document.querySelector('#suiteSummary'); return s && !s.hidden && !s.className.includes('running'); })()", timeout=120000)
    summary = page.inner_text("#suiteSummary")
    check("containment suite: all payloads behaved as expected", summary.startswith("All"), summary)
    badges = page.locator("#gallery .badge.held").count()
    check("every example has a 'held' badge", badges == page.locator(".ex").count(), f"{badges} held")
    page.locator("#suiteSummary").scroll_into_view_if_needed()
    page.screenshot(path=f"{SHOTS}/04-suite.png", full_page=True)

    # --- history persisted
    check("history populated", page.locator(".hrow").count() >= 3)
    on_screen = page.evaluate("""() => [...document.querySelectorAll('.hrow .badge')].filter(b => {
        const r = b.getBoundingClientRect(); return r.width > 0 && r.left >= 0 && r.right <= window.innerWidth; }).length""")
    check("every history row shows its status badge ON SCREEN", on_screen == page.locator(".hrow").count(), f"{on_screen}/{page.locator('.hrow').count()}")
    check("API-key bar hidden when auth is off", not page.locator("#authBar").is_visible())

    # --- network hygiene & errors
    check("no external network requests (self-contained)", not external, str(external))
    check("no console errors", not console_errors, str(console_errors))
    page.close()

    # --- mobile layout
    m = browser.new_page(viewport={"width": 390, "height": 844})
    m.goto(BASE)
    m.wait_for_selector("#health.ok", timeout=15000)
    m.click("#runBtn")
    m.wait_for_selector(".verdict", timeout=15000)
    over = m.evaluate("document.scrollingElement.scrollWidth - window.innerWidth")
    check("mobile: no horizontal overflow", over <= 1, f"overflow={over}px")
    m.screenshot(path=f"{SHOTS}/05-mobile.png", full_page=True)
    browser.close()

failed = [r for r in results if not r[1]]
print(f"\n{len(results) - len(failed)}/{len(results)} UI checks passed")
sys.exit(1 if failed else 0)
