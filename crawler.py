from playwright.async_api import async_playwright
from termcolor import colored
import asyncio
import re
from urllib.parse import urljoin, urlparse
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

async def crawl_website(target_url: str, timeout_seconds: int = 300):
    print(colored(f"Starting crawl for {target_url} with Playwright...", "blue"))
    crawled_urls = set()
    websocket_urls = set()
    to_crawl = {target_url}
    max_requests = 100
    max_depth = 5
    current_depth = 0
    per_page_timeout = 30  # seconds

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 720},
                ignore_https_errors=True,
            )

            async def crawl_page(url, depth):
                nonlocal crawled_urls, websocket_urls, to_crawl
                if len(crawled_urls) >= max_requests or depth > max_depth or url in crawled_urls:
                    return

                parsed_target = urlparse(target_url)
                parsed_url = urlparse(url)
                if parsed_url.netloc != parsed_target.netloc:
                    return

                crawled_urls.add(url)
                print(colored(f"Crawling (Depth {depth}): {url}", "blue"))

                page = await context.new_page()
                try:
                    page.on("websocket", lambda ws: websocket_urls.add(ws.url) if ws.url.startswith(('ws://', 'wss://')) else None)
                    page.on("console", lambda msg: logging.info(f"Console: {msg.text}"))
                    page.on("requestfailed", lambda req: logging.warning(f"Request failed: {req.url} - {req.failure}"))

                    response = await page.goto(url, timeout=15000, wait_until="domcontentloaded")
                    if not response or response.status in (403, 429):
                        logging.warning(f"Access denied or throttled at {url}, status: {response.status if response else 'N/A'}")
                        return

                    content = await page.content()
                    if "Enable JavaScript and cookies" in content or "challenge" in content:
                        logging.warning(f"Blocked by bot challenge at {url}, skipping.")
                        return

                    # Wait for network to settle
                    try:
                        await page.wait_for_load_state("networkidle", timeout=5000)
                    except Exception:
                        pass

                    # Scroll to load dynamic content
                    await page.evaluate("window.scrollTo(0, document.body.scrollHeight);")
                    await asyncio.sleep(3)

                    # Try interacting with elements
                    interactive_elements = await page.query_selector_all('button, a[href], input[type="submit"], div[role="button"]')
                    for element in interactive_elements[:15]:
                        try:
                            if await element.is_visible():
                                await element.click()
                                await asyncio.sleep(2)
                        except Exception as e:
                            logging.debug(f"Interaction issue in {url}: {e}")

                    # Extract new URLs
                    new_urls = set()
                    links = await page.query_selector_all('a[href]')
                    for link in links:
                        try:
                            href = await link.get_attribute('href')
                            if href:
                                absolute_url = urljoin(url, href)
                                parsed_abs = urlparse(absolute_url)
                                if (absolute_url.startswith(('http://', 'https://')) and
                                    parsed_abs.netloc == parsed_target.netloc and
                                    absolute_url not in crawled_urls and
                                    absolute_url not in to_crawl):
                                    new_urls.add(absolute_url)
                        except Exception:
                            continue
                    to_crawl.update(new_urls)

                    # Extract WebSocket URLs
                    ws_in_html = re.findall(r'(wss?://[^\s"\']+)', content, re.IGNORECASE)
                    websocket_urls.update(ws_in_html)

                    scripts = await page.query_selector_all('script')
                    for script in scripts:
                        try:
                            script_content = await script.inner_text()
                            script_urls = re.findall(r'(wss?://[^\s"\']+)', script_content, re.IGNORECASE)
                            ws_dynamic = re.findall(r'new\s+WebSocket\s*\(\s*[\'"](wss?://[^\s"\']+)[\'"]\s*\)', script_content, re.IGNORECASE)
                            websocket_urls.update(script_urls)
                            websocket_urls.update(ws_dynamic)
                        except Exception:
                            pass

                except Exception as e:
                    logging.error(f"Error processing {url}: {e}")
                finally:
                    await page.close()

            try:
                while to_crawl and len(crawled_urls) < max_requests and current_depth <= max_depth:
                    current_batch = list(to_crawl - crawled_urls)
                    to_crawl.difference_update(current_batch)
                    tasks = [
                        asyncio.wait_for(crawl_page(url, current_depth), timeout=per_page_timeout)
                        for url in current_batch
                    ]
                    await asyncio.gather(*tasks, return_exceptions=True)
                    current_depth += 1
                    print(colored(f"Depth {current_depth}: Crawled {len(crawled_urls)} URLs, {len(to_crawl)} remaining", "cyan"))

            except asyncio.TimeoutError:
                print(colored(f"Crawl timed out after {timeout_seconds} seconds.", "red"))

            await browser.close()

    except Exception as e:
        logging.error(f"Crawl error: {e}")
        print(colored(f"Crawl error: {e}", "red"))

    if not websocket_urls:
        print(colored("No WebSocket endpoints found.", "yellow"))
    else:
        print(colored(f"Found {len(websocket_urls)} WebSocket endpoints:", "green"))
        for ws_url in websocket_urls:
            print(colored(f"- {ws_url}", "green"))

    return {
        "num_crawls": len(crawled_urls),
        "crawled_urls": list(crawled_urls),
        "num_websockets": len(websocket_urls),
        "websocket_urls": list(websocket_urls),
        "crawl_notes": "No WebSocket endpoints found." if not websocket_urls else ""
    }
