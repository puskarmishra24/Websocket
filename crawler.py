from playwright.async_api import async_playwright
from termcolor import colored
import asyncio
import re
from urllib.parse import urljoin, urlparse
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

async def crawl_website(target_url: str, timeout_seconds: int = 300, cookies: list = None):
    """Crawl the website to find URLs and WebSocket endpoints with improved SPA handling."""
    print(colored(f"Starting crawl for {target_url} with Playwright...", "blue"))
    crawled_urls = set()
    websocket_urls = set()
    to_crawl = {target_url}  # URLs to be crawled
    max_requests = 100  # Match the report's crawl limit
    max_depth = 5
    current_depth = 0

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 720},
                ignore_https_errors=True,
            )

            # Add cookies for authentication if provided
            if cookies:
                await context.add_cookies(cookies)
                logging.info(f"Added {len(cookies)} cookies for authentication")

            async def crawl_page(url, depth):
                nonlocal crawled_urls, websocket_urls, to_crawl
                if len(crawled_urls) >= max_requests or depth > max_depth:
                    logging.info(f"Stopping crawl: Reached max requests ({max_requests}) or max depth ({max_depth})")
                    return

                if url in crawled_urls:
                    logging.info(f"Skipping already crawled URL: {url}")
                    return

                parsed_target = urlparse(target_url)
                parsed_url = urlparse(url)
                if parsed_url.netloc != parsed_target.netloc:
                    logging.info(f"Skipping URL from different domain: {url}")
                    return

                crawled_urls.add(url)
                print(colored(f"Crawling (Depth {depth}): {url}", "blue"))

                try:
                    page = await context.new_page()
                    # Log WebSocket connections
                    page.on("websocket", lambda ws: websocket_urls.add(ws.url) if ws.url.startswith(('ws://', 'wss://')) else None)
                    # Log console messages to debug JavaScript errors
                    page.on("console", lambda msg: logging.info(f"Console message in {url}: {msg.text}"))
                    # Log requests to detect failed requests (e.g., bot protection)
                    page.on("requestfailed", lambda req: logging.warning(f"Request failed in {url}: {req.url} - {req.failure}"))

                    response = await page.goto(url, timeout=30000, wait_until="networkidle")
                    if not response or response.status >= 400:
                        print(colored(f"Failed to load {url}: Status {response.status if response else 'Unknown'}", "yellow"))
                        await page.close()
                        return

                    # Wait longer for dynamic content (SPAs)
                    await page.wait_for_timeout(15000)  # Increased to 15 seconds
                    # Simulate user interactions to trigger dynamic content
                    await page.evaluate("window.scrollTo(0, document.body.scrollHeight);")
                    await page.wait_for_timeout(5000)  # Wait after scrolling
                    # Click interactive elements to trigger navigation and WebSocket connections
                    interactive_elements = await page.query_selector_all('button, a[href], input[type="submit"], div[role="button"]')
                    for element in interactive_elements[:10]:  # Increased to 10 interactions
                        try:
                            await element.click()
                            await page.wait_for_timeout(3000)  # Wait after each click
                        except Exception as e:
                            logging.info(f"Could not interact with element in {url}: {e}")

                    # Wait for dynamic navigation in SPAs
                    await page.wait_for_timeout(5000)  # Additional wait for SPA route changes
                    # Check for new URLs after interactions
                    new_urls = set()
                    links = await page.query_selector_all('a[href]')
                    for link in links:
                        try:
                            href = await link.get_attribute('href')
                            if href:
                                absolute_url = urljoin(url, href)
                                parsed_absolute = urlparse(absolute_url)
                                if (absolute_url.startswith(('http://', 'https://')) and
                                    parsed_absolute.netloc == parsed_target.netloc and
                                    absolute_url not in crawled_urls and
                                    absolute_url not in to_crawl):
                                    new_urls.add(absolute_url)
                                    logging.info(f"Added new URL to crawl: {absolute_url}")
                        except Exception as e:
                            logging.info(f"Error processing link in {url}: {e}")

                    # Extract dynamically loaded links from onclick events
                    elements_with_onclick = await page.query_selector_all('[onclick]')
                    for element in elements_with_onclick:
                        try:
                            onclick = await element.get_attribute('onclick')
                            if onclick and 'location' in onclick:
                                url_match = re.search(r'location\.href\s*=\s*[\'"]([^\'"]+)[\'"]', onclick)
                                if url_match:
                                    dynamic_url = urljoin(url, url_match.group(1))
                                    parsed_dynamic = urlparse(dynamic_url)
                                    if (dynamic_url.startswith(('http://', 'https://')) and
                                        parsed_dynamic.netloc == parsed_target.netloc and
                                        dynamic_url not in crawled_urls and
                                        dynamic_url not in to_crawl):
                                        new_urls.add(dynamic_url)
                                        logging.info(f"Added dynamic URL to crawl from onclick: {dynamic_url}")
                        except Exception as e:
                            logging.info(f"Error processing onclick in {url}: {e}")

                    # Extract WebSocket URLs from page content
                    content = await page.content()
                    ws_urls = re.findall(r'(wss?://[^\s"\']*)', content, re.IGNORECASE)
                    websocket_urls.update(ws_urls)
                    logging.info(f"Found {len(ws_urls)} WebSocket URLs in content of {url}")

                    # Extract WebSocket URLs from scripts
                    scripts = await page.query_selector_all('script')
                    for script in scripts:
                        try:
                            script_content = await script.inner_text()
                            script_urls = re.findall(r'(wss?://[^\s"\']*)', script_content, re.IGNORECASE)
                            websocket_urls.update(script_urls)
                            logging.info(f"Found {len(script_urls)} WebSocket URLs in scripts of {url}")
                            ws_dynamic = re.findall(r'new\s+WebSocket\s*\(\s*[\'"]?(wss?://[^\s"\']*)[\'"]?\s*\)', script_content, re.IGNORECASE)
                            websocket_urls.update(ws_dynamic)
                            logging.info(f"Found {len(ws_dynamic)} dynamic WebSocket URLs in {url}")
                            ws_constructed = re.findall(r'wss?://[^+\s"\']+\+[^+\s"\']+', script_content, re.IGNORECASE)
                            for constructed in ws_constructed:
                                try:
                                    eval_url = await page.evaluate(f'() => {{ return "{constructed}"; }}')
                                    if eval_url and (eval_url.startswith('ws://') or eval_url.startswith('wss://')):
                                        websocket_urls.add(eval_url)
                                        logging.info(f"Evaluated constructed WebSocket URL: {eval_url}")
                                except Exception as e:
                                    logging.info(f"Could not evaluate constructed URL in {url}: {e}")
                        except Exception as e:
                            logging.info(f"Error processing script in {url}: {e}")

                    # Handle SPA route changes by checking the current URL after interactions
                    current_url = page.url
                    if current_url != url and current_url not in crawled_urls and current_url not in to_crawl:
                        parsed_current = urlparse(current_url)
                        if parsed_current.netloc == parsed_target.netloc:
                            new_urls.add(current_url)
                            logging.info(f"Added SPA route URL to crawl: {current_url}")

                    await page.close()
                    to_crawl.update(new_urls)
                    logging.info(f"After crawling {url}, to_crawl now has {len(to_crawl)} URLs")

                except Exception as e:
                    logging.error(f"Error processing {url}: {e}")
                    print(colored(f"Error processing {url}: {e}", "yellow"))

            # Crawl all URLs in the to_crawl set
            try:
                while to_crawl and len(crawled_urls) < max_requests and current_depth <= max_depth:
                    current_batch = list(to_crawl)
                    to_crawl.clear()
                    tasks = [crawl_page(url, current_depth + 1) for url in current_batch if url not in crawled_urls]
                    await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=timeout_seconds)
                    current_depth += 1
                    logging.info(f"Completed crawl depth {current_depth}. Crawled: {len(crawled_urls)}, To crawl: {len(to_crawl)}")
                    print(colored(f"Depth {current_depth}: Crawled {len(crawled_urls)} URLs, {len(to_crawl)} URLs remaining to crawl", "cyan"))

            except asyncio.TimeoutError:
                print(colored(f"Crawl timed out after {timeout_seconds} seconds.", "red"))
                logging.error(f"Crawl timed out after {timeout_seconds} seconds.")

            await browser.close()

    except Exception as e:
        logging.error(f"Error during crawl: {e}")
        print(colored(f"Error during crawl: {e}", "red"))

    if not crawled_urls:
        print(colored("No crawlable URLs found.", "red"))
        logging.error("No crawlable URLs found.")

    if not websocket_urls:
        print(colored("No WebSocket endpoints found. This might be due to dynamic loading, authentication requirements, or bot protection.", "yellow"))
        logging.info("No WebSocket endpoints found. Check logs for JavaScript errors, dynamic loading, or authentication issues.")
    else:
        print(colored(f"Found {len(websocket_urls)} WebSocket endpoints:", "green"))
        for ws_url in websocket_urls:
            print(colored(f"- {ws_url}", "green"))

    return {
        "num_crawls": len(crawled_urls),
        "crawled_urls": list(crawled_urls),
        "num_websockets": len(websocket_urls),
        "websocket_urls": list(websocket_urls),
        "crawl_notes": "No WebSocket endpoints found. Possible reasons: dynamic loading, authentication required, or bot protection." if not websocket_urls else ""
    }