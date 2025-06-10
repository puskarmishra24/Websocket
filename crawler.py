from playwright.async_api import async_playwright
from termcolor import colored
import asyncio
import re
from urllib.parse import urljoin, urlparse

async def crawl_website(target_url: str):
    print(colored("Starting crawl with Playwright...", "blue"))
    crawled_urls = set()
    websocket_urls = set()
    to_crawl = {target_url}
    max_requests = 100
    max_depth = 5
    current_depth = 0

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 720},
            ignore_https_errors=True,
        )

        async def crawl_page(url, depth):
            nonlocal crawled_urls, websocket_urls, to_crawl
            if len(crawled_urls) >= max_requests or depth > max_depth:
                return

            if url in crawled_urls:
                return

            parsed_target = urlparse(target_url)
            parsed_url = urlparse(url)
            if parsed_url.netloc != parsed_target.netloc:
                return

            crawled_urls.add(url)
            print(colored(f"Crawling: {url}", "blue"))

            try:
                page = await context.new_page()
                page.on("websocket", lambda ws: websocket_urls.add(ws.url) if ws.url.startswith(('ws://', 'wss://')) else None)
                response = await page.goto(url, timeout=30000, wait_until="domcontentloaded")
                if not response or response.status >= 400:
                    print(colored(f"Failed to load {url}: Status {response.status if response else 'Unknown'}", "yellow"))
                    await page.close()
                    return

                await page.wait_for_timeout(2000)

                content = await page.content()
                ws_urls = re.findall(r'(wss?://[^\s"\']+)', content, re.IGNORECASE)
                websocket_urls.update(ws_urls)
                scripts = await page.query_selector_all('script')
                for script in scripts:
                    script_content = await script.inner_text()
                    script_urls = re.findall(r'(wss?://[^\s"\']+)', script_content, re.IGNORECASE)
                    websocket_urls.update(script_urls)

                links = await page.query_selector_all('a[href]')
                new_urls = set()
                for link in links:
                    href = await link.get_attribute('href')
                    if href:
                        absolute_url = urljoin(url, href)
                        if absolute_url.startswith(('http://', 'https://')) and absolute_url not in crawled_urls:
                            new_urls.add(absolute_url)

                await page.close()

                to_crawl.update(new_urls - crawled_urls)

            except Exception as e:
                print(colored(f"Error processing {url}: {e}", "yellow"))

        while to_crawl and len(crawled_urls) < max_requests and current_depth <= max_depth:
            current_batch = to_crawl.copy()
            to_crawl.clear()
            tasks = [crawl_page(url, current_depth) for url in current_batch]
            await asyncio.gather(*tasks)
            current_depth += 1

        await browser.close()

    if not crawled_urls:
        print(colored("No crawlable URLs found.", "red"))

    if not websocket_urls:
        print(colored("No WebSocket endpoints found.", "yellow"))
    else:
        print(colored(f"Found {len(websocket_urls)} WebSocket endpoints.", "green"))

    return {
        "num_crawls": len(crawled_urls),
        "crawled_urls": list(crawled_urls),
        "num_websockets": len(websocket_urls),
        "websocket_urls": list(websocket_urls)
    }