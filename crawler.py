import time
from termcolor import colored
from tqdm import tqdm
import requests
from urllib3.exceptions import InsecureRequestWarning
import urllib3

urllib3.disable_warnings(InsecureRequestWarning)

def crawl_website(zap, target_url):
    print(colored("Starting crawl...", "blue"))
    zap.spider.set_option_max_depth(5)
    zap.spider.set_option_parse_comments(True)
    zap.spider.set_option_process_form(True)
    zap.spider.scan(target_url)
    print("Crawling in progress...")
    while int(zap.spider.status()) < 100:
        time.sleep(1)

    crawled_urls = zap.spider.results()
    websocket_urls = []

    for attempt in range(3):
        try:
            response = requests.get(target_url, verify=False, timeout=20)
            content = response.text.lower()
            if 'ws://' in content or 'wss://' in content:
                if 'ws://localhost:8081' in content:
                    websocket_urls.append('ws://localhost:8081')
            break
        except Exception as e:
            print(colored(f"Attempt {attempt + 1} failed: {e}", "yellow"))
            time.sleep(3)
            if attempt == 2:
                print(colored(f"Could not fetch page: {e}", "red"))

    if not crawled_urls:
        print(colored("No crawlable links found.", "red"))

    if not websocket_urls:
        print(colored("No WebSocket endpoints found.", "yellow"))
    else:
        print(colored(f"Found {len(websocket_urls)} WebSocket endpoints.", "green"))

    return {
        "num_crawls": len(crawled_urls),
        "crawled_urls": crawled_urls,
        "num_websockets": len(websocket_urls),
        "websocket_urls": websocket_urls
    }