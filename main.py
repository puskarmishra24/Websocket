import csv
from datetime import datetime
import time
import asyncio
from termcolor import colored
import crawler
import attack
import report_generator
from urllib.parse import urlparse

async def main():
    print(colored("Initializing WebSocket vulnerability scanner for real-world web applications...", "blue"))

    # Choose input method
    input_method = input(colored("Choose input method (1: Manual, 2: CSV file): ", "cyan")).strip()
    target_urls = []
    cookies = []

    if input_method == "1":
        urls_input = input(colored("Enter the URLs you want to test (e.g., https://example.com), separated by commas: ", "cyan")).strip()
        if urls_input:
            target_urls = [url.strip() for url in urls_input.split(',')]
        # Ask for cookies (for authentication)
        cookie_input = input(colored("Do you want to provide cookies for authentication? (yes/no): ", "cyan")).strip().lower()
        if cookie_input == "yes":
            cookie_name = input(colored("Enter cookie name (e.g., session): ", "cyan")).strip()
            cookie_value = input(colored("Enter cookie value: ", "cyan")).strip()
            if target_urls:
                cookies = [{"name": cookie_name, "value": cookie_value, "url": target_urls[0], "domain": urlparse(target_urls[0]).netloc}]
    elif input_method == "2":
        csv_file = input(colored("Enter the path to your CSV file (must have a 'url' column): ", "cyan")).strip()
        try:
            with open(csv_file, newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                if 'url' not in reader.fieldnames:
                    print(colored("CSV file must contain a 'url' column.", "red"))
                    return
                target_urls = [row['url'].strip() for row in reader]
        except FileNotFoundError:
            print(colored(f"CSV file not found: {csv_file}", "red"))
            return
        except Exception as e:
            print(colored(f"Error reading CSV file: {e}", "red"))
            return
    else:
        print(colored("Invalid input method. Exiting.", "red"))
        return

    if not target_urls:
        print(colored("No URLs provided. Exiting.", "red"))
        return

    combined_results = {
        'scan_start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'total_scan_duration': 0,
        'urls_scanned': [],
        'total_vulnerabilities': {
            'High': 0,
            'Medium': 0,
            'Low': 0
        },
        'detailed_results': []
    }

    start_scan_time = time.time()

    for idx, target_url in enumerate(target_urls, 1):
        target_url = target_url.strip()
        if not target_url.startswith(('http://', 'https://')):
            print(colored(f"Invalid URL: {target_url}. Skipping. Please use http:// or https://", "red"))
            continue
        print(colored(f"\n[{idx}/{len(target_urls)}] Processing URL: {target_url}", "cyan"))
        start_time = time.time()

        # Crawl the website with cookies
        print(colored("Starting website crawl with Playwright...", "blue"))
        try:
            crawl_data = await crawler.crawl_website(target_url, cookies=cookies)
            print(colored(f"Crawling complete! {crawl_data['num_crawls']} URLs crawled, {crawl_data['num_websockets']} WebSocket endpoints found.", "green"))
        except Exception as e:
            print(colored(f"Error crawling {target_url}: {e}", "red"))
            crawl_data = {
                "num_crawls": 0,
                "crawled_urls": [],
                "num_websockets": 0,
                "websocket_urls": [],
                "crawl_notes": f"Error during crawl: {str(e)}"
            }

        # Allow manual input of WebSocket URLs if none were found
        websocket_urls = crawl_data['websocket_urls']
        if not websocket_urls:
            manual_ws = input(colored("No WebSocket endpoints found. Would you like to manually specify WebSocket URLs? (yes/no): ", "yellow")).strip().lower()
            if manual_ws == "yes":
                ws_input = input(colored("Enter WebSocket URLs (e.g., wss://example.com/ws), separated by commas: ", "cyan")).strip()
                if ws_input:
                    websocket_urls = [ws_url.strip() for ws_url in ws_input.split(',')]
                    crawl_data['websocket_urls'] = websocket_urls
                    crawl_data['num_websockets'] = len(websocket_urls)
                    crawl_data['crawl_notes'] = "WebSocket URLs manually specified by user."

        # Attack phase
        perform_attack = input(colored(f"Do you want to attack the site {target_url}? (yes/no): ", "cyan")).strip().lower()
        vulnerabilities = []
        attack_type = "WebSocket Tests"

        if perform_attack == "yes":
            if not websocket_urls:
                print(colored("No WebSocket endpoints to attack. Skipping attack phase.", "yellow"))
            else:
                print(colored(f"Starting WebSocket Tests (75+ vulnerabilities)...", "yellow"))
                try:
                    vulnerabilities = attack.attack_website(target_url, websocket_urls, attack_type="websocket")
                    print(colored(f"Attack complete! Found {len(vulnerabilities)} vulnerabilities.", "green"))
                except Exception as e:
                    print(colored(f"Error during attack on {target_url}: {e}", "red"))
                    vulnerabilities = []

        # Compile results for this URL
        url_result = {
            'url': target_url,
            'crawled_urls': crawl_data['crawled_urls'],
            'num_crawled_urls': crawl_data['num_crawls'],
            'websocket_urls': websocket_urls,
            'num_websockets': len(websocket_urls),
            'vulnerabilities': vulnerabilities,
            'crawl_notes': crawl_data['crawl_notes'],
            'scan_duration': time.time() - start_time
        }

        # Update vulnerability counts
        for vuln in vulnerabilities:
            risk = vuln.get('risk', 'Low')
            combined_results['total_vulnerabilities'][risk] = combined_results['total_vulnerabilities'].get(risk, 0) + 1

        combined_results['urls_scanned'].append(target_url)
        combined_results['detailed_results'].append(url_result)

    # Finalize combined results
    combined_results['total_scan_duration'] = time.time() - start_scan_time

    # Generate report
    print(colored("\nGenerating scan report...", "blue"))
    try:
        report_file = report_generator.generate_report(combined_results)
        print(colored(f"Scan report generated: {report_file}", "green"))
    except Exception as e:
        print(colored(f"Error generating report: {e}", "red"))

if __name__ == "__main__":
    asyncio.run(main())