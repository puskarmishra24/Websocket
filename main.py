import warnings
warnings.filterwarnings("ignore", category=UserWarning)
import asyncio
from datetime import datetime
import time
from termcolor import colored
import crawler
import attack
import report_generator
import csv

def print_aligned(label, value, label_width=25):
    """Print a label and value with aligned formatting."""
    print(colored(f"{label:<{label_width}}", "cyan") + colored(f"{value}", "white"))

async def main():
    print(colored("\n=== WebSocket Vulnerability Scanner ===", "blue", attrs=['bold']))
    print(colored("Starting scan on " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "blue"))
    print(colored("=" * 40 + "\n", "blue"))

    start_scan_time = time.time()

    #Choose input method
    input_method = input(colored("Choose input method (1: Manual, 2: CSV file): ", "cyan")).strip()
    target_urls = []
    safety_sockets = []

    if input_method == "1":
        urls_input = input(colored("Enter the URLs you want to test (e.g., https://example.com), separated by commas: ", "cyan")).strip()
        if urls_input:
            target_urls = [url.strip() for url in urls_input.split(',')]
        
    elif input_method == "2":
        csv_file = r"C:\Users\puska\OneDrive\Documents\Github\Websocket\websites.csv"
        # csv_file = r"D:\GitHub\Websocket\websites.csv"
        try:
            with open(csv_file, newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                d1 = [row for row in reader]
                target_urls = [row['Website_URL'].strip() for row in d1]
                safety_sockets = [row['WebSocket_URL'].strip() for row in d1]
            
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
        'total_vulnerabilities': {'High': 0, 'Medium': 0, 'Low': 0},
        'detailed_results': []
    }
    all_ws = []
    di = {}
    for idx, target_url in enumerate(target_urls,1):
        if not target_url.startswith(('http://', 'https://')):
            print(colored(f"[-] Invalid URL: {target_url}. Skipping.", "red"))
            continue

        print(colored(f"\n[Scanning {idx}/{len(target_urls)}] {target_url}", "blue", attrs=['bold']))
        print(colored("-" * 60, "blue"))
        start_time = time.time()

        # Crawl the website
        print(colored("[*] Crawling website...", "yellow"))
        try:
            crawl_data = await crawler.crawl_website(target_url)
            if not isinstance(crawl_data, dict):
                print(colored("Crawling failed to return expected data structure. Skipping this site.", "red"))
                continue

            print(colored(f"[+] Crawling complete: {crawl_data['num_crawls']} URLs, {crawl_data['num_websockets']} WebSocket endpoints", "green"))
            print(colored("\nCrawled URLs:", "cyan"))
            for i, url in enumerate(crawl_data['crawled_urls'], 1):
                print(colored(f"  {i}. {url}", "white"))

            print(colored("\nWebSocket Endpoints:", "blue", attrs=["bold"]))
            if crawl_data['websocket_urls']:
                for i, ws_url in enumerate(crawl_data['websocket_urls'], 1):
                    print(colored(f"  {i}. {ws_url}", "white"))
                di[target_url] = crawl_data["websocket_urls"]
                all_ws.extend(crawl_data["websocket_urls"])

            else:
                if input_method == "2":
                    try:
                        index = target_urls.index(target_url)
                        x = safety_sockets[index] if index < len(safety_sockets) else ""
                        if x:
                            print(colored("  None found from crawling. Using fallback WebSocket from CSV: ", "yellow") + x)
                            crawl_data['websocket_urls'].append(x)
                            di[target_url] = crawl_data["websocket_urls"]
                        else:
                            print(colored("  None found and no fallback WebSocket in CSV.", "red"))
                    except Exception as e:
                        print(colored(f"  Error accessing fallback WebSocket: {e}", "red"))
                else:
                    print(colored("  None found.", "yellow"))


        except Exception as e:
            print(colored(f"[-] Error crawling {target_url}: {e}", "red"))
            crawl_data = {
                "num_crawls": 0,
                "crawled_urls": [],
                "num_websockets": 0,
                "websocket_urls": [],
                "crawl_notes": f"Error during crawl: {str(e)}"
            }

    #Manual WebSocket input
    websocket_urls = crawl_data['websocket_urls']
    if not websocket_urls and input_method == '1':
        manual_ws = input(colored("\n[?] No WebSocket endpoints found. Manually specify URLs? (yes/no): ", "yellow")).strip().lower()
        if manual_ws == "yes":
            for i in range(len(target_urls)):
                ws_input = input(colored(f"Enter WebSocket URLs for {i} (comma-separated, e.g., wss://example.com/ws): ", "cyan")).strip()
                if ws_input:
                    websocket_urls = [ws_url.strip() for ws_url in ws_input.split(',')]
                    crawl_data['websocket_urls'] = websocket_urls
                    crawl_data['num_websockets'] = len(websocket_urls)
                    crawl_data['crawl_notes'] = "WebSocket URLs manually specified"
                    print(colored("\nManually Specified WebSocket URLs:", "cyan"))
                    all_ws.extend(websocket_urls)
                    di[i] = websocket_urls
                

                for i, ws_url in enumerate(websocket_urls, 1):
                    print(colored(f"  {i}. {ws_url}", "white"))
    # Attack phase
    perform_attack = input(colored("\n[?] Perform WebSocket attack? (yes/no): ", "yellow")).strip().lower()
    vulnerabilities = []
    if perform_attack == "yes":
        if not all_ws:
            print(colored("[-] No WebSocket endpoints to attack.", "red"))
        else:
            print(colored("[*] Starting WebSocket attack...", "yellow"))
            try:
                for key, val in di.items():
                    valid_ws = [ws for ws in val if attack.test_working_websocket(ws)]
                    if valid_ws:
                        vulnerabilities, ds = attack.attack_website(valid_ws)
                    else:
                        print(colored("All WebSocket URLs failed the test. Skipping the website: " + key, "red"))

                print(colored(f"[+] Attack complete: {len(vulnerabilities)} vulnerabilities found", "green"))

            except Exception as e:
                print(colored(f"[-] Error during attack: {e}", "red"))

        # Compile results
        scan_duration = time.time() - start_time
        url_result = {
            'url': target_url,
            'num_crawled_urls': crawl_data['num_crawls'],
            'crawled_urls': crawl_data['crawled_urls'],
            'num_websockets': crawl_data['num_websockets'],
            'websocket_urls': websocket_urls,
            'vulnerabilities': vulnerabilities,
            'crawl_notes': crawl_data.get('crawl_notes', ''),
            'scan_duration': scan_duration
        }

        # Update vulnerability counts
        for vuln in vulnerabilities:
            risk = vuln.get('risk', 'Low')
            combined_results['total_vulnerabilities'][risk] += 1

        combined_results['urls_scanned'].append(target_url)
        combined_results['detailed_results'].append(url_result)

    combined_results['total_scan_duration'] = time.time() - start_scan_time

    # Print summary
    print(colored("\n=== Scan Summary ===", "green", attrs=['bold']))
    print_aligned("Scan Start Time:", combined_results['scan_start_time'])
    print_aligned("Total Scan Duration:", f"{combined_results['total_scan_duration']:.2f} seconds")
    print_aligned("Total URLs Scanned:", len(combined_results['urls_scanned']))
    print_aligned("High Severity:", combined_results['total_vulnerabilities']['High'])
    print_aligned("Medium Severity:", combined_results['total_vulnerabilities']['Medium'])
    print_aligned("Low Severity:", combined_results['total_vulnerabilities']['Low'])

    # Generate report
    print(colored("\n[*] Generating PDF report...", "yellow"))
    try:
        report_file = report_generator.generate_pdf_report(combined_results)
        print(colored(f"[+] Report saved: {report_file}", "green"))
    except Exception as e:
        print(colored(f"[-] Error generating report: {e}", "red"))

if __name__ == "__main__":
    asyncio.run(main())