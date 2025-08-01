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
import pickle

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

    combined_results = {
        'scan_start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'total_scan_duration': 0,
        'urls_scanned': [],
        'total_vulnerabilities': {'High': 0, 'Medium': 0, 'Low': 0, 'No':0},
        'detailed_results': {},
        'dict_total_errors':{
            "Handshake & Upgrade Validation":0,
            "Authentication & Session Control":0,
            "Subprotocols & Extension Handling":0,
            "Transport Security & Encryption":0,
            "Payload Framing & Messaging Semantics":0,
            "Origin Policy & Cross-Origin Enforcement":0,
            "Application-Layer Logic & Misconfigurations":0,
            "DoS, Compression & Resource Limits":0,
            "Protocol Fuzzing":0,
        }
    }

    if input_method == "1":
        urls_input = input(colored("Enter the URLs you want to test (e.g., https://example.com), separated by commas: ", "cyan")).strip()
        if urls_input:
            target_urls = [url.strip() for url in urls_input.split(',')]
        
    elif input_method == "2":
        #csv_file = r"C:\Users\puska\OneDrive\Documents\Github\Websocket\websites.csv"
        #csv_file = r"D:\GitHub\Websocket\websites.csv"
        csv_file = r"/home/ifscr/internship/Websocket/websites.csv"
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

    di = {}

    CONCURRENCY_LIMIT = 4
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    async def scan_target_url(target_url, idx, di, combined_results):
        async with semaphore:
            if not target_url.startswith(('http://', 'https://')):
                print(colored(f"[-] Invalid URL: {target_url}. Skipping.", "red"))
                return

            print(colored(f"\n[Scanning {idx}] {target_url}", "blue", attrs=['bold']))
            print(colored("-" * 60, "blue"))
            start_time = time.time()

            try:
                crawl_data = await crawler.crawl_website(target_url)
                if not isinstance(crawl_data, dict):
                    print(colored("Crawling failed to return expected data structure. Skipping this site.", "red"))
                    return

                print(colored(f"[+] Crawling complete: {crawl_data['num_crawls']} URLs, {crawl_data['num_websockets']} WebSocket endpoints", "green"))
                # print(colored("\nCrawled URLs:", "cyan"))
                # for i, url in enumerate(crawl_data['crawled_urls'], 1):
                #     print(colored(f"  {i}. {url}", "white"))

                print(colored("\nWebSocket Endpoints:", "blue", attrs=["bold"]))
                for i, ws_url in enumerate(crawl_data['websocket_urls'], 1):
                    print(colored(f"  {i}. {ws_url}", "white"))

                di[target_url] = crawl_data['websocket_urls']
                scan_duration = time.time() - start_time

                combined_results['detailed_results'][target_url] = {
                    'num_crawled_urls': crawl_data['num_crawls'],
                    'crawled_urls': crawl_data['crawled_urls'],
                    'num_websockets': len(crawl_data['websocket_urls']),
                    'websocket_urls': crawl_data['websocket_urls'],
                    'crawl_notes': crawl_data.get('crawl_notes', ''),
                    'scan_duration': scan_duration,
                }

            except Exception as e:
                print(colored(f"[-] Error crawling {target_url}: {e}", "red"))
                di[target_url] = []
                combined_results['detailed_results'][target_url] = {
                    'num_crawled_urls': 0,
                    'crawled_urls': [],
                    'num_websockets': 0,
                    'websocket_urls': [],
                    'crawl_notes': f"Error during crawl: {str(e)}",
                    'scan_duration': 0
                }

    tasks = [scan_target_url(url, idx, di, combined_results) for idx, url in enumerate(target_urls, 1)]
    await asyncio.gather(*tasks)
    print(colored("\n[Post-scan Check] Verifying WebSocket discovery status...", "yellow", attrs=['bold']))

    for url, data in combined_results["detailed_results"].items():
        if not data.get("websocket_urls"):
            print(colored(f"\n[!] No WebSocket endpoints found for {url}", "red"))

            websocket_urls = []

            if input_method == "1":
                manual_input = input(colored("    [?] Would you like to enter WebSocket URLs manually? (yes/no): ", "yellow")).strip().lower()
                if manual_input == "yes":
                    ws_input = input(colored("    Enter WebSocket URLs (comma-separated, e.g., wss://example.com/ws): ", "cyan")).strip()
                    if ws_input:
                        websocket_urls = [ws.strip() for ws in ws_input.split(",") if ws.strip()]
                    else:
                        print(colored("    [!] No URLs entered. Skipping.", "red"))

            elif input_method == "2":
                try:
                    index = target_urls.index(url)
                    fallback_ws = safety_sockets[index] if index < len(safety_sockets) else ""
                    if fallback_ws:
                        websocket_urls = [fallback_ws]
                        print(colored(f"    [+] Using fallback WebSocket from CSV: {fallback_ws}", "green"))
                    else:
                        print(colored("    [!] No fallback WebSocket found in CSV.", "red"))
                except Exception as e:
                    print(colored(f"    [!] Error accessing fallback WebSocket: {e}", "red"))

            # ✅ Update if any WebSockets were added
            if websocket_urls:
                di[url] = websocket_urls
                combined_results["detailed_results"][url]["websocket_urls"] = websocket_urls
                combined_results["detailed_results"][url]["crawl_notes"] += " WebSocket URLs added post-scan."
                print(colored(f"    [+] {len(websocket_urls)} WebSocket URL(s) added to {url}", "green"))
            else:
                print(colored("    [-] No WebSocket endpoints added.", "red"))


    # Attack phase
    #perform_attack = input(colored("\n[?] Perform WebSocket attack? (yes/no): ", "yellow")).strip().lower()
    perform_attack = 'yes'
    if perform_attack == "yes":
        print(colored("[*] Starting WebSocket attack...", "yellow"))
        try:
            for key, val in di.items():
                attack_time = time.time()
                ws_report, ds = attack.attack_website(key,val)
                scan_duration = time.time() - attack_time
                x = combined_results["detailed_results"][key]
                
                x['vulnerabilities'] = ws_report
                x['scan_duration'] += scan_duration
                x['dict_errors'] = ds

        except Exception as e:
            print(colored(f"[-] Error during attack: {e}", "red"))
        print(colored(f"[+] Attack complete for all websites.", "green"))
        
    combined_results['urls_scanned'].extend(target_urls)
    combined_results['total_scan_duration'] = time.time() - start_scan_time
    with open("report.dat","wb") as f:
        pickle.dump(combined_results,f)

    if perform_attack == 'yes':
        for x, y in combined_results["detailed_results"].items():
            z = y.get("vulnerabilities")
            if z is None:
                continue
            for n in y["vulnerabilities"].values():
                if n is None:
                    continue
                for o in n:
                    if isinstance(o, dict):
                        p = o.get("risk", "Low")
                        combined_results['total_vulnerabilities'][p] += 1
                    elif isinstance(o, list):
                        for item in o:
                            if isinstance(item, dict):
                                p = item.get("risk", "Low")
                                combined_results['total_vulnerabilities'][p] += 1
            for q, r in y["dict_errors"].items():
                combined_results["dict_total_errors"][q] += r
    with open("report.dat","wb") as f:
        pickle.dump(combined_results,f)

    # Print summary
    print(colored("\n=== Scan Summary ===", "green", attrs=['bold']))
    print_aligned("Scan Start Time:", combined_results['scan_start_time'])
    print_aligned("Total Scan Duration:", f"{combined_results['total_scan_duration']:.2f} seconds")
    print_aligned("Total URLs Scanned:", len(combined_results['urls_scanned']))
    print_aligned("High Severity:", combined_results['total_vulnerabilities']['High'])
    print_aligned("Medium Severity:", combined_results['total_vulnerabilities']['Medium'])
    print_aligned("Low Severity:", combined_results['total_vulnerabilities']['Low'])

    #Generate report
    print(colored("\n[*] Generating PDF report...", "yellow"))
    try:
        report_file = report_generator.generate_pdf_report(combined_results)
        print(colored(f"[+] Report saved: {report_file}", "green"))
    except Exception as e:
        print(colored(f"[-] Error generating report: {e}", "red"))
if __name__ == "__main__":
    asyncio.run(main())