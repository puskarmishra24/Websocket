from datetime import datetime
import time
import asyncio
from termcolor import colored
import crawler
import attack
import report_generator

async def main():
    print(colored("Initializing WebSocket vulnerability scanner for real-world web applications...", "blue"))
    target_urls = input("Enter the URLs you want to test (e.g., https://example.com), separated by commas: ").strip().split(',')

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

    for target_url in target_urls:
        target_url = target_url.strip()
        if not target_url.startswith(('http://', 'https://')):
            print(colored(f"Invalid URL: {target_url}. Skipping. Please use http:// or https://", "red"))
            continue
        print(colored(f"\nProcessing URL: {target_url}", "cyan"))
        start_time = time.time()
        print(colored("Starting website crawl with Playwright...", "blue"))
        crawl_data = await crawler.crawl_website(target_url)
        print(colored(f"Crawling complete! {crawl_data['num_crawls']} URLs crawled, {crawl_data['num_websockets']} WebSocket endpoints found.", "green"))
        perform_attack = input(f"Do you want to attack the site {target_url}? (yes/no): ").strip().lower()
        vulnerabilities = []
        attack_type = ""

        if perform_attack == "yes":
            attack_mode = input("1. WebSocket Tests: ").strip()
            attack_types = {
                "1": ("WebSocket Tests", "websocket"),
            }

            if attack_mode in attack_types:
                attack_type, attack_code = attack_types[attack_mode]
                print(colored(f"Starting {attack_type}...", "yellow"))
                vulnerabilities = attack.attack_website(target_url, crawl_data['websocket_urls'], attack_type=attack_code)

        end_time = time.time()
        scan_duration = round(end_time - start_time, 2)

        vuln_counts = {
            'High': len([v for v in vulnerabilities if v['risk'] == "High"]),
            'Medium': len([v for v in vulnerabilities if v['risk'] == "Medium"]),
            'Low': len([v for v in vulnerabilities if v['risk'] == "Low"])
        }

        combined_results['total_scan_duration'] += scan_duration
        combined_results['urls_scanned'].append(target_url)
        for severity in ['High', 'Medium', 'Low']:
            combined_results['total_vulnerabilities'][severity] += vuln_counts[severity]

        url_result = {
            'url': target_url,
            'scan_duration': scan_duration,
            'crawl_data': crawl_data,
            'attack_performed': perform_attack == "yes",
            'attack_type': attack_type if perform_attack == "yes" else "None",
            'vulnerabilities': vulnerabilities,
            'vulnerability_counts': vuln_counts
        }
        combined_results['detailed_results'].append(url_result)

        print(colored(f"\nResults for {target_url}:", "yellow"))
        print(f"- High Severity: {vuln_counts['High']}")
        print(f"- Medium Severity: {vuln_counts['Medium']}")
        print(f"- Low Severity: {vuln_counts['Low']}")

    print(colored("\nGenerating combined report...", "yellow"))
    combined_results['scan_end_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report_generator.generate_combined_report(combined_results)
    print(colored("\nFinal Summary:", "green"))
    print(f"Total URLs scanned: {len(combined_results['urls_scanned'])}")
    print(f"Total scan duration: {round(combined_results['total_scan_duration'], 2)} seconds")
    print("Total vulnerabilities found:")
    print(f"- High Severity: {combined_results['total_vulnerabilities']['High']}")
    print(f"- Medium Severity: {combined_results['total_vulnerabilities']['Medium']}")
    print(f"- Low Severity: {combined_results['total_vulnerabilities']['Low']}")

if __name__ == "__main__":
    asyncio.run(main())