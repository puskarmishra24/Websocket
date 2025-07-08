import pickle
from termcolor import colored
import report_generator
import json
from pprint import pprint

with open('report.dat','rb') as f:
    s = pickle.load(f)

def flatten_vulns(vuln_list):
    flat = []
    for item in vuln_list:
        if isinstance(item, list):
            flat.extend(flatten_vulns(item))  # recurse
        else:
            flat.append(item)
    return flat


def pretty_print_combined_results(combined_results):
    print("\n=== Combined Results Summary ===")
    print(f"Scan Started: {combined_results.get('scan_start_time', 'N/A')}")
    print(f"Total Scan Duration: {round(combined_results.get('total_scan_duration', 0), 2)} seconds")

    print("\nURLs Scanned:")
    for url_group in combined_results.get("urls_scanned", []):
        print(f"  - {url_group}")

    print("\nTotal Vulnerabilities:")
    for level, count in combined_results.get("total_vulnerabilities", {}).items():
        print(f"  {level}: {count}")

    print("\nTotal Error Counts:")
    for err_type, count in combined_results.get("dict_total_errors", {}).items():
        print(f"  {err_type}: {count}")

    print("\n=== Per-URL Details ===")
    for url, details in combined_results.get("detailed_results", {}).items():
        print(f"\n--- {url} ---")
        print(f"  Crawled URLs: {details.get('num_crawled_urls', 0)}")
        print(f"  WebSocket Endpoints: {details.get('num_websockets', 0)}")
        print(f"  Scan Duration: {round(details.get('scan_duration', 0), 2)}s")
        print(f"  Crawl Notes: {details.get('crawl_notes', '')}")

        # print("\n  Crawled URLs:")
        # for i, crawled in enumerate(details.get("crawled_urls", []), 1):
        #     print(f"    {i}. {crawled}")

        print("\n  WebSocket Vulnerabilities:")
        for ws, vulns in details.get("vulnerabilities", {}).items():
            print(f"    WebSocket: {ws}")
            flat_vulns = flatten_vulns(vulns)
            for idx, v in enumerate(flat_vulns, 1):
                print(f"      {idx}. [{v.get('risk')}] {v.get('name')}")
                print(f"         → Affected: {v.get('affected_url', v.get('affected_host', 'N/A'))}")
                print(f"         → Desc: {v.get('description', '')}")
                print(f"         → Solution: {v.get('solution', '')}")

        print("\n  Error Breakdown:")
        for err_type, count in details.get("dict_errors", {}).items():
            print(f"    {err_type}: {count}")
pretty_print_combined_results(s)
print(colored("\n[*] Generating PDF report...", "yellow"))
try:
    report_file = report_generator.generate_pdf_report(s)
    print(colored(f"[+] Report saved: {report_file}", "green"))
except Exception as e:
    print(colored(f"[-] Error generating report: {e}", "red"))