import pickle
from termcolor import colored
import report_generator
import json
from pprint import pprint

with open('report1.dat','rb') as f:
    s = pickle.load(f)

def flatten_vulns(vuln_list):
    flat = []
    for item in vuln_list:
        if isinstance(item, list):
            flat.extend(flatten_vulns(item))  # recurse
        else:
            flat.append(item)
    return flat

# ATTACK_LIST = [
#     "Weak TLS Ciphers", "TLS Downgrade","Certificate Mismatch","Mixed Content"
# ]

# def pretty_print_combined_results(combined_results):
#     print("\n=== Combined Results Summary ===")
#     print(f"Scan Started: {combined_results.get('scan_start_time', 'N/A')}")
#     print(f"Total Scan Duration: {round(combined_results.get('total_scan_duration', 0), 2)} seconds")

#     print("\nURLs Scanned:")
#     for url_group in combined_results.get("urls_scanned", []):
#         print(f"  - {url_group}")

#     print("\nTotal Vulnerabilities:")
#     for level, count in combined_results.get("total_vulnerabilities", {}).items():
#         print(f"  {level}: {count}")

#     print("\nTotal Error Counts:")
#     for err_type, count in combined_results.get("dict_total_errors", {}).items():
#         print(f"  {err_type}: {count}")

#     print("\n=== Per-URL Details ===")
#     for url, details in combined_results.get("detailed_results", {}).items():
#         print(f"\n--- {url} ---")
#         # print(f"  Crawled URLs: {details.get('num_crawled_urls', 0)}")
#         # print(f"  WebSocket Endpoints: {details.get('num_websockets', 0)}")
#         # print(f"  Scan Duration: {round(details.get('scan_duration', 0), 2)}s")
#         # print(f"  Crawl Notes: {details.get('crawl_notes', '')}")
#         #print("websockets:",details.get('websocket_urls'))
#         for y in details['vulnerabilities'].values():
#             flag1 = False
#             flag2 = False
#             flag3 = False
#             flag4 = False
#             for z in  y:
#                 if z.get('name') == "Weak TLS Ciphers":
#                     flag1 = True
#                 if z.get('name') == "TLS Downgrade":
#                     flag2 = True
#                 if z.get('name') == "Certificate Mismatch":
#                     flag3 = True
#                 if z.get('name') == "Mixed Content":
#                     flag4 = True
#             if not flag1:
#                 y.append({"name":"Weak TLS Ciphers",'risk':'No'})
#                 print("Made changes")
#             if not flag2:
#                 y.append({"name":"TLS Downgrade",'risk':'No'})
#             if not flag3:
#                 y.append({"name":"Certificate Mismatch",'risk':'No'})
#             if not flag4:
#                 y.append({"name":"Mixed Content",'risk':'No'})
#     return combined_results
# comb = pretty_print_combined_results(s)
# with open('report1.dat','wb') as f:
#     pickle.dump(comb, f)
print(colored("\n[*] Generating PDF report...", "yellow"))
try:
    report_file = report_generator.generate_pdf_report(s)
    print(colored(f"[+] Report saved: {report_file}", "green"))
except Exception as e:
    print(colored(f"[-] Error generating report: {e}", "red"))