import pickle
from termcolor import colored
import report_generator

with open('report.dat','rb') as f:
    s = pickle.load(f)
    print(s)
    
print(colored("\n[*] Generating PDF report...", "yellow"))
try:
    report_file = report_generator.generate_pdf_report(s)
    print(colored(f"[+] Report saved: {report_file}", "green"))
except Exception as e:
    print(colored(f"[-] Error generating report: {e}", "red"))