from datetime import datetime
import os

def generate_report(combined_results):
    """Generate a detailed scan report in a text file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"security_scan_report_{timestamp}.txt"
    report_dir = "scan_reports"
    
    # Create directory if it doesn't exist
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
    
    report_path = os.path.join(report_dir, report_filename)
    
    with open(report_path, "w") as f:
        # Header
        f.write("=" * 50 + "\n")
        f.write("WebSocket Security Scan Report\n")
        f.write("=" * 50 + "\n\n")
        
        # Scan Summary
        f.write("Scan Summary\n")
        f.write("-" * 50 + "\n")
        f.write(f"Scan Start Time: {combined_results['scan_start_time']}\n")
        f.write(f"Total Scan Duration: {int(combined_results['total_scan_duration'])} seconds\n")
        f.write(f"URLs Scanned: {len(combined_results['urls_scanned'])}\n")
        f.write("Total Vulnerabilities Found:\n")
        for risk, count in combined_results['total_vulnerabilities'].items():
            f.write(f"  {risk}: {count}\n")
        f.write("\n")
        
        # Detailed Results
        f.write("Detailed Results\n")
        f.write("-" * 50 + "\n")
        for result in combined_results['detailed_results']:
            f.write(f"\nURL: {result['url']}\n")
            f.write(f"Number of URLs Crawled: {result['num_crawled_urls']}\n")
            f.write(f"Crawled URLs:\n")
            for url in result['crawled_urls'][:10]:  # Limit to 10 for brevity
                f.write(f"  - {url}\n")
            if len(result['crawled_urls']) > 10:
                f.write(f"  ... and {len(result['crawled_urls']) - 10} more\n")
            f.write(f"Number of WebSocket Endpoints: {result['num_websockets']}\n")
            f.write("WebSocket Endpoints:\n")
            if result['websocket_urls']:
                for ws_url in result['websocket_urls']:
                    f.write(f"  - {ws_url}\n")
            else:
                f.write("  None\n")
            f.write("Vulnerabilities:\n")
            if result['vulnerabilities']:
                for vuln in result['vulnerabilities']:
                    f.write(f"  - Name: {vuln['name']}\n")
                    f.write(f"    Risk: {vuln['risk']}\n")
                    f.write(f"    Description: {vuln['description']}\n")
                    f.write(f"    Solution: {vuln['solution']}\n")
                    affected_key = 'affected_url' if 'affected_url' in vuln else 'affected_host'
                    f.write(f"    Affected: {vuln[affected_key]}\n")
                    f.write(f"    Impact: {vuln['impact']}\n")
                    f.write("\n")
            else:
                f.write("  None\n")
            if result['crawl_notes']:
                f.write(f"Notes: {result['crawl_notes']}\n")
            f.write(f"Scan Duration: {int(result['scan_duration'])} seconds\n")
            f.write("-" * 50 + "\n")
        
        # Footer
        f.write("\nEnd of Report\n")
        f.write("=" * 50 + "\n")
    
    return report_path