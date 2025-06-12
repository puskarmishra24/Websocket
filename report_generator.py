from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.barcharts import VerticalBarChart
from datetime import datetime
from termcolor import colored
from textwrap import wrap
import os
import math

def create_wrapped_cell(text, width=60):
    """Helper function to wrap text in table cells"""
    if text is None:
        text = ""
    if not isinstance(text, str):
        text = str(text)
    wrapped_text = "\n".join(wrap(text, width))
    return Paragraph(wrapped_text, ParagraphStyle('Normal'))

def create_bar_chart(data, width=400, height=200, title="", categories=None, colors_list=None):
    """Create a vertical bar chart for vulnerability counts"""
    drawing = Drawing(width, height)
    bc = VerticalBarChart()
    bc.x = 50
    bc.y = 30
    bc.height = height - 80
    bc.width = width - 100
    bc.data = [data]
    bc.strokeColor = colors.black
    max_value = max(max(data, default=0), 5)
    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueMax = max_value + (max_value // 5) + 1
    bc.valueAxis.valueStep = max(1, (max_value // 5))
    bc.categoryAxis.labels.boxAnchor = 'ne'
    bc.categoryAxis.labels.dx = 8
    bc.categoryAxis.labels.dy = -2
    bc.categoryAxis.labels.angle = 30
    bc.categoryAxis.labels.fontSize = 8
    bc.categoryAxis.categoryNames = categories if categories else ['High', 'Medium', 'Low']
    if colors_list:
        for idx, color in enumerate(colors_list):
            bc.bars[idx].fillColor = color
    else:
        bc.bars[0].fillColor = colors.red
        bc.bars[1].fillColor = colors.yellow
        bc.bars[2].fillColor = colors.green
    drawing.add(bc)
    drawing.add(Rect(0, 0, width, height, strokeColor=colors.black, fillColor=None))
    if title:
        drawing.add(String(width/2, height-20, title, fontName='Helvetica', fontSize=12, textAnchor='middle'))
    return drawing

def generate_pdf_report(combined_results):
    """Generates a combined PDF report with charts for multiple URLs"""
    try:
        report_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"security_scan_report_{report_time}.pdf"
        
        doc = SimpleDocTemplate(
            report_filename,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        styles = getSampleStyleSheet()
        title_style = styles['Heading1']
        heading2_style = styles['Heading2']
        
        vuln_style = ParagraphStyle(
            'VulnerabilityStyle',
            parent=styles['Normal'],
            spaceAfter=10,
            leftIndent=20
        )
        
        elements = []
        
        # Title and Executive Summary
        elements.append(Paragraph("WebSocket Security Scan Report", title_style))
        elements.append(Spacer(1, 30))
        
        elements.append(Paragraph("Executive Summary", heading2_style))
        elements.append(Spacer(1, 15))
        
        summary_data = [
            ["Scan Start Time:", combined_results.get('scan_start_time', 'N/A')],
            ["Scan End Time:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Total Scan Duration:", f"{round(combined_results.get('total_scan_duration', 0), 2)} seconds"],
            ["Total URLs Scanned:", str(len(combined_results.get('urls_scanned', [])))],
            ["High Severity Vulnerabilities:", str(combined_results.get('total_vulnerabilities', {}).get('High', 0))],
            ["Medium Severity Vulnerabilities:", str(combined_results.get('total_vulnerabilities', {}).get('Medium', 0))],
            ["Low Severity Vulnerabilities:", str(combined_results.get('total_vulnerabilities', {}).get('Low', 0))]
        ]
        
        wrapped_summary_data = [[create_wrapped_cell(cell) for cell in row] for row in summary_data]
        summary_table = Table(wrapped_summary_data, colWidths=[2*inch, 4*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(summary_table)
        elements.append(Spacer(1, 30))
        
        # Vulnerability Distribution Chart
        vuln_counts = [
            combined_results.get('total_vulnerabilities', {}).get('High', 0),
            combined_results.get('total_vulnerabilities', {}).get('Medium', 0),
            combined_results.get('total_vulnerabilities', {}).get('Low', 0)
        ]
        elements.append(create_bar_chart(vuln_counts, title="Vulnerability Distribution by Severity"))
        elements.append(Spacer(1, 30))
        
        elements.append(Paragraph("Detailed Scan Results", heading2_style))
        elements.append(Spacer(1, 20))
        
        for url_result in combined_results.get('detailed_results', []):
            elements.append(Paragraph(f"Target URL: {url_result.get('url', 'N/A')}", heading2_style))
            elements.append(Spacer(1, 15))
            
            # URL Details Table
            url_details = [
                ["Scan Duration:", f"{round(url_result.get('scan_duration', 0), 2)} seconds"],
                ["URLs Crawled:", str(url_result.get('num_crawled_urls', 0))],
                ["WebSocket Endpoints Found:", str(url_result.get('num_websockets', 0))],
                ["Attack Performed:", "True" if url_result.get('vulnerabilities', []) else "False"],
                ["Attack Type:", "WebSocket Tests" if url_result.get('vulnerabilities', []) else "None"],
                ["High Severity Findings:", str(sum(1 for v in url_result.get('vulnerabilities', []) if v.get('risk') == 'High'))],
                ["Medium Severity Findings:", str(sum(1 for v in url_result.get('vulnerabilities', []) if v.get('risk') == 'Medium'))],
                ["Low Severity Findings:", str(sum(1 for v in url_result.get('vulnerabilities', []) if v.get('risk') == 'Low'))]
            ]
            
            wrapped_url_details = [[create_wrapped_cell(cell) for cell in row] for row in url_details]
            url_table = Table(wrapped_url_details, colWidths=[2*inch, 4*inch])
            url_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('TOPPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            elements.append(url_table)
            elements.append(Spacer(1, 30))
            
            # WebSocket Endpoints
            elements.append(Paragraph("WebSocket Endpoints:", heading2_style))
            elements.append(Spacer(1, 15))
            
            ws_data = [["#", "URL"]]
            ws_urls = url_result.get('websocket_urls', [])
            if ws_urls:
                for idx, ws_url in enumerate(ws_urls, 1):
                    ws_data.append([str(idx), ws_url])
            else:
                ws_data.append(["", "No WebSocket endpoints found."])
            
            wrapped_ws_data = [[create_wrapped_cell(cell, width=40) for cell in row] for row in ws_data]
            ws_table = Table(wrapped_ws_data, colWidths=[0.5*inch, 5.5*inch])
            ws_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('TOPPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            elements.append(ws_table)
            elements.append(Spacer(1, 30))
            
            # Crawled URLs
            elements.append(Paragraph("Crawled URLs:", heading2_style))
            elements.append(Spacer(1, 15))
            
            crawled_urls_data = [["#", "URL"]]
            for idx, crawled_url in enumerate(url_result.get('crawled_urls', []), 1):
                crawled_urls_data.append([str(idx), crawled_url])
            
            wrapped_crawled_data = [[create_wrapped_cell(cell, width=40) for cell in row] for row in crawled_urls_data]
            crawled_table = Table(wrapped_crawled_data, colWidths=[0.5*inch, 5.5*inch])
            crawled_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('TOPPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            elements.append(crawled_table)
            elements.append(Spacer(1, 30))
            
            # Vulnerabilities Chart for this URL
            url_vuln_counts = [
                sum(1 for v in url_result.get('vulnerabilities', []) if v.get('risk') == 'High'),
                sum(1 for v in url_result.get('vulnerabilities', []) if v.get('risk') == 'Medium'),
                sum(1 for v in url_result.get('vulnerabilities', []) if v.get('risk') == 'Low')
            ]
            elements.append(create_bar_chart(url_vuln_counts, title=f"Vulnerability Distribution for {url_result.get('url', 'N/A')}"))
            elements.append(Spacer(1, 30))
            
            # Detailed Vulnerabilities List
            if url_result.get('vulnerabilities', []):
                elements.append(Paragraph("Detected Vulnerabilities:", heading2_style))
                elements.append(Spacer(1, 15))
                
                for vuln in url_result['vulnerabilities']:
                    # Set background color based on risk level
                    if vuln.get('risk') == 'High':
                        bg_color = colors.mistyrose
                    elif vuln.get('risk') == 'Medium':
                        bg_color = colors.lightgoldenrodyellow
                    else:
                        bg_color = colors.lightgreen
                    
                    vuln_data = [
                        ["Name:", vuln.get('name', 'Unknown')],
                        ["Risk Level:", vuln.get('risk', 'Unknown')],
                        ["Description:", vuln.get('description', '')],
                        ["Solution:", vuln.get('solution', '')],
                        ["Affected URL:", vuln.get('affected_url', vuln.get('affected_host', 'N/A'))]
                    ]
                    
                    wrapped_vuln_data = [[create_wrapped_cell(cell, width=50) for cell in row] for row in vuln_data]
                    vuln_table = Table(wrapped_vuln_data, colWidths=[1.5*inch, 4.5*inch])
                    vuln_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                        ('TOPPADDING', (0, 0), (-1, -1), 12),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('BACKGROUND', (0, 1), (1, 1), bg_color)
                    ]))
                    
                    elements.append(vuln_table)
                    elements.append(Spacer(1, 15))
            
            elements.append(PageBreak())
        
        # Vulnerability Summary by Type
        elements.append(Paragraph("Vulnerability Summary by Type", heading2_style))
        elements.append(Spacer(1, 15))
        
        vuln_types = {
            'Origin Check': 0,
            'Authentication': 0,
            'Fuzzing': 0,
            'Handshake': 0,
            'Payload Handling': 0,
            'Session Management': 0,
            'Subprotocol': 0,
            'Security': 0,
            'DoS': 0,
            'Cross-Origin': 0,
            'Other': 0
        }
        
        for url_result in combined_results.get('detailed_results', []):
            for vuln in url_result.get('vulnerabilities', []):
                name = vuln.get('name', '').lower()
                if 'origin check' in name:
                    vuln_types['Origin Check'] += 1
                elif 'authentication' in name:
                    vuln_types['Authentication'] += 1
                elif 'fuzzing' in name:
                    vuln_types['Fuzzing'] += 1
                elif any(x in name for x in ['sec-websocket', 'upgrade', 'connection', 'host', 'http', 'path']):
                    vuln_types['Handshake'] += 1
                elif any(x in name for x in ['opcode', 'payload', 'fragment', 'masking', 'rsv', 'utf-8', 'close']):
                    vuln_types['Payload Handling'] += 1
                elif any(x in name for x in ['cookie', 'token', 'session']):
                    vuln_types['Session Management'] += 1
                elif any(x in name for x in ['subprotocol', 'extension']):
                    vuln_types['Subprotocol'] += 1
                elif any(x in name for x in ['tls', 'certificate', 'cipher']):
                    vuln_types['Security'] += 1
                elif any(x in name for x in ['flood', 'oversized', 'timeout', 'compression', 'leak']):
                    vuln_types['DoS'] += 1
                elif any(x in name for x in ['cors', 'iframe', 'mixed', 'postmessage', 'spoofed']):
                    vuln_types['Cross-Origin'] += 1
                else:
                    vuln_types['Other'] += 1
        
        type_data = [[k, str(v)] for k, v in vuln_types.items()]
        type_table = Table([["Type", "Count"]] + type_data, colWidths=[3*inch, 3*inch])
        type_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(type_table)
        elements.append(Spacer(1, 30))
        
        # Vulnerability Type Distribution Chart
        type_counts = [v for v in vuln_types.values()]
        type_categories = list(vuln_types.keys())
        elements.append(create_bar_chart(
            type_counts,
            title="Vulnerability Distribution by Type",
            categories=type_categories,
            colors_list=[colors.blue] * len(type_categories),
            height=250
        ))
        elements.append(Spacer(1, 30))
        
        # Build the PDF
        doc.build(elements)
        absolute_path = os.path.abspath(report_filename)
        print(colored(f"\n[+] Combined PDF report generated: {absolute_path}", "green"))
        return absolute_path
    
    except Exception as e:
        print(colored(f"[-] Error generating PDF report: {str(e)}", "red"))
        raise