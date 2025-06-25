from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import black, orange
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.platypus import Image, Table, TableStyle
from reportlab.graphics.charts.barcharts import VerticalBarChart
from datetime import datetime
from textwrap import wrap
import os

def create_wrapped_cell(text, width=60):
    """Helper function to wrap text in table cells"""
    if text is None:
        text = ""
    if not isinstance(text, str):
        text = str(text)
    wrapped_text = "\n".join(wrap(text, width))
    return Paragraph(wrapped_text, ParagraphStyle('Normal'))

def create_bar_chart(data, width=380, height=200, title="", categories=None, colors_list=None):
    """
    Create a visually responsive vertical bar chart with centered title,
    equal left/right padding, and content fitting inside.
    """
    left_padding = 60
    right_padding = 60
    top_padding = 30
    bottom_padding = 40

    chart_width = width
    chart_height = height

    total_width = left_padding + chart_width + right_padding
    total_height = bottom_padding + chart_height + top_padding

    drawing = Drawing(total_width, total_height)

    # Draw outer border
    drawing.add(Rect(0, 0, total_width, total_height, strokeColor=colors.black, fillColor=None))

    # Create bar chart
    bc = VerticalBarChart()
    bc.x = left_padding
    bc.y = bottom_padding
    bc.width = chart_width
    bc.height = chart_height

    bc.data = [data]
    bc.strokeColor = colors.black

    # Set axis value range and steps
    max_val = max(max(data, default=0), 5)
    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueMax = max_val + (max_val // 5) + 1
    bc.valueAxis.valueStep = max(1, (max_val // 5))

    # Category labels
    bc.categoryAxis.labels.boxAnchor = 'ne'
    bc.categoryAxis.labels.dx = 6
    bc.categoryAxis.labels.dy = -2
    bc.categoryAxis.labels.angle = 30
    bc.categoryAxis.labels.fontSize = 8
    bc.categoryAxis.categoryNames = categories if categories else ['High', 'Medium', 'Low']

    # Bar fill colors
    if colors_list:
        for idx, color in enumerate(colors_list):
            if idx < len(bc.bars):
                bc.bars[idx].fillColor = color
    else:
        bc.bars[0].fillColor = colors.red
        bc.bars[1].fillColor = colors.yellow
        bc.bars[2].fillColor = colors.green

    drawing.add(bc)

    # Chart title
    if title:
        drawing.add(String(total_width / 2, total_height - 20, title,
                           fontName='Helvetica-Bold', fontSize=12, textAnchor='middle'))

    return drawing

def flatten_vuln_list(vuln_list):
    """Flattens a list that may contain nested lists of vulnerability dicts."""
    flat = []
    for item in vuln_list:
        if isinstance(item, dict):
            flat.append(item)
        elif isinstance(item, list):
            flat.extend([v for v in item if isinstance(v, dict)])
    return flat

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

        # === FRONT PAGE FIXED WITH WARNINGS REMOVED ===
        
        # Paths
        center_logo_path = "ISFCR.png"

        # Load logos
        isfcr_logo = Image(center_logo_path, width=2.5 * inch, height=2.5 * inch) if os.path.exists(center_logo_path) else ""

        # Base styles
        styles = getSampleStyleSheet()
        style_title = ParagraphStyle('MyTitle', parent=styles['Title'], fontSize=26, alignment=1, spaceAfter=10)
        style_subtitle = ParagraphStyle('MySubtitle', parent=styles['Normal'], fontSize=18, alignment=1, leading=20, spaceAfter=10)
        style_date = ParagraphStyle('MyDate', parent=styles['Normal'], fontSize=16, alignment=1, spaceAfter=8)
        style_author = ParagraphStyle('MyAuthor', parent=styles['Normal'], fontSize=16, alignment=1,spaceAfter=8)

        # Paragraphs
        front_title = Paragraph("Websocket Endpoint Analysis Report", style_title)
        subtitle = Paragraph(
            "Insecure WebSocket Implementations: Crawling Public Sites, Testing Endpoints for Vulnerabilities, and Reporting Impact Analysis",
            style_subtitle
        )
        report_date = Paragraph(f"Report Generated on :  {datetime.today().strftime('%B %d, %Y')}", style_date)

        # Table: logo layout
        if isfcr_logo:
            logo_table = Table([[isfcr_logo]], colWidths=[doc.width])
            logo_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (0, 0), 'CENTER'),
                ('VALIGN', (0, 0), (0, 0), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (0, 0), 12)
            ]))
            elements.append(logo_table)
            elements.append(Spacer(1, 0.3 * inch))

        # Build cover page
        elements.append(front_title)
        elements.append(Spacer(1, 0.2 * inch))

        # Subtitle in centered table
        wrapped_subtitle = Table([[subtitle]], colWidths=[5.5 * inch])
        wrapped_subtitle.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, 0), 'CENTER')
        ]))
        elements.append(wrapped_subtitle)

        elements.append(Spacer(1, 0.2 * inch))
        elements.append(report_date)
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(PageBreak())

        # Title and Executive Summary
        elements.append(Paragraph("WebSocket Security Scan Report", title_style))
        elements.append(Spacer(1, 30))
        
        elements.append(Paragraph("Executive Summary", heading2_style))
        elements.append(Paragraph(
            "Real-time apps increasingly rely on WebSocket connections, but insecure implementations—such as missing origin checks or weak authentication—can allow hijacking or sensitive data exposure.",
            styles['Normal']
        ))
        elements.append(Spacer(1, 5))

        elements.append(Paragraph(
            "To address this, we developed an automated scanner that crawls public web applications, detects vulnerable WebSocket endpoints, and analyzes their real-world impact.",
            styles['Normal']
        ))
        elements.append(Spacer(1, 15))

# Solution Summary
        solution_points = [
        "• Crawl and detect active WebSocket endpoints from public websites.",
        "• Apply origin-header enforcement and protocol fuzzing tests to assess security gaps.",
        "• Generate structured PDF reports summarizing detected vulnerabilities and severity."
]
        for point in solution_points:
            elements.append(Paragraph(point, styles['Normal']))
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
            ('BACKGROUND', (0, 0), (0, -1), colors.lightyellow),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.lightyellow]),
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

        # === All Scanned Websites Section ===
        elements.append(Paragraph("All Scanned Websites", heading2_style))
        elements.append(Paragraph(
            "This section lists all scanned websites and summarizes the overall vulnerability distribution by severity. "
            "The bar graph below visualizes the number of High, Medium, and Low severity vulnerabilities identified across all scanned sites.",
        styles['Normal']
        ))
        elements.append(Spacer(1, 10))

        scanned_urls = combined_results.get("urls_scanned", [])
        urls_table_data = [["#", "Website"]]
        urls_table_data += [[str(i+1), create_wrapped_cell(url, 50)] for i, url in enumerate(scanned_urls)]

        urls_table = Table(urls_table_data, colWidths=[0.5 * inch, 5.5 * inch])
        urls_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.lightyellow]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]))
        elements.append(urls_table)
        elements.append(Spacer(1, 20))


        # Vulnerability Distribution Chart
        vuln_counts = [
            combined_results.get('total_vulnerabilities', {}).get('High', 0),
            combined_results.get('total_vulnerabilities', {}).get('Medium', 0),
            combined_results.get('total_vulnerabilities', {}).get('Low', 0)
        ]
        
        elements.append(create_bar_chart(
            vuln_counts,
            categories=['High', 'Medium', 'Low'],
            colors_list=[colors.red, colors.orange, colors.green],
            width=380,     # narrower width to fit within margins
            height=180,    # optional, keeps consistent sizing
            title="Vulnerability Distribution by Severity"
        ))


        # Vulnerability Summary by Type
        elements.append(Paragraph("Vulnerability Summary by Type", heading2_style))
        elements.append(Spacer(1, 10))

        elements.append(Paragraph(
            "This section summarizes key categories of vulnerabilities found during the scan. It groups issues like missing origin checks, weak authentication, insecure handshakes, and over 80 other attack for test to highlight common WebSocket flaws.",
        styles['Normal']
        ))
        elements.append(Spacer(1, 8))

        elements.append(Paragraph(
            "The bar chart below visualizes how many vulnerabilities were found in each category. This helps quickly identify the most common and critical problem areas across scanned applications.",
        styles['Normal']
        ))
        elements.append(Spacer(1, 15))
        
        vuln_types = combined_results["dict_total_errors"]
        
        type_data = [[k, str(v)] for k, v in vuln_types.items()]
        type_table = Table([["Type", "Count"]] + type_data, colWidths=[3*inch, 3*inch])
        type_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.lightyellow]),
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
            height=180,
            width=380
        ))
        elements.append(Spacer(1, 30))
        elements.append(PageBreak())
        elements.append(Paragraph("Detailed Scan Results", heading2_style))
        elements.append(Spacer(1, 20))

        # Description paragraph for Detailed Scan Results section
        details_para_text = (
            "This section provides an in-depth breakdown of each scanned target. "
            "For every URL, it lists the scan duration, number of URLs crawled during reconnaissance, "
            "and the WebSocket endpoints discovered. It helps identify how many potential communication "
            "channels were exposed for testing. Each target's vulnerability distribution is summarized "
            "by severity (High, Medium, Low) using a bar chart, followed by a detailed list of detected vulnerabilities. "
            "The section also documents the types of attacks performed and the exact WebSocket endpoints and internal URLs "
            "involved in the scan. This allows for a thorough understanding of the security posture and exposure of each target."
        )

        elements.append(Paragraph(details_para_text, styles['Normal']))
        elements.append(Spacer(1, 15))

        
        for url, url_result in combined_results.get('detailed_results', {}).items():
            elements.append(Paragraph(f"Target URL: {url}", heading2_style))
            elements.append(Spacer(1, 15))

            # === URL Details Table ===
            # Flatten all vulnerabilities across all websockets
            all_vulns = []
            for vuln_list in url_result.get('vulnerabilities', {}).values():
                all_vulns.extend(flatten_vuln_list(vuln_list))


            url_details = [
                ["Scan Duration:", f"{round(url_result.get('scan_duration', 0), 2)} seconds"],
                ["URLs Crawled:", str(url_result.get('num_crawled_urls', 0))],
                ["WebSocket Endpoints Found:", str(url_result.get('num_websockets', 0))],
                ["Attack Performed:", "True" if all_vulns else "False"],
                ["Attack Type:", "WebSocket Tests" if all_vulns else "None"],
                ["High Severity Findings:", str(sum(1 for v in all_vulns if v.get('risk') == 'High'))],
                ["Medium Severity Findings:", str(sum(1 for v in all_vulns if v.get('risk') == 'Medium'))],
                ["Low Severity Findings:", str(sum(1 for v in all_vulns if v.get('risk') == 'Low'))]
            ]

            wrapped_url_details = [[create_wrapped_cell(cell) for cell in row] for row in url_details]
            url_table = Table(wrapped_url_details, colWidths=[2*inch, 4*inch])
            url_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
    ('FONTSIZE', (0, 0), (-1, -1), 10),
    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
    ('TOPPADDING', (0, 0), (-1, -1), 12),
    ('GRID', (0, 0), (-1, -1), 1, colors.black)]))  # keep same style
            elements.append(url_table)
            elements.append(Spacer(1, 30))

            # === WebSocket Endpoints Table ===
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
            ws_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
    ('FONTSIZE', (0, 0), (-1, -1), 10),
    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
    ('TOPPADDING', (0, 0), (-1, -1), 12),
    ('GRID', (0, 0), (-1, -1), 1, colors.black)]))  # keep same style
            elements.append(ws_table)
            elements.append(Spacer(1, 30))

            # === Crawled URLs Table ===
            elements.append(Paragraph("Crawled URLs:", heading2_style))
            elements.append(Spacer(1, 15))

            crawled_urls_data = [["#", "URL"]]
            for idx, crawled_url in enumerate(url_result.get('crawled_urls', []), 1):
                crawled_urls_data.append([str(idx), crawled_url])

            wrapped_crawled_data = [[create_wrapped_cell(cell, width=40) for cell in row] for row in crawled_urls_data]
            crawled_table = Table(wrapped_crawled_data, colWidths=[0.5*inch, 5.5*inch])
            crawled_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
    ('FONTSIZE', (0, 0), (-1, -1), 10),
    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
    ('TOPPADDING', (0, 0), (-1, -1), 12),
    ('GRID', (0, 0), (-1, -1), 1, colors.black)]))  # keep same style
            elements.append(crawled_table)
            elements.append(Spacer(1, 30))

            # === Vulnerabilities Chart for this URL ===
            url_vuln_counts = [
                sum(1 for v in all_vulns if v.get('risk') == 'High'),
                sum(1 for v in all_vulns if v.get('risk') == 'Medium'),
                sum(1 for v in all_vulns if v.get('risk') == 'Low')
            ]
            elements.append(create_bar_chart(url_vuln_counts, title=f"Vulnerability Distribution for {url}", width=380, height=180))
            elements.append(Spacer(1, 30))

            # === Detailed Vulnerabilities ===
            if all_vulns:
                elements.append(PageBreak())
                elements.append(Paragraph("Detected Vulnerabilities:", heading2_style))
                elements.append(Spacer(1, 15))

                vuln_intro_para = (
                    "This section lists all vulnerabilities identified during the scan of the target. "
                    "Each entry includes the vulnerability name, its severity (High, Medium, or Low), a description of the issue, "
                    "recommended solutions, and the affected WebSocket URL or host. This detailed information helps prioritize fixes "
                    "and understand the exact flaws present in the WebSocket implementation of each target."
                )
                elements.append(Paragraph(vuln_intro_para, styles['Normal']))
                elements.append(Spacer(1, 10))

                for ws_url, vuln_list in url_result.get('vulnerabilities', {}).items():
                    # Print once per WebSocket
                    elements.append(Paragraph(f"Affected WebSocket Endpoint: {ws_url}", styles['Heading3']))
                    elements.append(Spacer(1, 10))

                    flat_vulns = flatten_vuln_list(vuln_list)
                    for vuln in flat_vulns:
                        risk = vuln.get('risk', 'Unknown')
                        bg_color = colors.mistyrose if risk == 'High' else \
                                colors.lightgoldenrodyellow if risk == 'Medium' else \
                                colors.lightgreen

                        vuln_data = [
                            ["Name:", vuln.get('name', 'Unknown')],
                            ["Risk Level:", risk],
                            ["Description:", vuln.get('description', '')],
                            ["Solution:", vuln.get('solution', '')]
                            # ⛔ Removed affected_url — no longer needed here
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

        # Build the PDF
        from reportlab.platypus import BaseDocTemplate, PageTemplate, Frame

        frame = Frame(
            doc.leftMargin,
            doc.bottomMargin + 60,
            doc.width,
            doc.height - 110,
            id='normal'
        )

        def draw_header_footer(canvas, doc):
            draw_header(canvas, doc)
            draw_footer(canvas, doc)

        doc = BaseDocTemplate(
            report_filename,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        doc.addPageTemplates([
            PageTemplate(id='header_footer', frames=frame, onPage=draw_header_footer)
        ])
        doc.build(elements)

        absolute_path = os.path.abspath(report_filename)
        return absolute_path
    
    except Exception as e:
        print(f"[-] Error generating PDF report: {str(e)}")
        raise e
    
def draw_header(canvas, doc):
    width, height = doc.pagesize
    header_height = 60

    canvas.setFillColor(colors.orange)
    canvas.rect(0, height - header_height, width, header_height, fill=True, stroke=0)

    pes_logo_path = "header.png"
    if os.path.exists(pes_logo_path):
        canvas.drawImage(
            pes_logo_path,
            x=50,
            y=height - 52,
            width=90,
            height=45,
            preserveAspectRatio=True,
            mask='auto'
        )

def draw_footer(canvas, doc):
    width, height = doc.pagesize

    footer_height = 60
    canvas.setFillColor(colors.orange)
    canvas.rect(0, 0, width, footer_height, fill=True, stroke=0)

    isfcr_logo_path = "footer.png"
    logo_x = 40
    logo_y = 5
    logo_w = 50
    logo_h = 40

    if os.path.exists(isfcr_logo_path):
        canvas.drawImage(isfcr_logo_path, logo_x, logo_y, width=logo_w, height=logo_h, preserveAspectRatio=True, mask='auto')

    text_left_x = logo_x + logo_w + 10
    text_base_y = logo_y + logo_h - 8
    canvas.setFont("Helvetica-Bold", 7)
    canvas.setFillColor(colors.black)
    canvas.drawString(text_left_x, text_base_y, "PESU Center for")
    canvas.setFont("Helvetica-Bold", 7)
    canvas.drawString(text_left_x, text_base_y -10, "Information Security,")
    canvas.setFont("Helvetica-Bold", 7)
    canvas.drawString(text_left_x, text_base_y -20, "Forensics and Cyber Resilience")

    canvas.setFont("Helvetica-Bold", 7)
    canvas.setFillColor(colors.black)
    canvas.drawRightString(width - 40, 45, "PESU RESEARCH")
    canvas.setFont("Helvetica-Bold", 7)
    canvas.drawRightString(width - 40, 35, "11TH FLOOR, BE BLOCK,")
    canvas.setFont("Helvetica-Bold", 7)
    canvas.drawRightString(width - 40, 25, "PES UNIVERSITY, RING ROAD CAMPUS,")
    canvas.setFont("Helvetica-Bold", 7)
    canvas.drawRightString(width - 40, 15, "BANGALORE, INDIA")