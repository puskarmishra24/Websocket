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
from html import escape
from reportlab.graphics.charts.piecharts import Pie
import math

def create_wrapped_cell(text, width=60):
    """Helper function to wrap and escape text in table cells"""
    if text is None:
        text = ""
    if not isinstance(text, str):
        text = str(text)
    text = escape(text)  # ⬅️ Add this line
    wrapped_text = "\n".join(wrap(text, width=width, break_long_words=True, break_on_hyphens=False))

    return Paragraph(wrapped_text, ParagraphStyle('Normal'))


def create_bar_chart(data, width=380, height=250, title="", categories=None, colors_list=None):
    """
    Create a visually responsive vertical bar chart with centered title,
    equal left/right padding, and content fitting inside.
    """
    left_padding = 60
    right_padding = 60
    top_padding = 30
    bottom_padding = 50

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
    rounded_max = math.ceil(max_val / 50) * 50

    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueMax = rounded_max
    bc.valueAxis.valueStep = 50

    def wrap_label_words(text, words_per_line=2):
        words = text.split()
        return '\n'.join(
            [' '.join(words[i:i+words_per_line]) for i in range(0, len(words), words_per_line)]
        )
    wrapped_labels = [wrap_label_words(label) for label in categories] if categories else ['High', 'Medium', 'Low']

    # Category labels
    bc.categoryAxis.labels.boxAnchor = 'ne'
    bc.categoryAxis.labels.dx = 6
    bc.categoryAxis.labels.dy = -2
    bc.categoryAxis.labels.angle = 30
    bc.categoryAxis.labels.fontSize = 6
    bc.categoryAxis.categoryNames = wrapped_labels

    # Bar fill colors
    if colors_list:
        for idx, color in enumerate(colors_list):
            if idx < len(bc.bars):
                bc.bars[idx].fillColor = color
    else:
        bc.bars[0].fillColor = colors.red
        bc.bars[1].fillColor = colors.yellow
        bc.bars[2].fillColor = colors.green
    # Add value labels on top of bars
    for i, val in enumerate(data,1):
        lbl = Label()
        lbl.setOrigin(
            bc.x + (bc.width/9) * i - 20,
            bc.y + (val / bc.valueAxis.valueMax) * bc.height + 5  # Y-position slightly above the bar
        )
        lbl.boxAnchor = 's'
        lbl.fontSize = 7
        lbl.setText(str(val))
        drawing.add(lbl)

    drawing.add(bc)

    # Chart title
    if title:
        drawing.add(String(total_width / 2, total_height - 20, title,
                           fontName='Helvetica-Bold', fontSize=12, textAnchor='middle'))

    return drawing

from reportlab.graphics.charts.textlabels import Label
from reportlab.graphics.shapes import Rect, Drawing, String

def create_heatmap(data_dict, width=500, height_per_row=20):
    """
    Create a horizontal heatmap based on website-wise vulnerability counts.
    `data_dict` format: {site1: {"High": x, "Medium": y, "Low": z}, ...}
    """
    websites = list(data_dict.keys())
    severities = ["High", "Medium", "Low"]
    color_map = {"High": colors.red, "Medium": colors.orange, "Low": colors.green}

    max_val = max([count for site in data_dict.values() for count in site.values()], default=1)
    
    cell_width = 40
    cell_height = height_per_row
    padding = 10
    title_height = 20

    total_width = padding * 4 + cell_width * len(severities) + 150  # space for labels
    total_height = title_height + (cell_height + padding) * len(websites) + padding

    drawing = Drawing(total_width, total_height)

    # Column Headers
    for idx, sev in enumerate(severities):
        drawing.add(String(150 + idx * cell_width + padding, total_height - title_height - 5, sev, fontSize=8))

    # Draw heatmap cells
    for row_idx, site in enumerate(websites):
        y = total_height - title_height - (row_idx + 1) * (cell_height + padding)

        # Site name
        drawing.add(String(5, y + 5, site[:25], fontSize=7))

        for col_idx, sev in enumerate(severities):
            count = data_dict[site].get(sev, 0)
            intensity = min(1.0, count / max_val if max_val!=0 else 0)
            color = color_map[sev]

            # Adjust color intensity
            fill = colors.Color(
                color.red * intensity,
                color.green * intensity,
                color.blue * intensity
            )
            x = 150 + col_idx * cell_width
            drawing.add(Rect(x, y, cell_width - 2, cell_height, fillColor=fill, strokeColor=colors.black))

            # Add count inside
            drawing.add(String(x + (cell_width / 2) - 2, y + 5, str(count), fontSize=6, textAnchor='middle'))

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

ATTACK_LIST = [
    # 1. Handshake & Protocol Validation (1–22)
    "Invalid Port",                          # 1
    "Non-WS Scheme",                         # 2
    "Omit Sec-WebSocket-Key",                # 3
    "Non-Base64 Sec-WebSocket-Key",          # 4
    "Oversized Sec-WebSocket-Key",           # 5
    "Duplicate Sec-WebSocket-Key",           # 6
    "Missing Sec-WebSocket-Version",         # 7
    "Invalid Sec-WebSocket-Version",         # 8
    "Conflicting Sec-WebSocket-Version",     # 9
    "Wrong Upgrade Header",                  #10
    "Missing Connection Header",             #11
    "Case-Sensitive Headers",                #12
    "Non-GET Method",                        #13
    "Fake HTTP Status",                      #14
    "Wrong Sec-WebSocket-Accept",            #15
    "Oversized Headers",                     #16
    "Missing Host Header",                   #17
    "Fake Host Header",                      #18
    "Multiple Host Headers",                 #19
    "Long URL Path",                         #20
    "Unicode URL",                           #21
    "HTTP/0.9 Handshake",                    #22

    # 2. Authentication & Session Control
    "No Session Cookie",                     # 23
    "Expired Cookie",                        # 24
    "Fake Token",                            # 25
    "HTTP Session Reuse",                    # 26
    "Stale Session Reconnect",               # 27
    "Cross-Site Cookie Hijack",              # 28
    "Missing Authentication",                  # 29

    # 3. Subprotocols & Extension Handling
    "Invalid Subprotocol",                   # 30
    "Conflicting Subprotocols",              # 31
    "Unaccepted Subprotocol",                # 32
    "Fake Extension",                        # 33
    "Conflicting Extensions",                # 34

    # 4. Transport Security & Encryption
    "Spoofed Connection Header",             # 35
    "HTTP/1.0 Downgrade",                    # 36
    "TLS Downgrade",                         # 37
    "Weak TLS Ciphers",                      # 38
    "Certificate Mismatch",                  # 39

    # 5. Payload Framing & Messaging Semantics
    "Undefined Opcode",                      # 40
    "Reserved Opcode",                       # 41
    "Zero-Length Fragment",                  # 42
    "Invalid Payload Length",                # 43
    "Negative Payload Length",               # 44
    "Mismatched Payload",                    # 45
    "Invalid Masking Key",                   # 46
    "Unmasked Client Frame",                 # 47
    "Invalid RSV Bits",                      # 48
    "Oversized Control Frame",               # 49
    "Non-UTF-8 Text",                        # 50
    "Null Bytes in Text",                    # 51
    "Binary as Text",                        # 52
    "Text as Binary",                        # 53
    "Invalid Close Code",                    # 54
    "Early Close Frame",                     # 55
    "No Close Frame",                        # 56
    "Long Close Reason",                     # 57

    # 6. Origin Policy & Cross-Origin Enforcement
    "Missing CORS Headers",                  # 58
    "Cross-Origin Iframe",                   # 59
    "Mixed Content",                         # 60
    "PostMessage Abuse",                     # 61
    "Spoofed URL",                           # 62
    "Missing Origin Check",                  # 63

    # 7. Application-Layer Logic & Misconfigurations
    "Error Message Leak",                    # 64
    "Server Disclosure",                     # 65
    "Invalid Content-Type",                  # 66
    "Missing Security Headers",              # 67
    "URL Path Traversal",                    # 68
    "Query Parameter Flood",                 # 69

    # 8. DoS, Compression & Resource Limits
    "Connection Flood",                      # 70
    "Oversized Message",                     # 71
    "Max Connections",                       # 72
    "Idle Timeout Abuse",                    # 73
    "High Compression Ratio",                # 74
    "Large Payload Resource Leak",           # 75
    "TCP Half-Open Resource Leak",           # 76
    "No Compression Negotiation",            # 77
    "No Timeout Policy",                     # 78

    # 9. Protocol Fuzzing
    "Protocol Fuzzing #1",                      # 79
    "Protocol Fuzzing #2",                      # 80
    "Protocol Fuzzing #3",                      # 81
    "Protocol Fuzzing #4",                      # 82
    "Protocol Fuzzing #5",                      # 83
    "Protocol Fuzzing #6",                      # 84
    "Protocol Fuzzing #7",                      # 85
    "Protocol Fuzzing #8",                      # 86
    "Protocol Fuzzing #9",                      # 87
    "Protocol Fuzzing #10",                     # 88
    "Protocol Fuzzing #11",                     # 89
    "Protocol Fuzzing #12",                     # 90
]

def create_side_by_side_pies_with_legend(error_dict, attack_list, width=400, height=200):
    """
    Draw two pie charts side by side with shared legend below.
    Left = Attack Types (static), Right = Results (from dict_total_errors)
    """
    # Color palette (repeatable)
    palette = [
        colors.HexColor("#e41a1c"), colors.HexColor("#377eb8"),
        colors.HexColor("#4daf4a"), colors.HexColor("#984ea3"),
        colors.HexColor("#ff7f00"), colors.HexColor("#ffff33"),
        colors.HexColor("#a65628"), colors.HexColor("#f781bf"),
        colors.HexColor("#999999")
    ]

    # === Pie 1: Attack Types by Category ===
    CATEGORY_SPLITS = {
    "Handshake": (0, 22),
    "Auth/Sessions": (40, 47),
    "Subprotocols": (47, 52),
    "Transport Security": (52, 57),
    "Payload": (22, 40),
    "Cross-Origin": (66, 72),
    "Application": (72, 78),
    "DoS": (57, 66),
    "Fuzzing": (78, 90)
    }   
    cat_labels = list(CATEGORY_SPLITS.keys())
    cat_data = [end - start for (_, (start, end)) in CATEGORY_SPLITS.items()]

    # === Pie 2: Result Counts from dict_total_errors ===
    result_labels = list(error_dict.keys())
    result_data = list(error_dict.values())

    drawing = Drawing(width, height)

    pie1 = Pie()
    pie1.x = 20
    pie1.y = 80
    pie1.width = 110
    pie1.height = 110
    pie1.data = cat_data
    pie1.labels = []
    total = sum(pie1.data)
    pie1.simpleLabels = 1  # enables percentage-based labels inside
    for i in range(len(pie1.data)):
        percent = round((pie1.data[i] / total) * 100,2) if total else 0
        pie1.slices[i].fillColor = palette[i % len(palette)]
        pie1.labels.append(percent)

    pie2 = Pie()
    pie2.x = 200
    pie2.y = 80
    pie2.width = 110
    pie2.height = 110
    pie2.data = result_data
    total2 = sum(pie2.data)
    pie2.labels = []
    pie2.simpleLabels = 1
    for i in range(len(pie2.data)):
        percent = round((pie2.data[i] / total2) * 100,2) if total2 else 0
        pie2.slices[i].fillColor = palette[i % len(palette)]
        pie2.labels.append(percent)

    drawing.add(pie1)
    drawing.add(pie2)

    # === Legend ===
    legend_y = 10
    legend_x = 10
    spacing = 65
    box_size = 8

    for i, label in enumerate(cat_labels):
        x_pos = legend_x + (i % 5) * spacing
        y_pos = legend_y - (i // 5) * 12
        drawing.add(Rect(x_pos, y_pos, box_size, box_size, fillColor=palette[i % len(palette)]))
        drawing.add(String(x_pos + box_size + 3, y_pos, label, fontSize=6))

    return drawing

def create_detailed_heatmap(combined_results, cell_width=5, cell_height=5, padding=1):
    """
    Create a detailed heatmap showing WebSocket vs 78 attacks.
    Colors: High=Red, Medium=Orange, Low=Yellow, Safe=Green, Not Run=Black.
    """
    attack_index = {name: idx for idx, name in enumerate(ATTACK_LIST)}
    color_map = {"High": colors.red, "Medium": colors.orange, "Low": colors.yellow}
    fallback_color = colors.green  # attack run, no vuln
    missing_color = colors.black   # not run

    grouped_rows = {}

    for site, details in combined_results.get("detailed_results", {}).items():
        grouped_rows[site] = []
        for vuln_list in details.get("vulnerabilities", {}).values():
            flat = flatten_vuln_list(vuln_list)
            risk_map = {}
            for v in flat:
                name = v.get("name")
                risk = v.get("risk")
                if name and risk:
                    risk_map[name] = risk
            grouped_rows[site].append(risk_map)

    # Drawing dimensions
    total_width = 150 + len(ATTACK_LIST) * (cell_width + padding) + padding
    total_height = padding + len(grouped_rows) * (cell_height + padding) + 50

    drawing = Drawing(total_width, total_height)

    # Column headers
    for idx, name in enumerate(ATTACK_LIST):
        x = 3 + idx * (5)
        drawing.add(String(74+x, total_height-6, f"{idx+1}", fontSize=4, textAnchor="middle"))

    row_idx = 0
    for site, ws_risks in grouped_rows.items():
        y = total_height - (row_idx + 2) * (cell_height + padding)
        if ws_risks == []:
            continue
        # Write website name once
        drawing.add(String(-5, y + 2, site[:60], fontSize=6))
        for i, risk_map in enumerate(ws_risks):
            y = total_height - (row_idx + 2) * (cell_height + padding)

            for attack_name in ATTACK_LIST:
                x = attack_index[attack_name] * (cell_width)
                risk = risk_map.get(attack_name)

                if risk in color_map:
                    fill = color_map[risk]
                elif attack_name in risk_map:
                    fill = fallback_color
                else:
                    fill = missing_color

                drawing.add(Rect(75 + x, y, cell_width, cell_height, fillColor=fill, strokeColor=None))

            row_idx += 1  # Next row
    # Legend
    legend_items = [
        ("High Risk", colors.red),
        ("Medium Risk", colors.orange),
        ("Low Risk", colors.yellow),
        ("No Risk", colors.green),
        ("Test Failed", colors.black),
    ]

    legend_x = 75  # Starting X-position for legend
    legend_y = 0 # Y-position at bottom of drawing
    legend_spacing = 60  # Horizontal spacing between legend items

    for i, (label, color) in enumerate(legend_items):
        x_pos = legend_x + i * legend_spacing
        drawing.add(Rect(x_pos, legend_y, 5, 5, fillColor=color, strokeColor=colors.black))
        drawing.add(String(x_pos + 8, legend_y, label, fontSize=5, fillColor=colors.black))

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
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black)
        ]))
        elements.append(urls_table)
        elements.append(Spacer(1, 20))


        # # Vulnerability Distribution Chart
        # vuln_counts = [
        #     combined_results.get('total_vulnerabilities', {}).get('High', 0),
        #     combined_results.get('total_vulnerabilities', {}).get('Medium', 0),
        #     combined_results.get('total_vulnerabilities', {}).get('Low', 0)
        # ]
        
        # elements.append(create_bar_chart(
        #     vuln_counts,
        #     categories=['High', 'Medium', 'Low'],
        #     colors_list=[colors.red, colors.orange, colors.green],
        #     width=380,     # narrower width to fit within margins
        #     height=180,    # optional, keeps consistent sizing
        #     title="Vulnerability Distribution by Severity"
        # ))
# === Heatmap Section ===
#         elements.append(Paragraph("Vulnerability Heatmap by Website", heading2_style))
#         elements.append(Spacer(1, 10))

# # Build data for heatmap: {site: {"High": x, "Medium": y, "Low": z}, ...}
#         heatmap_data = {}
#         for url, details in combined_results.get("detailed_results", {}).items():
#             all_vulns = [v for vulns in details.get("vulnerabilities", {}).values() for v in vulns]
#             heatmap_data[url] = {
#                 "High": sum(1 for v in all_vulns if v.get("risk") == "High"),
#                 "Medium": sum(1 for v in all_vulns if v.get("risk") == "Medium"),
#                 "Low": sum(1 for v in all_vulns if v.get("risk") == "Low")
#             }

#         elements.append(create_heatmap(heatmap_data))
#         elements.append(Spacer(1, 30))

        heatmap = create_detailed_heatmap(combined_results)
        elements.append(Paragraph("WebSocket vs. Attack Heatmap", heading2_style))
        elements.append(Spacer(1, 10))
        elements.append(heatmap)
        elements.append(Spacer(1, 30))

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
        
        type_data = [[k, str(v)] for k, v in vuln_types.items() if k != 'No']
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
        # Vulnerability Type Distribution Chart
        type_counts = [v for v in vuln_types.values()]
        type_categories = list(vuln_types.keys())
        elements.append(create_bar_chart(
            type_counts,
            title="Vulnerability Distribution by Type",
            categories=type_categories,
            colors_list=[colors.blue] * len(type_categories),
            height=250,
            width=380
        ))
        elements.append(Spacer(1, 30))

        # drawing = create_attack_type_piechart(ATTACK_LIST)
        # elements.append(Paragraph("Test Type Distribution", heading2_style))
        # elements.append(drawing)
        # drawing = create_attack_results_piechart(combined_results["dict_total_errors"])
        # elements.append(Paragraph("Attack Result Summary", heading2_style))
        # elements.append(drawing)
        elements.append(PageBreak())

        elements.append(Paragraph("Test Distribution vs Results", heading2_style))
        elements.append(create_side_by_side_pies_with_legend(
            combined_results["dict_total_errors"],
            ATTACK_LIST
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

            # # === Crawled URLs Table ===
            # elements.append(Paragraph("Crawled URLs:", heading2_style))
            # elements.append(Spacer(1, 15))

    #         crawled_urls_data = [["#", "URL"]]
    #         for idx, crawled_url in enumerate(url_result.get('crawled_urls', []), 1):
    #             crawled_urls_data.append([str(idx), crawled_url])

    #         wrapped_crawled_data = [[create_wrapped_cell(cell, width=40) for cell in row] for row in crawled_urls_data]
    #         crawled_table = Table(wrapped_crawled_data, colWidths=[0.5*inch, 5.5*inch])
    #         crawled_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
    # ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
    # ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
    # ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
    # ('FONTSIZE', (0, 0), (-1, -1), 10),
    # ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
    # ('TOPPADDING', (0, 0), (-1, -1), 12),
    # ('GRID', (0, 0), (-1, -1), 1, colors.black)]))  # keep same style
    #         elements.append(crawled_table)
    #         elements.append(Spacer(1, 30))

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
                        if risk == 'No':
                            continue
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