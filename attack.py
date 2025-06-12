import os
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import time
import websocket
import logging
from base64 import b64encode
import socket
import ssl
from urllib.parse import urlparse
from termcolor import colored
import struct
import random
import string
import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_payload(file_name):
    """Load payloads from the specified file."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(base_dir, file_name)
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Payload file not found: {file_path}")
    with open(file_path, "r", encoding='utf-8', errors='ignore') as file:
        return [line.strip() for line in file.readlines() if line.strip()]

def attack_website(target_url, websocket_urls, attack_type="websocket"):
    """Main function to handle WebSocket attack logic."""
    websocket_payloads = load_payload("websocket_payload.txt")
    print(colored("Starting WebSocket tests...", "yellow"))
    vulnerabilities = perform_websocket_tests(websocket_urls, websocket_payloads)
    return vulnerabilities

def send_raw_handshake(host, port, request_headers):
    """Send a raw WebSocket handshake."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        if port == 443:
            s = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLS)
        s.connect((host, port))
        s.send(request_headers.encode())
        response = s.recv(4096).decode()
        s.close()
        return response
    except socket.error as e:
        print(colored(f"Handshake failed for {host}:{port}: {e}", "yellow"))
        return ""

def send_custom_frame(ws_url, frame_data):
    """Send a custom WebSocket frame."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, timeout=5)
        ws.send_binary(frame_data)
        response = ws.recv()
        ws.close()
        return response
    except websocket.WebSocketException as e:
        print(colored(f"Custom frame failed for {ws_url}: {e}", "yellow"))
        return None

def test_origin_check(ws_url):
    """Test for missing or weak origin checks."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, origin="http://malicious-site.com", timeout=5)
        ws.send("ping")
        response = ws.recv()
        ws.close()
        return {
            'name': 'Missing Origin Check',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepts connections from unauthorized origin 'http://malicious-site.com'.",
            'solution': 'Implement strict Origin header validation (whitelist allowed domains).',
            'affected_url': ws_url,
            'impact': 'Allows cross-origin attacks, potentially leading to data theft or session hijacking.'
        }
    except websocket.WebSocketException as e:
        logging.info(f"Origin check test for {ws_url}: {e}")
        return None

def test_authentication(ws_url):
    """Test for missing or weak authentication."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, timeout=5)
        ws.send("whoami")
        response = ws.recv()
        ws.close()
        if response and len(response) > 0:
            return {
                'name': 'Missing Authentication',
                'risk': 'High',
                'description': f"WebSocket at {ws_url} allows unauthenticated connections and responds with data.",
                'solution': 'Require authentication (e.g., JWT, API keys) for WebSocket connections.',
                'affected_url': ws_url,
                'impact': 'Unauthorized access to sensitive data or functionality.'
            }
        return None
    except websocket.WebSocketException as e:
        logging.info(f"Authentication test for {ws_url}: {e}")
        return None

def test_fuzzing(ws_url, payload):
    """Perform protocol fuzzing with payloads."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, timeout=5)
        ws.send(payload)
        try:
            response = ws.recv()
            ws.close()
            if response:
                return {
                    'name': 'Protocol Fuzzing Vulnerability',
                    'risk': 'Medium',
                    'description': f"WebSocket at {ws_url} responds to malformed payload: {payload[:50]}...",
                    'solution': 'Implement robust input validation and reject malformed messages.',
                    'affected_url': ws_url,
                    'impact': 'Malformed messages may cause server errors or data leaks.'
                }
        except websocket.WebSocketException:
            ws.close()
            return {
                'name': 'Protocol Fuzzing Crash',
                'risk': 'High',
                'description': f"WebSocket at {ws_url} crashed or closed connection on payload: {payload[:50]}...",
                'solution': 'Handle malformed messages gracefully to prevent crashes.',
                'affected_url': ws_url,
                'impact': 'Server crashes can lead to denial-of-service.'
            }
    except websocket.WebSocketException as e:
        logging.info(f"Fuzzing test for {ws_url}: {e}")
        return None

def test_omit_sec_websocket_key(host, port, path="/"):
    """Test omitting Sec-WebSocket-Key header (Vuln #1)."""
    req = f"""GET {path} HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Version: 13\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Omit Sec-WebSocket-Key',
        'risk': 'High',
        'description': f"Server at {host}:{port} accepted handshake without Sec-WebSocket-Key.",
        'solution': 'Require Sec-WebSocket-Key header for WebSocket handshake.',
        'affected_host': f"{host}:{port}",
        'impact': 'Bypassing handshake validation can allow unauthorized connections.'
    } if "101 Switching Protocols" in response else None

def test_non_base64_sec_websocket_key(host, port, path="/"):
    """Test non-base64 Sec-WebSocket-Key header (Vuln #2)."""
    req = f"""GET {path} HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: NotBase64!!\r
Sec-WebSocket-Version: 13\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Non-Base64 Sec-WebSocket-Key',
        'risk': 'High',
        'description': f"Server at {host}:{port} accepted non-base64 Sec-WebSocket-Key.",
        'solution': 'Validate Sec-WebSocket-Key as base64-encoded.',
        'affected_host': f"{host}:{port}",
        'impact': 'Improper key validation can lead to handshake vulnerabilities.'
    } if "101 Switching Protocols" in response else None

def test_oversized_sec_websocket_key(host, port, path="/"):
    """Test oversized Sec-WebSocket-Key header (Vuln #3)."""
    big_key = b64encode(b"A" * 1024).decode()  # 1KB key
    req = f"""GET {path} HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {big_key}\r
Sec-WebSocket-Version: 13\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Oversized Sec-WebSocket-Key',
        'risk': 'Medium',
        'description': f"Server at {host}:{port} accepted oversized Sec-WebSocket-Key (1KB).",
        'solution': 'Limit Sec-WebSocket-Key size to prevent resource exhaustion.',
        'affected_host': f"{host}:{port}",
        'impact': 'Large keys can cause server resource exhaustion.'
    } if "101 Switching Protocols" in response else None

def test_duplicate_sec_websocket_key(host, port, path="/"):
    """Test duplicate Sec-WebSocket-Key headers (Vuln #4)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Key: {key}duplicate\r
Sec-WebSocket-Version: 13\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Duplicate Sec-WebSocket-Key',
        'risk': 'High',
        'description': f"Server at {host}:{port} accepted duplicate Sec-WebSocket-Key headers.",
        'solution': 'Reject requests with multiple Sec-WebSocket-Key headers.',
        'affected_host': f"{host}:{port}",
        'impact': 'Duplicate headers can confuse handshake processing.'
    } if "101 Switching Protocols" in response else None

def test_missing_sec_websocket_version(host, port, path="/"):
    """Test missing Sec-WebSocket-Version header (Vuln #5)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Missing Sec-WebSocket-Version',
        'risk': 'High',
        'description': f"Server at {host}:{port} accepted handshake without Sec-WebSocket-Version.",
        'solution': 'Require Sec-WebSocket-Version header for WebSocket handshake.',
        'affected_host': f"{host}:{port}",
        'impact': 'Missing version header can allow incompatible connections.'
    } if "101 Switching Protocols" in response else None

def test_invalid_sec_websocket_version(host, port, path="/"):
    """Test invalid Sec-WebSocket-Version header (Vuln #6)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Version: 999\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Invalid Sec-WebSocket-Version',
        'risk': 'High',
        'description': f"Server at {host}:{port} accepted invalid Sec-WebSocket-Version.",
        'solution': 'Validate Sec-WebSocket-Version (e.g., 13) for WebSocket handshake.',
        'affected_host': f"{host}:{port}",
        'impact': 'Invalid versions can lead to protocol mismatches.'
    } if "101 Switching Protocols" in response else None

def test_conflicting_sec_websocket_version(host, port, path="/"):
    """Test conflicting Sec-WebSocket-Version headers (Vuln #7)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Version: 13\r
Sec-WebSocket-Version: 8\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Conflicting Sec-WebSocket-Version',
        'risk': 'High',
        'description': f"Server at {host}:{port} accepted conflicting Sec-WebSocket-Version headers.",
        'solution': 'Reject requests with multiple Sec-WebSocket-Version headers.',
        'affected_host': f"{host}:{port}",
        'impact': 'Conflicting versions can cause protocol errors.'
    } if "101 Switching Protocols" in response else None

def test_wrong_upgrade_header(host, port, path="/"):
    """Test wrong Upgrade header (Vuln #8)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r
Host: {host}\r
Upgrade: websocketty\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Version: 13\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Wrong Upgrade Header',
        'risk': 'High',
        'description': f"Server at {host}:{port} accepted handshake with wrong Upgrade header.",
        'solution': 'Enforce strict Upgrade header validation.',
        'affected_host': f"{host}:{port}",
        'impact': 'Incorrect headers can bypass protocol validation.'
    } if "101 Switching Protocols" in response else None

def test_missing_connection_header(host, port, path="/"):
    """Test missing Connection header (Vuln #9)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Version: 13\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Missing Connection Header',
        'risk': 'High',
        'description': f"Server at {host}:{port} accepted handshake without Connection header.",
        'solution': 'Require Connection: Upgrade header for security.',
        'affected_host': f"{host}:{port}",
        'impact': 'Missing headers can allow improper connections.'
    } if "101 Switching Protocols" in response else None

def test_case_sensitive_headers(host, port, path="/"):
    """Test case-sensitive headers (Vuln #10)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r
Host: {host}\r
uPgradE: websocket\r
cOnneCtion: Upgrade\r
sEc-websocKet-key: {key}\r
Sec-WebSocket-Version: 13\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Case-Sensitive Headers',
        'risk': 'Medium',
        'description': f"Server at {host}:{port} accepted case-sensitive headers.",
        'solution': 'Ensure case-insensitive header parsing as per RFC.',
        'affected_host': f"{host}:{port}",
        'impact': 'Inconsistent header parsing can lead to security bypasses.'
    } if "101 Switching Protocols" in response else None

def test_non_get_method(host, port, path="/"):
    """Test non-GET method for handshake (Vuln #11)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""POST {path} HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Version: 13\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Non-GET Method',
        'risk': 'High',
        'description': f"Server at {host}:{port} accepted non-GET method (POST) for handshake.",
        'solution': 'Restrict WebSocket handshakes to GET method.',
        'affected_host': f"{host}:{port}",
        'impact': 'Non-GET methods can bypass standard handshake validation.'
    } if "101 Switching Protocols" in response else None

def test_fake_http_status(host, port, path="/"):
    """Test fake HTTP status code (Vuln #12)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Version: 13\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Fake HTTP Status',
        'risk': 'Medium',
        'description': f"Server at {host}:{port} returned unexpected HTTP status.",
        'solution': 'Ensure server returns 101 Switching Protocols for valid handshakes.',
        'affected_host': f"{host}:{port}",
        'impact': 'Incorrect status codes can confuse clients.'
    } if "101 Switching Protocols" not in response and response else None

def test_omit_sec_websocket_key(host, port, path="/"):
    """Test omitting Sec-WebSocket-Key header (Vuln #1)."""
    req = f"""GET {path} HTTP/1.1\r\n
Host: {host}\r\n
Upgrade: websocket\r\n
Connection: Upgrade\r\n
Sec-WebSocket-Version: 13\r\n
\r\n"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Omit Sec-WebSocket-Key',
        'risk': 'High',
        'description': f"Server at {host}:{port} accepted handshake without Sec-WebSocket-Key.",
        'solution': 'Require Sec-WebSocket-Key header for WebSocket handshake.',
        'affected_host': f"{host}:{port}",
        'impact': 'Bypassing handshake validation can allow unauthorized connections.'
    } if "101 Switching Protocols" in response else None

def test_oversized_headers(host, port, path="/"):
    """Test oversized headers (Vuln #14)."""
    big_value = "A" * 8000
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r
Host: {host}\r
X-Big-Header: {big_value}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Version: 13\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Oversized Headers',
        'risk': 'Medium',
        'description': f"Server at {host}:{port} accepted handshake with oversized headers.",
        'solution': 'Set limits for header size to prevent resource exhaustion.',
        'affected_host': f"{host}:{port}",
        'impact': 'Oversized headers can cause denial-of-service attacks.'
    } if "101 Switching Protocols" in response else None

def test_missing_host_header(host, port, path="/"):
    """Test missing Host header (Vuln #15)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Version: 13\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Missing Host Header',
        'risk': 'High',
        'description': f"Server at {host}:{port} accepted handshake without Host header.",
        'solution': 'Enforce Host header validation.',
        'affected_host': f"{host}:{port}",
        'impact': 'Missing Host header can allow domain spoofing.'
    } if "101 Switching Protocols" in response else None

def test_fake_host_header(host, port, path="/"):
    """Test fake Host header (Vuln #16)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r
Host: fake.example.com\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Version: 13\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Fake Host Header',
        'risk': 'Medium',
        'description': f"Server at {host}:{port} accepted handshake with incorrect Host header.",
        'solution': 'Validate Host header to match expected server domain.',
        'affected_host': f"{host}:{port}",
        'impact': 'Fake Host headers can enable domain spoofing attacks.'
    } if "101 Switching Protocols" in response else None

def test_multiple_host_headers(host, port, path="/"):
    """Test multiple Host headers (Vuln #17)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r
Host: real.example.com\r
Host: fake.example.com\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Version: 13\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Multiple Host Headers',
        'risk': 'High',
        'description': f"Server at {host}:{port} accepted handshake with multiple Host headers.",
        'solution': 'Reject requests with duplicate Host headers.',
        'affected_host': f"{host}:{port}",
        'impact': 'Multiple Host headers can confuse server routing.'
    } if "101 Switching Protocols" in response else None

def test_long_url_path(host, port, path="/"):
    """Test long URL path (Vuln #18)."""
    long_path = "/" + "a" * 2048
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {long_path} HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Version: 13\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Long URL Path',
        'risk': 'Medium',
        'description': f"Server at {host}:{port} accepted handshake with long URL path (2KB).",
        'solution': 'Limit URL path length to prevent resource exhaustion.',
        'affected_host': f"{host}:{port}",
        'impact': 'Long URLs can cause server overload or crashes.'
    } if "101 Switching Protocols" in response else None

def test_unicode_url(host, port, path="/"):
    """Test Unicode URL (Vuln #19)."""
    unicode_path = "/%F0%9F%98%80"  # Smiling emoji
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {unicode_path} HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Version: 13\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Unicode URL',
        'risk': 'Medium',
        'description': f"Server at {host}:{port} accepted handshake with Unicode URL.",
        'solution': 'Sanitize and validate URL paths to handle Unicode correctly.',
        'affected_host': f"{host}:{port}",
        'impact': 'Improper Unicode handling can lead to parsing errors or bypasses.'
    } if "101 Switching Protocols" in response else None

def test_http_0_9_handshake(host, port, path="/"):
    """Test HTTP/0.9 handshake (Vuln #20)."""
    req = f"""GET {path}\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'HTTP/0.9 Handshake',
        'risk': 'High',
        'description': f"Server at {host}:{port} accepted HTTP/0.9 handshake.",
        'solution': 'Require HTTP/1.1 or higher for WebSocket handshakes.',
        'affected_host': f"{host}:{port}",
        'impact': 'HTTP/0.9 lacks headers, enabling downgrade attacks.'
    } if response else None

def test_invalid_port(ws_url):
    """Test invalid port (Vuln #21)."""
    try:
        parsed_url = urlparse(ws_url)
        invalid_url = f"{parsed_url.scheme}://{parsed_url.hostname}:99999{parsed_url.path}"
        ws = websocket.WebSocket()
        ws.connect(invalid_url, timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
            'name': 'Invalid Port',
            'risk': 'Medium',
            'description': f"WebSocket at {invalid_url} accepted connection on invalid port 99999.",
            'solution': 'Restrict WebSocket connections to valid ports.',
            'affected_url': invalid_url,
            'impact': 'Invalid ports can indicate misconfiguration.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"Invalid port test failed for {ws_url}: {e}", "yellow"))
        return None

def test_non_ws_scheme(ws_url):
    """Test non-WS scheme (Vuln #22)."""
    try:
        parsed_url = urlparse(ws_url)
        non_ws_url = f"http://{parsed_url.hostname}:{parsed_url.port or (443 if parsed_url.scheme == 'wss' else 80)}{parsed_url.path}"
        ws = websocket.WebSocket()
        ws.connect(non_ws_url, timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
            'name': 'Non-WS Scheme',
            'risk': 'High',
            'description': f"Server at {non_ws_url} accepted WebSocket connection with non-WS scheme.",
            'solution': 'Restrict WebSocket connections to ws:// or wss:// schemes.',
            'affected_url': non_ws_url,
            'impact': 'Non-WS schemes can bypass protocol validation.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"Non-WS scheme test failed for {ws_url}: {e}", "yellow"))
        return None

def test_undefined_opcode(ws_url):
    """Test undefined opcode (Vuln #23)."""
    frame = struct.pack("!B", 0x83) + struct.pack("!B", 0x04) + b"test"  # FIN=1, Opcode=0x3, Length=4
    response = send_custom_frame(ws_url, frame)
    return {
        'name': 'Undefined Opcode',
        'risk': 'Medium',
        'description': f"WebSocket at {ws_url} accepted frame with undefined opcode 0x3.",
        'solution': 'Reject frames with undefined opcodes.',
        'affected_url': ws_url,
        'impact': 'Undefined opcodes can cause unexpected server behavior.'
    } if response else None

def test_reserved_opcode(ws_url):
    """Test reserved opcode (Vuln #24)."""
    frame = struct.pack("!B", 0x8B) + struct.pack("!B", 0x04) + b"test"  # FIN=1, Opcode=0xB, Length=4
    response = send_custom_frame(ws_url, frame)
    return {
        'name': 'Reserved Opcode',
        'risk': 'Medium',
        'description': f"WebSocket at {ws_url} accepted frame with reserved opcode 0xB.",
        'solution': 'Reject frames with reserved opcodes (0x3-0x7, 0xB-0xF).',
        'affected_url': ws_url,
        'impact': 'Reserved opcodes can lead to protocol errors.'
    } if response else None

def test_zero_length_fragment(ws_url):
    """Test zero-length fragment (Vuln #25)."""
    frame1 = struct.pack("!B", 0x01) + struct.pack("!B", 0x00)
    frame2 = struct.pack("!B", 0x80) + struct.pack("!B", 0x04) + b"test"
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, timeout=5)
        ws.send_binary(frame1)
        ws.send_binary(frame2)
        response = ws.recv()
        ws.close()
        return {
            'name': 'Zero-Length Fragment',
            'risk': 'Medium',
            'description': f"WebSocket at {ws_url} accepted zero-length fragment.",
            'solution': 'Reject zero-length fragments to prevent parsing issues.',
            'affected_url': ws_url,
            'impact': 'Zero-length fragments can cause server confusion.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"Zero-length fragment test failed for {ws_url}: {e}", "yellow"))
        return None

def test_invalid_payload_length(ws_url):
    """Test invalid payload length (Vuln #26)."""
    frame = struct.pack("!B", 0x81) + struct.pack("!B", 0x0A) + b"test"
    response = send_custom_frame(ws_url, frame)
    return {
        'name': 'Invalid Payload Length',
        'risk': 'High',
        'description': f"WebSocket at {ws_url} accepted frame with invalid payload length.",
        'solution': 'Validate payload length matches actual data.',
        'affected_url': ws_url,
        'impact': 'Invalid lengths can cause buffer overflows or crashes.'
    } if response else None

def test_negative_payload_length(ws_url):
    """Test negative payload length (Vuln #27)."""
    frame = struct.pack("!B", 0x81) + struct.pack("!B", 0xFF) + b"test"
    response = send_custom_frame(ws_url, frame)
    return {
        'name': 'Negative Payload Length',
        'risk': 'High',
        'description': f"WebSocket at {ws_url} accepted frame with invalid (large) payload length.",
        'solution': 'Reject frames with invalid or negative payload lengths.',
        'affected_url': ws_url,
        'impact': 'Invalid lengths can lead to server crashes.'
    } if response else None

def test_mismatched_payload(ws_url):
    """Test mismatched payload (Vuln #28)."""
    frame = struct.pack("!B", 0x81) + struct.pack("!B", 0x04) + b"testtest"
    response = send_custom_frame(ws_url, frame)
    return {
        'name': 'Mismatched Payload',
        'risk': 'High',
        'description': f"WebSocket at {ws_url} accepted frame with mismatched payload length.",
        'solution': 'Ensure payload length matches actual data received.',
        'affected_url': ws_url,
        'impact': 'Mismatched payloads can cause parsing errors or exploits.'
    } if response else None

def test_invalid_masking_key(ws_url):
    """Test invalid masking key (Vuln #29)."""
    payload = b"test"
    mask = b"\x00\x00\x00\x00"
    masked_payload = bytes(p ^ mask[i % 4] for i, p in enumerate(payload))
    frame = struct.pack("!B", 0x81) + struct.pack("!B", 0x84) + mask + masked_payload
    response = send_custom_frame(ws_url, frame)
    return {
        'name': 'Invalid Masking Key',
        'risk': 'Medium',
        'description': f"WebSocket at {ws_url} accepted frame with invalid masking key.",
        'solution': 'Validate masking key application for client frames.',
        'affected_url': ws_url,
        'impact': 'Invalid masking can lead to data corruption.'
    } if response else None

def test_unmasked_client_frame(ws_url):
    """Test unmasked client frame (Vuln #30)."""
    frame = struct.pack("!B", 0x81) + struct.pack("!B", 0x04) + b"test"
    response = send_custom_frame(ws_url, frame)
    return {
        'name': 'Unmasked Client Frame',
        'risk': 'High',
        'description': f"WebSocket at {ws_url} accepted unmasked client frame.",
        'solution': 'Require masking for all client-to-server frames per RFC 6455.',
        'affected_url': ws_url,
        'impact': 'Unmasked frames can be intercepted by proxies.'
    } if response else None

def test_invalid_rsv_bits(ws_url):
    """Test invalid RSV bits (Vuln #31)."""
    frame = struct.pack("!B", 0xC1) + struct.pack("!B", 0x04) + b"test"
    response = send_custom_frame(ws_url, frame)
    return {
        'name': 'Invalid RSV Bits',
        'risk': 'Medium',
        'description': f"WebSocket at {ws_url} accepted frame with invalid RSV bits.",
        'solution': 'Reject frames with non-zero RSV bits unless negotiated.',
        'affected_url': ws_url,
        'impact': 'Invalid RSV bits can cause protocol violations.'
    } if response else None

def test_oversized_control_frame(ws_url):
    """Test oversized control frame (Vuln #32)."""
    payload = b"A" * 126
    frame = struct.pack("!B", 0x89) + struct.pack("!B", 0x7E) + struct.pack("!H", 126) + payload
    response = send_custom_frame(ws_url, frame)
    return {
        'name': 'Oversized Control Frame',
        'risk': 'High',
        'description': f"WebSocket at {ws_url} accepted oversized control frame (126 bytes).",
        'solution': 'Enforce 125-byte limit for control frames per RFC 6455.',
        'affected_url': ws_url,
        'impact': 'Oversized control frames can cause server crashes.'
    } if response else None

def test_non_utf8_text(ws_url):
    """Test non-UTF-8 text frame (Vuln #33)."""
    frame = struct.pack("!B", 0x81) + struct.pack("!B", 0x02) + b"\xFF\xFF"
    response = send_custom_frame(ws_url, frame)
    return {
        'name': 'Non-UTF-8 Text',
        'risk': 'Medium',
        'description': f"WebSocket at {ws_url} accepted non-UTF-8 Hztext frame.",
        'solution': 'Validate text frames for UTF-8 encoding.',
        'affected_url': ws_url,
        'impact': 'Non-UTF-8 text can cause parsing errors or crashes.'
    } if response else None

def test_null_bytes_in_text(ws_url):
    """Test null bytes in text frame (Vuln #34)."""
    frame = struct.pack("!B", 0x81) + struct.pack("!B", 0x05) + b"te\x00st"
    response = send_custom_frame(ws_url, frame)
    return {
        'name': 'Null Bytes in Text',
        'risk': 'Medium',
        'description': f"WebSocket at {ws_url} accepted text frame with null bytes.",
        'solution': 'Reject text frames containing null bytes.',
        'affected_url': ws_url,
        'impact': 'Null bytes can lead to string termination issues.'
    } if response else None

def test_binary_as_text(ws_url):
    """Test binary data as text frame (Vuln #35)."""
    frame = struct.pack("!B", 0x81) + struct.pack("!B", 0x04) + b"\x00\xFF\x00\xFF"
    response = send_custom_frame(ws_url, frame)
    return {
        'name': 'Binary as Text',
        'risk': 'Medium',
        'description': f"WebSocket at {ws_url} accepted binary data in text frame.",
        'solution': 'Validate text frames for valid UTF-8 content.',
        'affected_url': ws_url,
        'impact': 'Binary data in text frames can cause parsing errors.'
    } if response else None

def test_text_as_binary(ws_url):
    """Test text data as binary frame (Vuln #36)."""
    frame = struct.pack("!B", 0x82) + struct.pack("!B", 0x04) + b"text"
    response = send_custom_frame(ws_url, frame)
    return {
        'name': 'Text as Binary',
        'risk': 'Low',
        'description': f"WebSocket at {ws_url} accepted text data in binary frame.",
        'solution': 'Ensure binary frames are processed correctly.',
        'affected_url': ws_url,
        'impact': 'Incorrect frame type can cause application logic errors.'
    } if response else None

def test_invalid_close_code(ws_url):
    """Test invalid close code (Vuln #37)."""
    frame = struct.pack("!B", 0x88) + struct.pack("!B", 0x04) + struct.pack("!H", 999) + b"OK"
    response = send_custom_frame(ws_url, frame)
    return {
        'name': 'Invalid Close Code',
        'risk': 'Medium',
        'description': f"WebSocket at {ws_url} accepted close frame with invalid code 999.",
        'solution': 'Validate close codes per RFC 6455 (1000-4999).',
        'affected_url': ws_url,
        'impact': 'Invalid close codes can cause protocol errors.'
    } if response else None

def test_early_close_frame(ws_url):
    """Test early close frame (Vuln #38)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, timeout=5)
        frame = struct.pack("!B", 0x88) + struct.pack("!B", 0x02) + struct.pack("!H", 1000)
        ws.send_binary(frame)
        response = ws.recv()
        ws.close()
        return {
            'name': 'Early Close Frame',
            'risk': 'Medium',
            'description': f"WebSocket at {ws_url} accepted early close frame.",
            'solution': 'Handle early close frames gracefully.',
            'affected_url': ws_url,
            'impact': 'Early close frames can disrupt connection state.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"Early close frame test failed for {ws_url}: {e}", "yellow"))
        return None

def test_no_close_frame(ws_url):
    """Test no close frame (Vuln #39)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, timeout=5)
        ws.sock.close()
        time.sleep(1)
        ws = websocket.WebSocket()
        ws.connect(ws_url, timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
            'name': 'No Close Frame',
            'risk': 'Medium',
            'description': f"WebSocket at {ws_url} handled abrupt closure without issues.",
            'solution': 'Ensure server handles abrupt closures gracefully.',
            'affected_url': ws_url,
            'impact': 'Abrupt closures can leave server resources open.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"No close frame test failed for {ws_url}: {e}", "yellow"))
        return None

def test_long_close_reason(ws_url):
    """Test long close reason (Vuln #40)."""
    reason = "A" * 123
    frame = struct.pack("!B", 0x88) + struct.pack("!B", len(reason) + 2) + struct.pack("!H", 1000) + reason.encode()
    response = send_custom_frame(ws_url, frame)
    return {
        'name': 'Long Close Reason',
        'risk': 'Medium',
        'description': f"WebSocket at {ws_url} accepted close frame with long reason (123 bytes).",
        'solution': 'Limit close reason length to prevent resource exhaustion.',
        'affected_url': ws_url,
        'impact': 'Long close reasons can cause server overload.'
    } if response else None

def test_no_session_cookie(ws_url):
    """Test if WebSocket accepts connections without a session cookie (Vuln #41)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
            'name': 'No Session Cookie',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepts connections without a session cookie.",
            'solution': 'Require valid session cookies for WebSocket connections.',
            'affected_url': ws_url,
            'impact': 'Unauthenticated users can access WebSocket sessions.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"No session cookie test failed for {ws_url}: {e}", "yellow"))
        return None

def test_expired_cookie(ws_url):
    """Test if WebSocket accepts connections with an expired session cookie (Vuln #42)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, cookie="session=expired_cookie_value; Max-Age=-1", timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
            'name': 'Expired Cookie',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepts connections with an expired session cookie.",
            'solution': 'Validate cookie expiration on the server side.',
            'affected_url': ws_url,
            'impact': 'Expired sessions can be exploited for unauthorized access.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"Expired cookie test failed for {ws_url}: {e}", "yellow"))
        return None

def test_fake_token(ws_url):
    """Test if WebSocket accepts connections with a fake authentication token (Vuln #43)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, header=["Authorization: Bearer fake_token_123"], timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
            'name': 'Fake Token',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepts connections with a fake authentication token.",
            'solution': 'Implement robust token validation (e.g., JWT verification).',
            'affected_url': ws_url,
            'impact': 'Fake tokens can allow unauthorized access to WebSocket data.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"Fake token test failed for {ws_url}: {e}", "yellow"))
        return None

def test_http_session_reuse(ws_url):
    """Test if HTTP session cookie is reused for WebSocket without revalidation (Vuln #44)."""
    try:
        parsed_url = urlparse(ws_url)
        http_url = f"{'https' if parsed_url.scheme == 'wss' else 'http'}://{parsed_url.netloc}/"
        session = requests.Session()
        response = session.get(http_url, timeout=5)
        cookies = session.cookies.get_dict()
        if not cookies:
            return None
        cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        ws = websocket.WebSocket()
        ws.connect(ws_url, cookie=cookie_str, timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
            'name': 'HTTP Session Reuse',
            'risk': 'Medium',
            'description': f"WebSocket at {ws_url} reuses HTTP session cookie without revalidation.",
            'solution': 'Revalidate session cookies for WebSocket connections.',
            'affected_url': ws_url,
            'impact': 'Reused sessions can be exploited if HTTP session is compromised.'
        }
    except (websocket.WebSocketException, requests.RequestException) as e:
        print(colored(f"HTTP session reuse test failed for {ws_url}: {e}", "yellow"))
        return None

def test_stale_session_reconnect(ws_url):
    """Test if WebSocket allows reconnection with a stale session (Vuln #45)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, cookie="session=stale_session_id_123", timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()
        time.sleep(1)
        ws = websocket.WebSocket()
        ws.connect(ws_url, cookie="session=stale_session_id_123", timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
            'name': 'Stale Session Reconnect',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} allows reconnection with a stale session.",
            'solution': 'Invalidate stale sessions and require fresh authentication.',
            'affected_url': ws_url,
            'impact': 'Stale sessions can be reused by attackers for unauthorized access.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"Stale session reconnect test failed for {ws_url}: {e}", "yellow"))
        return None

def test_cross_site_cookie_hijack(ws_url):
    """Test if WebSocket accepts cookies from a different origin (Vuln #46)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, cookie="session=cross_site_session; Domain=malicious.com", origin="http://malicious.com", timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
            'name': 'Cross-Site Cookie Hijack',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepts cookies from a different origin.",
            'solution': 'Set SameSite=Strict on cookies and validate origin.',
            'affected_url': ws_url,
            'impact': 'Attackers can hijack sessions via cross-site requests.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"Cross-site cookie hijack test failed for {ws_url}: {e}", "yellow"))
        return None

def test_invalid_subprotocol(ws_url):
    """Test if WebSocket accepts an invalid subprotocol (Vuln #47)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, subprotocols=["invalid..protocol"], timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
            'name': 'Invalid Subprotocol',
            'risk': 'Medium',
            'description': f"WebSocket at {ws_url} accepts invalid subprotocol 'invalid..protocol'.",
            'solution': 'Validate subprotocol names against a whitelist.',
            'affected_url': ws_url,
            'impact': 'Invalid subprotocols can lead to unexpected server behavior.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"Invalid subprotocol test failed for {ws_url}: {e}", "yellow"))
        return None

def test_conflicting_subprotocols(ws_url):
    """Test if WebSocket accepts conflicting subprotocols (Vuln #48)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, subprotocols=["protocol1,protocol2"], timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
            'name': 'Conflicting Subprotocols',
            'risk': 'Medium',
            'description': f"WebSocket at {ws_url} accepts conflicting subprotocols 'protocol1,protocol2'.",
            'solution': 'Reject requests with multiple or malformed subprotocols.',
            'affected_url': ws_url,
            'impact': 'Conflicting subprotocols can cause protocol confusion.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"Conflicting subprotocols test failed for {ws_url}: {e}", "yellow"))
        return None

def test_unaccepted_subprotocol(ws_url):
    """Test if WebSocket accepts an unadvertised subprotocol (Vuln #49)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, subprotocols=["unadvertised_protocol"], timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
            'name': 'Unaccepted Subprotocol',
            'risk': 'Medium',
            'description': f"WebSocket at {ws_url} accepts unadvertised subprotocol 'unadvertised_protocol'.",
            'solution': 'Only accept subprotocols advertised by the server.',
            'affected_url': ws_url,
            'impact': 'Unadvertised subprotocols can bypass protocol restrictions.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"Unaccepted subprotocol test failed for {ws_url}: {e}", "yellow"))
        return None

def test_fake_extension(host, port, path="/"):
    """Test if WebSocket accepts a fake extension (Vuln #50)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Extensions: fake-extension\r
Sec-WebSocket-Version: 13\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Fake Extension',
        'risk': 'Medium',
        'description': f"Server at {host}:{port} accepted fake extension 'fake-extension'.",
        'solution': 'Validate Sec-WebSocket-Extensions against supported extensions.',
        'affected_host': f"{host}:{port}",
        'impact': 'Fake extensions can lead to unexpected server behavior.'
    } if "101 Switching Protocols" in response else None

def test_conflicting_extensions(host, port, path="/"):
    """Test if WebSocket accepts conflicting extensions (Vuln #51)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Extensions: permessage-deflate; permessage-deflate\r
Sec-WebSocket-Version: 13\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Conflicting Extensions',
        'risk': 'Medium',
        'description': f"Server at {host}:{port} accepted conflicting extensions.",
        'solution': 'Reject requests with duplicate or conflicting extensions.',
        'affected_host': f"{host}:{port}",
        'impact': 'Conflicting extensions can cause protocol errors.'
    } if "101 Switching Protocols" in response else None

def test_spoofed_connection_header(host, port, path="/"):
    """Test if WebSocket accepts a spoofed Connection header (Vuln #52)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Connection: Keep-Alive\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Version: 13\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Spoofed Connection Header',
        'risk': 'High',
        'description': f"Server at {host}:{port} accepted spoofed Connection header 'Keep-Alive'.",
        'solution': 'Require Connection: Upgrade header for WebSocket handshake.',
        'affected_host': f"{host}:{port}",
        'impact': 'Spoofed headers can bypass handshake validation.'
    } if "101 Switching Protocols" in response else None

def test_http_1_0_downgrade(host, port, path="/"):
    """Test if WebSocket accepts HTTP/1.0 handshake (Vuln #53)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.0\r\n
Host: {host}\r\n
Upgrade: websocket\r\n
Connection: Upgrade\r\n
Sec-WebSocket-Key: {key}\r\n
Sec-WebSocket-Version: 13\r\n
\r\n
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'HTTP/1.0 Downgrade',
        'risk': 'High',
        'description': f"Server at {host}:{port} accepted HTTP/1.0 handshake.",
        'solution': 'Require HTTP/1.1 or higher for WebSocket handshakes.',
        'affected_host': f"{host}:{port}",
        'impact': 'HTTP/1.0 lacks modern security features.'
    } if "101 Switching Protocols" in response else None

def test_tls_downgrade(ws_url):
    """Test if WebSocket allows TLS downgrade (Vuln #54)."""
    if not ws_url.startswith("wss://"):
        return None
    try:
        parsed_url = urlparse(ws_url)
        host = parsed_url.hostname
        port = parsed_url.port or 443
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                response = ssock.recv(4096).decode()
                return {
                    'name': 'TLS Downgrade',
                    'risk': 'High',
                    'description': f"Server at {host}:{port} allows TLS 1.0 connection.",
                    'solution': 'Disable TLS 1.0/1.1; enforce TLS 1.2 or higher.',
                    'affected_host': f"{host}:{port}",
                    'impact': 'Weak TLS versions are vulnerable to attacks.'
                }
    except (socket.error, ssl.SSLError) as e:
        print(colored(f"TLS downgrade test failed for {ws_url}: {e}", "yellow"))
        return None

def test_weak_tls_ciphers(ws_url):
    """Test if WebSocket supports weak TLS ciphers (Vuln #55)."""
    if not ws_url.startswith("wss://"):
        return None
    try:
        parsed_url = urlparse(ws_url)
        host = parsed_url.hostname
        port = parsed_url.port or 443
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.set_ciphers("RC4-MD5")
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                response = ssock.recv(4096).decode()
                return {
                    'name': 'Weak TLS Ciphers',
                    'risk': 'High',
                    'description': f"Server at {host}:{port} supports weak cipher RC4-MD5.",
                    'solution': 'Disable weak ciphers; use strong ciphers like AES-GCM.',
                    'affected_host': f"{host}:{port}",
                    'impact': 'Weak ciphers are vulnerable to attacks.'
                }
    except (socket.error, ssl.SSLError) as e:
        print(colored(f"Weak TLS ciphers test failed for {ws_url}: {e}", "yellow"))
        return None

def test_certificate_mismatch(ws_url):
    """Test if WebSocket server's certificate matches the hostname (Vuln #56)."""
    if not ws_url.startswith("wss://"):
        return None
    try:
        parsed_url = urlparse(ws_url)
        host = parsed_url.hostname
        port = parsed_url.port or 443
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname="mismatch.example.com") as ssock:
                pass
        return {
            'name': 'Certificate Mismatch',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted connection with mismatched hostname.",
            'solution': 'Ensure certificate hostname matches the server domain.',
            'affected_host': f"{host}:{port}",
            'impact': 'Mismatched certificates enable man-in-the-middle attacks.'
        }
    except ssl.SSLError as e:
        print(colored(f"Certificate mismatch test failed for {ws_url}: {e}", "yellow"))
        return None
    except socket.error as e:
        print(colored(f"Certificate mismatch test failed for {ws_url}: {e}", "yellow"))
        return None

def test_connection_flood(ws_url):
    """Test server resilience to connection flood (Vuln #57)."""
    try:
        connections = []
        for _ in range(10):
            ws = websocket.WebSocket()
            ws.connect(ws_url, timeout=5)
            connections.append(ws)
        for ws in connections:
            ws.send("test")
            response = ws.recv()
        for ws in connections:
            ws.close()
        return {
            'name': 'Connection Flood',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepts multiple connections without restriction.",
            'solution': 'Implement connection rate limiting.',
            'affected_url': ws_url,
            'impact': 'Connection floods can overwhelm server resources.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"Connection flood test failed for {ws_url}: {e}", "yellow"))
        return None

def test_oversized_message(ws_url):
    """Test server handling of oversized messages (Vuln #58)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, timeout=5)
        large_message = "A" * 1000000
        ws.send(large_message)
        response = ws.recv()
        ws.close()
        return {
            'name': 'Oversized Message',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepts oversized message (1MB).",
            'solution': 'Enforce maximum message size limits.',
            'affected_url': ws_url,
            'impact': 'Large messages can cause memory exhaustion.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"Oversized message test failed for {ws_url}: {e}", "yellow"))
        return None

def test_max_connections(ws_url):
    """Test if server enforces maximum connections per client (Vuln #59)."""
    try:
        connections = []
        for _ in range(20):
            ws = websocket.WebSocket()
            ws.connect(ws_url, timeout=5)
            connections.append(ws)
        for ws in connections:
            ws.close()
        return {
            'name': 'Max Connections',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} allows excessive connections (20).",
            'solution': 'Set a maximum connection limit per client IP.',
            'affected_url': ws_url,
            'impact': 'Excessive connections can lead to denial-of-service.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"Max connections test failed for {ws_url}: {e}", "yellow"))
        return None

def test_idle_timeout_abuse(ws_url):
    """Test if server enforces idle timeout (Vuln #60)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, timeout=5)
        time.sleep(60)
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
            'name': 'Idle Timeout Abuse',
            'risk': 'Medium',
            'description': f"WebSocket at {ws_url} allows idle connection for 60 seconds.",
            'solution': 'Implement idle timeout to close inactive connections.',
            'affected_url': ws_url,
            'impact': 'Idle connections consume server resources.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"Idle timeout test failed for {ws_url}: {e}", "yellow"))
        return None

def test_no_compression_negotiation(host, port, path="/"):
    """Test if server accepts no compression negotiation (Vuln #61)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Version: 13\r
\r
"""
    response = send_raw_handshake(host, port, req)
    if "101 Switching Protocols" in response and "permessage-deflate" not in response.lower():
        return {
            'name': 'No Compression Negotiation',
            'risk': 'Low',
            'description': f"Server at {host}:{port} does not negotiate compression.",
            'solution': 'Support permessage-deflate for efficient data transfer.',
            'affected_host': f"{host}:{port}",
            'impact': 'Lack of compression increases bandwidth usage.'
        }
    return None

def test_high_compression_ratio(ws_url):
    """Test server handling of high compression ratio data (Vuln #62)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, timeout=5)
        compressible_data = "A" * 100000
        ws.send(compressible_data)
        response = ws.recv()
        ws.close()
        return {
            'name': 'High Compression Ratio',
            'risk': 'Medium',
            'description': f"WebSocket at {ws_url} accepts highly compressible data (100KB).",
            'solution': 'Limit compression ratios to prevent DoS.',
            'affected_url': ws_url,
            'impact': 'High compression can amplify DoS attacks.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"High compression test failed for {ws_url}: {e}", "yellow"))
        return None

def test_resource_leak(ws_url):
    """Test for resource leaks (Vuln #63)."""
    try:
        for _ in range(50):
            ws = websocket.WebSocket()
            ws.connect(ws_url, timeout=3)
            ws.close()
        ws = websocket.WebSocket()
        ws.connect(ws_url, timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
            'name': 'Resource Leak',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} handles rapid connection open/close.",
            'solution': 'Ensure proper resource cleanup after connections.',
            'affected_url': ws_url,
            'impact': 'Resource leaks can degrade server performance.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"Resource leak test failed for {ws_url}: {e}", "yellow"))
        return None

def test_no_timeout_policy(host, port, path="/"):
    """Test if server lacks handshake timeout (Vuln #64)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        if port == 443:
            s = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLS)
        s.connect((host, port))
        s.send(b"GET " + path.encode() + b" HTTP/1.1\r\nHost: " + host.encode() + b"\r\n")
        time.sleep(30)
        response = s.recv(4096).decode()
        s.close()
        if response:
            return {
                'name': 'No Timeout Policy',
                'risk': 'Medium',
                'description': f"Server at {host}:{port} lacks handshake timeout.",
                'solution': 'Implement timeout for incomplete handshakes.',
                'affected_host': f"{host}:{port}",
                'impact': 'Long-held connections consume resources.'
            }
        return None
    except socket.error as e:
        print(colored(f"No timeout policy test failed for {host}:{port}: {e}", "yellow"))
        return None

def test_missing_cors_headers(ws_url):
    """Test for missing CORS headers (Vuln #65)."""
    try:
        parsed_url = urlparse(ws_url)
        http_url = f"{'https' if parsed_url.scheme == 'wss' else 'http'}://{parsed_url.netloc}/"
        response = requests.options(http_url, headers={"Origin": "http://malicious.com"}, timeout=5)
        cors_headers = ["Access-Control-Allow-Origin", "Access-Control-Allow-Methods"]
        missing = [h for h in cors_headers if h not in response.headers]
        if missing:
            return {
                'name': 'Missing CORS Headers',
                'risk': 'Moderate',
                'description': f"Server at {http_url} lacks CORS headers: {', '.join(missing)}.",
                'solution': 'Configure appropriate CORS headers.',
                'affected_host': http_url,
                'impact': 'Missing CORS can allow unauthorized cross-origin access.'
            }
        return None
    except requests.RequestException as e:
        print(colored(f"Missing CORS test failed for {ws_url}: {e}", "yellow"))
        return None

def test_cross_origin_iframe(ws_url):
    """Test cross-origin iframe connections (Vuln #66)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, origin="http://malicious.com", timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
            'name': 'Cross-Origin Iframe',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepts cross-origin iframe connections.",
            'solution': 'Validate Origin header; enforce X-Frame-Options: DENY.',
            'affected_url': ws_url,
            'impact': 'Cross-origin iframes can enable clickjacking.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"Cross-origin iframe test failed for {ws_url}: {e}", "yellow"))
        return None

def test_mixed_content(ws_url):
    """Test mixed content usage (Vuln #67)."""
    if not ws_url.startswith("wss://"):
        return None
    try:
        parsed_url = urlparse(ws_url)
        http_url = f"http://{parsed_url.netloc}/"
        response = requests.get(http_url, timeout=5)
        if "wss://" in response.text:
            return {
                'name': 'Mixed Content',
                'risk': 'High',
                'description': f"WebSocket at {ws_url} referenced in HTTP context at {http_url}.",
                'solution': 'Use HTTPS for all pages referencing wss://.',
                'affected_url': http_url,
                'impact': 'Mixed content can be intercepted by attackers.'
            }
        return None
    except requests.RequestException as e:
        print(colored(f"Mixed content test failed for {ws_url}: {e}", "yellow"))
        return None

def test_postmessage_abuse(ws_url):
    """Test if WebSocket is vulnerable to postMessage abuse (Vuln #68)."""
    try:
        parsed_url = urlparse(ws_url)
        http_url = f"{'https' if parsed_url.scheme == 'wss' else 'http'}://{parsed_url.netloc}/"
        response = requests.get(http_url, timeout=5)
        if "postMessage" in response.text.lower():
            return {
                'name': 'PostMessage Abuse',
                'risk': 'High',
                'description': f"WebSocket at {ws_url} may be vulnerable to postMessage abuse via {http_url}.",
                'solution': 'Restrict postMessage origins and validate message sources.',
                'affected_url': ws_url,
                'impact': 'PostMessage abuse can allow unauthorized data injection.'
            }
        return None
    except requests.RequestException as e:
        print(colored(f"PostMessage abuse test failed for {ws_url}: {e}", "yellow"))
        return None

def test_spoofed_url(ws_url):
    """Test if WebSocket accepts spoofed URLs (Vuln #69)."""
    try:
        parsed_url = urlparse(ws_url)
        spoofed_url = f"{parsed_url.scheme}://malicious.com{parsed_url.path}"
        ws = websocket.WebSocket()
        ws.connect(ws_url, origin="http://malicious.com", timeout=5)
        ws.send(f"GET {spoofed_url}")
        response = ws.recv()
        ws.close()
        return {
            'name': 'Spoofed URL',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepts connections with spoofed URL {spoofed_url}.",
            'solution': 'Validate WebSocket URLs and origins.',
            'affected_url': ws_url,
            'impact': 'Spoofed URLs can lead to phishing or data leaks.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"Spoofed URL test failed for {ws_url}: {e}", "yellow"))
        return None

def test_error_message_leak(ws_url):
    """Test if WebSocket leaks sensitive information in error messages (Vuln #70)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, timeout=5)
        ws.send("INVALID_COMMAND")
        response = ws.recv()
        ws.close()
        if any(keyword in response.lower() for keyword in ["stack trace", "exception", "error at", "internal server error"]):
            return {
                'name': 'Error Message Leak',
                'risk': 'Medium',
                'description': f"WebSocket at {ws_url} leaks sensitive information in error messages.",
                'solution': 'Sanitize error messages to avoid leaking sensitive data.',
                'affected_url': ws_url,
                'impact': 'Error leaks can expose server details to attackers.'
            }
        return None
    except websocket.WebSocketException as e:
        print(colored(f"Error message leak test failed for {ws_url}: {e}", "yellow"))
        return None

def test_server_disclosure(host, port, path="/"):
    """Test if server discloses version or software details (Vuln #71)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Version: 13\r
\r
"""
    response = send_raw_handshake(host, port, req)
    server_headers = ["Server", "X-Powered-By"]
    for header in server_headers:
        for line in response.split("\r\n"):
            if header.lower() in line.lower() and any(keyword in line.lower() for keyword in ["apache", "nginx", "iis", "version"]):
                return {
                    'name': 'Server Disclosure',
                    'risk': 'Medium',
                    'description': f"Server at {host}:{port} discloses software details in {header} header.",
                    'solution': 'Remove or obfuscate Server and X-Powered-By headers.',
                    'affected_host': f"{host}:{port}",
                    'impact': 'Server details can aid attackers in targeted exploits.'
                }
    return None

def test_invalid_content_type(host, port, path="/"):
    """Test if server accepts invalid Content-Type headers (Vuln #72)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Version: 13\r
Content-Type: application/invalid\r
\r
"""
    response = send_raw_handshake(host, port, req)
    return {
        'name': 'Invalid Content-Type',
        'risk': 'Medium',
        'description': f"Server at {host}:{port} accepted handshake with invalid Content-Type.",
        'solution': 'Ignore or validate Content-Type headers for WebSocket handshakes.',
        'affected_host': f"{host}:{port}",
        'impact': 'Invalid Content-Type can lead to misinterpretation of requests.'
    } if "101 Switching Protocols" in response else None

def test_missing_security_headers(host, port, path="/"):
    """Test if server lacks security headers (Vuln #73)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Version: 13\r
\r
"""
    response = send_raw_handshake(host, port, req)
    security_headers = ["Content-Security-Policy", "X-Content-Type-Options", "X-XSS-Protection"]
    missing = []
    for header in security_headers:
        if not any(header.lower() in line.lower() for line in response.split("\r\n")):
            missing.append(header)
    if missing:
        return {
            'name': 'Missing Security Headers',
            'risk': 'Medium',
            'description': f"Server at {host}:{port} lacks security headers: {', '.join(missing)}.",
            'solution': 'Implement security headers like CSP, X-Content-Type-Options, and X-XSS-Protection.',
            'affected_host': f"{host}:{port}",
            'impact': 'Missing headers increase risk of XSS and other client-side attacks.'
        }
    return None

def test_url_path_traversal(ws_url):
    """Test for URL path traversal vulnerabilities (Vuln #74)."""
    try:
        parsed_url = urlparse(ws_url)
        host = parsed_url.hostname
        port = parsed_url.port or (443 if parsed_url.scheme == 'wss' else 80)
        paths = [
            "/../../etc/passwd",
            "/../secret.txt",
            "/%2e%2e/%2e%2e/config",
        ]
        for path in paths:
            key = b64encode(b"1234567890123456").decode()
            req = f"""GET {path} HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Version: 13\r
\r
"""
            response = send_raw_handshake(host, port, req)
            if "101 Switching Protocols" in response or any(keyword in response.lower() for keyword in ["root", "admin", "password"]):
                return {
                    'name': 'URL Path Traversal',
                    'risk': 'High',
                    'description': f"WebSocket at {ws_url} is vulnerable to path traversal with path {path}.",
                    'solution': 'Sanitize and validate URL paths to prevent directory traversal.',
                    'affected_url': ws_url,
                    'impact': 'Path traversal can expose sensitive server files.'
                }
        return None
    except socket.error as e:
        print(colored(f"URL path traversal test failed for {ws_url}: {e}", "yellow"))
        return None

def test_query_parameter_flood(ws_url):
    """Test for query parameter flood vulnerabilities (Vuln #75)."""
    try:
        parsed_url = urlparse(ws_url)
        host = parsed_url.hostname
        port = parsed_url.port or (443 if parsed_url.scheme == 'wss' else 80)
        path = parsed_url.path or "/"
        params = "&".join([f"param{i}={''.join(random.choices(string.ascii_letters, k=10))}" for i in range(1000)])
        query_url = f"{path}?{params}"
        key = b64encode(b"1234567890123456").decode()
        req = f"""GET {query_url} HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Version: 13\r
\r
"""
        response = send_raw_handshake(host, port, req)
        if "101 Switching Protocols" in response:
            return {
                'name': 'Query Parameter Flood',
                'risk': 'Medium',
                'description': f"WebSocket at {ws_url} accepts handshake with 1000 query parameters.",
                'solution': 'Limit the number and size of query parameters in WebSocket requests.',
                'affected_url': ws_url,
                'impact': 'Excessive query parameters can cause server resource exhaustion.'
            }
        return None
    except socket.error as e:
        print(colored(f"Query parameter flood test failed for {ws_url}: {e}", "yellow"))
        return None
    
def perform_websocket_tests(websocket_urls, payloads):
    """Perform WebSocket security tests."""
    vulnerabilities = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        # 1️⃣ Test Origin Check
        origin_results = executor.map(test_origin_check, websocket_urls)
        vulnerabilities.extend([v for v in origin_results if v])

        # 2️⃣ Test Authentication
        auth_results = executor.map(test_authentication, websocket_urls)
        vulnerabilities.extend([v for v in auth_results if v])

        # 3️⃣ Protocol Fuzzing
        fuzz_results = []
        for ws_url in websocket_urls:
            fuzz_results.extend(executor.map(lambda p: test_fuzzing(ws_url, p), payloads))
        vulnerabilities.extend([v for v in fuzz_results if v])

        # 4️⃣ Handshake & HTTP Request Tests (Vuln #1-22, excluding case-sensitive headers #10)
        handshake_results = []
        for ws_url in websocket_urls:
             parsed_url = urlparse(ws_url)
             host = parsed_url.hostname
             port = parsed_url.port or (443 if parsed_url.scheme == 'wss' else 80)
             path = parsed_url.path or "/"

             handshake_tests = [
                 test_omit_sec_websocket_key,  # 1
                 test_non_base64_sec_websocket_key,  # 2
                 test_oversized_sec_websocket_key,  # 3
                 test_duplicate_sec_websocket_key,  # 4
                 test_missing_sec_websocket_version,  # 5
                 test_invalid_sec_websocket_version,  # 6
                 test_conflicting_sec_websocket_version,  # 7
                 test_wrong_upgrade_header,  # 8
                 test_missing_connection_header,  # 9
                 test_case_sensitive_headers,  # 10
                 test_non_get_method,  # 11
                 test_fake_http_status,  # 12
                 # test_wrong_sec_websocket_accept,  # 13 (Commented out because it's not defined)
                 test_oversized_headers,  # 14
                 test_missing_host_header,  # 15
                 test_fake_host_header,  # 16
                 test_multiple_host_headers,  # 17
                 test_long_url_path,  # 18
                 test_unicode_url,  # 19
                 test_http_0_9_handshake,  # 20
             ]

        #     for test_func in handshake_tests:
        #         result = test_func(host, port, path)
        #         if result:
        #             vulnerabilities.append(result)

        #     # Tests requiring ws_url
        #     ws_handshake_tests = [
        #         test_invalid_port,  # 21
        #         test_non_ws_scheme,  # 22
        #     ]

        #     for test_func in ws_handshake_tests:
        #         result = test_func(ws_url)
        #         if result:
        #             vulnerabilities.append(result)

        # # 5️⃣ Payload Handling & Fragmentation Tests (Vuln #23-40)
        # payload_results = []
        # for ws_url in websocket_urls:
        #     payload_tests = [
        #         test_undefined_opcode,  # 23
        #         test_reserved_opcode,  # 24
        #         test_zero_length_fragment,  # 25
        #         test_invalid_payload_length,  # 26
        #         test_negative_payload_length,  # 27
        #         test_mismatched_payload,  # 28
        #         test_invalid_masking_key,  # 29
        #         test_unmasked_client_frame,  # 30
        #         test_invalid_rsv_bits,  # 31
        #         test_oversized_control_frame,  # 32
        #         test_non_utf8_text,  # 33
        #         test_null_bytes_in_text,  # 34
        #         test_binary_as_text,  # 35
        #         test_text_as_binary,  # 36
        #         test_invalid_close_code,  # 37
        #         test_early_close_frame,  # 38
        #         test_no_close_frame,  # 39
        #         test_long_close_reason,  # 40
        #     ]

        #     for test_func in payload_tests:
        #         result = test_func(ws_url)
        #         if result:
        #             vulnerabilities.append(result)

        # # 6️⃣ Authentication & Session Management Tests (Vuln #41-46)
        # auth_session_results = []
        # for ws_url in websocket_urls:
        #     auth_session_tests = [
        #         test_no_session_cookie,  # 41
        #         test_expired_cookie,  # 42
        #         test_fake_token,  # 43
        #         test_http_session_reuse,  # 44
        #         test_stale_session_reconnect,  # 45
        #         test_cross_site_cookie_hijack,  # 46
        #     ]

        #     for test_func in auth_session_tests:
        #         result = test_func(ws_url)
        #         if result:
        #             vulnerabilities.append(result)

        # # 7️⃣ Subprotocol & Extension Tests (Vuln #47-51)
        # subprotocol_results = []
        # for ws_url in websocket_urls:
        #     parsed_url = urlparse(ws_url)
        #     host = parsed_url.hostname
        #     port = parsed_url.port or (443 if parsed_url.scheme == 'wss' else 80)
        #     path = parsed_url.path or "/"

        #     subprotocol_tests = [
        #         test_fake_extension,  # 50
        #         test_conflicting_extensions,  # 51
        #     ]

        #     for test_func in subprotocol_tests:
        #         result = test_func(host, port, path)
        #         if result:
        #             vulnerabilities.append(result)

        #     ws_subprotocol_tests = [
        #         test_invalid_subprotocol,  # 47
        #         test_conflicting_subprotocols,  # 48
        #         test_unaccepted_subprotocol,  # 49
        #     ]

        #     for test_func in ws_subprotocol_tests:
        #         result = test_func(ws_url)
        #         if result:
        #             vulnerabilities.append(result)

        # # 8️⃣ Security & Encryption Tests (Vuln #52-56)
        # security_results = []
        # for ws_url in websocket_urls:
        #     parsed_url = urlparse(ws_url)
        #     host = parsed_url.hostname
        #     port = parsed_url.port or (443 if parsed_url.scheme == 'wss' else 80)
        #     path = parsed_url.path or "/"

        #     security_tests = [
        #         test_spoofed_connection_header,  # 52
        #         test_http_1_0_downgrade,  # 53
        #     ]

        #     for test_func in security_tests:
        #         result = test_func(host, port, path)
        #         if result:
        #             vulnerabilities.append(result)

        #     ws_security_tests = [
        #         test_tls_downgrade,  # 54
        #         test_weak_tls_ciphers,  # 55
        #         test_certificate_mismatch,  # 56
        #     ]

        #     for test_func in ws_security_tests:
        #         result = test_func(ws_url)
        #         if result:
        #             vulnerabilities.append(result)

        # # 9️⃣ DoS & Resource Management Tests (Vuln #57-64)
        # dos_results = []
        # for ws_url in websocket_urls:
        #     parsed_url = urlparse(ws_url)
        #     host = parsed_url.hostname
        #     port = parsed_url.port or (443 if parsed_url.scheme == 'wss' else 80)
        #     path = parsed_url.path or "/"

        #     dos_tests = [
        #         test_no_compression_negotiation,  # 61
        #         test_no_timeout_policy,  # 64
        #     ]

        #     for test_func in dos_tests:
        #         result = test_func(host, port, path)
        #         if result:
        #             vulnerabilities.append(result)

        #     ws_dos_tests = [
        #         test_connection_flood,  # 57
        #         test_oversized_message,  # 58
        #         test_max_connections,  # 59
        #         test_idle_timeout_abuse,  # 60
        #         test_high_compression_ratio,  # 62
        #         test_resource_leak,  # 63
        #     ]

        #     for test_func in ws_dos_tests:
        #         result = test_func(ws_url)
        #         if result:
        #             vulnerabilities.append(result)

        # # 🔟 Cross-Origin & Mixed Content Tests (Vuln #65-69)
        # cross_origin_results = []
        # for ws_url in websocket_urls:
        #     cross_origin_tests = [
        #         test_missing_cors_headers,  # 65
        #         test_cross_origin_iframe,  # 66
        #         test_mixed_content,  # 67
        #         test_postmessage_abuse,  # 68
        #         test_spoofed_url,  # 69
        #     ]

        #     for test_func in cross_origin_tests:
        #         result = test_func(ws_url)
        #         if result:
        #             vulnerabilities.append(result)

        # # 1️⃣1️⃣ Other Vulnerabilities Tests (Vuln #70-75)
        # other_results = []
        # for ws_url in websocket_urls:
        #     parsed_url = urlparse(ws_url)
        #     host = parsed_url.hostname
        #     port = parsed_url.port or (443 if parsed_url.scheme == 'wss' else 80)
        #     path = parsed_url.path or "/"

        #     other_tests = [
        #         test_server_disclosure,  # 71
        #         test_invalid_content_type,  # 72
        #         test_missing_security_headers,  # 73
        #     ]

        #     for test_func in other_tests:
        #         result = test_func(host, port, path)
        #         if result:
        #             vulnerabilities.append(result)

        #     ws_other_tests = [
        #         test_error_message_leak,  # 70
        #         test_url_path_traversal,  # 74
        #         test_query_parameter_flood,  # 75
        #     ]

        #     for test_func in ws_other_tests:
        #         result = test_func(ws_url)
        #         if result:
        #             vulnerabilities.append(result)

    return vulnerabilities