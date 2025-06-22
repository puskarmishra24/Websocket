import os
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import time
import websocket
import logging
from base64 import b64encode
import socket
import ssl
import http.client
from urllib.parse import urlparse
from termcolor import colored
import struct
import random
import string
import requests
from hashlib import sha1

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_payload(file_name):
    """Load payloads from the specified file."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(base_dir, file_name)
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Payload file not found: {file_path}")
    with open(file_path, "r", encoding='utf-8', errors='ignore') as file:
        return [line.strip() for line in file.readlines() if line.strip()]

def attack_website(websocket_urls):
    """Main function to handle WebSocket attack logic."""
    websocket_payloads = load_payload("websocket_payload.txt")
    print(colored("Starting WebSocket tests...", "yellow"))
    vulnerabilities = perform_websocket_tests(websocket_urls, websocket_payloads)
    return vulnerabilities

def send_raw_handshake(host, port, request_headers, scheme="ws", timeout=10):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

        if scheme == "wss":
            ssl_context = ssl.create_default_context()
            s = ssl_context.wrap_socket(s, server_hostname=host)

        logging.info(f"Connecting to {host}:{port}...")
        s.connect((host, port))
        logging.info(f"Sending request:\n{request_headers}")
        s.send(request_headers.encode())

        response = b""
        while b"\r\n\r\n" not in response:
            try:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            except socket.timeout:
                break

        # Truncate response after header
        header_end = response.find(b"\r\n\r\n")
        if header_end != -1:
            response = response[:header_end + 4]  # Include the \r\n\r\n

        
        logging.info(f"Received response:\n{response.decode(errors='ignore')}")
        return response.decode(errors="ignore")

    except Exception as e:
        logging.info(f"Handshake failed for {host}:{port}: {e}")
        return None
    finally:
        try:
            s.close()
        except:
            pass

def test_working_websocket(link):
    """Test non-base64 Sec-WebSocket-Key header (Vuln #2)."""
    
    key = b64encode(b"1234567890123456").decode()
    parsed_url = urlparse(link)
    host = parsed_url.hostname
    port = parsed_url.port or (443 if parsed_url.scheme == 'wss' else 80)
    path = parsed_url.path or "/"
    scheme = parsed_url.scheme
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return None
        if "101 Switching Protocols" in response:
            return True
        
    except Exception as e:
        logging.info(f"Error in test_non_base64_sec_websocket_key for {host}:{port}: {e}")
        

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
            'type': 'Origin Check',
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
                'type': 'Authentication',
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
                    'type': 'Protocol Fuzzing',
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
    
def test_omit_sec_websocket_key(host, port, path="/", scheme="ws"):
    """Test omitting Sec-WebSocket-Key header (Vuln #1)."""
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return None
        return {
            'name': 'Omit Sec-WebSocket-Key',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted handshake without Sec-WebSocket-Key.",
            'solution': 'Require Sec-WebSocket-Key header for WebSocket handshake.',
            'affected_host': f"{host}:{port}",
            'impact': 'Bypassing handshake validation can allow unauthorized connections.'
        } if response and "101 Switching Protocols" in response else None
    except Exception as e:
        logging.info(f"Error in test_omit_sec_websocket_key for {host}:{port}: {e}")
        return None
    
def test_non_base64_sec_websocket_key(host, port, path="/", scheme="ws"):
    """Test non-base64 Sec-WebSocket-Key header (Vuln #2)."""
    
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: NotBase64!!\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme=scheme)
        if response is None:
            return None
        return {
            'name': 'Non-Base64 Sec-WebSocket-Key',
            'risk': 'Medium',
            'description': f"Server at {host}:{port} accepted non-base64 Sec-WebSocket-Key.",
            'solution': 'Validate Sec-WebSocket-Key as base64-encoded.',
            'affected_host': f"{host}:{port}",
            'impact': 'Improper key validation can lead to handshake vulnerabilities.'
        } if response and "101 Switching Protocols" in response else None
    except Exception as e:
        logging.info(f"Error in test_non_base64_sec_websocket_key for {host}:{port}: {e}")
        return None
    
def test_oversized_sec_websocket_key(host, port, path="/", scheme="ws"):
    """Test oversized Sec-WebSocket-Key header (Vuln #3)."""
    big_key = b64encode(b"A" * 1024).decode()  # 1KB key
    
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {big_key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return None
        return {
            'name': 'Oversized Sec-WebSocket-Key',
            'risk': 'Medium',
            'description': f"Server at {host}:{port} accepted oversized Sec-WebSocket-Key (1KB).",
            'solution': 'Limit Sec-WebSocket-Key size to prevent resource exhaustion.',
            'affected_host': f"{host}:{port}",
            'impact': 'Large keys can cause server resource exhaustion.'
        } if "101 Switching Protocols" in response else None
    except Exception as e:
        logging.info(f"Error in test_oversized_sec_websocket_key for {host}:{port}: {e}")
        return None
    
def test_duplicate_sec_websocket_key(host, port, path="/", scheme="ws"):
    """Test duplicate Sec-WebSocket-Key headers (Vuln #4)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r\n
Host: {host}\r\n
Upgrade: websocket\r\n
Connection: Upgrade\r\n
Sec-WebSocket-Key: {key}\r\n
Sec-WebSocket-Key: {key}duplicate\r\n
Sec-WebSocket-Version: 13\r\n
\r\n"""
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    f"Sec-WebSocket-Key: {key}duplicate\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return None
        
        return {
            'name': 'Duplicate Sec-WebSocket-Key',
            'risk': 'Medium',
            'description': f"Server at {host}:{port} accepted duplicate Sec-WebSocket-Key headers.",
            'solution': 'Reject requests with multiple Sec-WebSocket-Key headers.',
            'affected_host': f"{host}:{port}",
            'impact': 'Duplicate headers can confuse handshake processing.'
        } if "101 Switching Protocols" in response else None
    
    except Exception as e:
        logging.info(f"Error in test_duplicate_sec_websocket_key for {host}:{port}: {e}")
        return None
   
def test_missing_sec_websocket_version(host, port, path="/", scheme="ws"):
    """Test missing Sec-WebSocket-Version header (Vuln #5)."""
    key = b64encode(b"1234567890123456").decode()
    
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return None
        return {
            'name': 'Missing Sec-WebSocket-Version',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted handshake without Sec-WebSocket-Version.",
            'solution': 'Require Sec-WebSocket-Version header for WebSocket handshake.',
            'affected_host': f"{host}:{port}",
            'impact': 'Missing version header can allow incompatible connections.'
        } if "101 Switching Protocols" in response else None
    except Exception as e:
        logging.info(f"Error in test_missing_sec_websocket_version for {host}:{port}: {e}")
        return None
    
def test_invalid_sec_websocket_version(host, port, path="/", scheme="ws"):
    """Test invalid Sec-WebSocket-Version header (Vuln #6)."""
    key = b64encode(b"1234567890123456").decode()
    
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 999\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return None
        return {
            'name': 'Invalid Sec-WebSocket-Version',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted invalid Sec-WebSocket-Version.",
            'solution': 'Validate Sec-WebSocket-Version (e.g., 13) for WebSocket handshake.',
            'affected_host': f"{host}:{port}",
            'impact': 'Invalid versions can lead to protocol mismatches.'
        } if "101 Switching Protocols" in response else None
    except Exception as e:
        logging.info(f"Error in test_invalid_sec_websocket_version for {host}:{port}: {e}")
        return None
    
def test_conflicting_sec_websocket_version(host, port, path="/", scheme="ws"):
    """Test conflicting Sec-WebSocket-Version headers (Vuln #7)."""
    key = b64encode(b"1234567890123456").decode()
    
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Sec-WebSocket-Version: 8\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return None
        return {
            'name': 'Conflicting Sec-WebSocket-Version',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted conflicting Sec-WebSocket-Version headers.",
            'solution': 'Reject requests with multiple Sec-WebSocket-Version headers.',
            'affected_host': f"{host}:{port}",
            'impact': 'Conflicting versions can cause protocol errors.'
        } if "101 Switching Protocols" in response else None
    except Exception as e:
        logging.info(f"Error in test_conflicting_sec_websocket_version for {host}:{port}: {e}")
        return None

def test_wrong_upgrade_header(host, port, path="/", scheme="ws"):
    """Test wrong Upgrade header (Vuln #8)."""
    key = b64encode(b"1234567890123456").decode()
    
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocketty\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return None
        return {
            'name': 'Wrong Upgrade Header',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted handshake with wrong Upgrade header.",
            'solution': 'Enforce strict Upgrade header validation.',
            'affected_host': f"{host}:{port}",
            'impact': 'Incorrect headers can bypass protocol validation.'
        } if "101 Switching Protocols" in response else None
    except Exception as e:
        logging.info(f"Error in test_wrong_upgrade_header for {host}:{port}: {e}")
        return None

def test_missing_connection_header(host, port, path="/", scheme="ws"):
    """Test missing Connection header (Vuln #9)."""
    key = b64encode(b"1234567890123456").decode()
    
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return None
        return {
            'name': 'Missing Connection Header',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted handshake without Connection header.",
            'solution': 'Require Connection: Upgrade header for security.',
            'affected_host': f"{host}:{port}",
            'impact': 'Missing headers can allow improper connections.'
        } if "101 Switching Protocols" in response else None
    except Exception as e:
        logging.info(f"Error in test_missing_connection_header for {host}:{port}: {e}")
        return None

def test_case_sensitive_headers(host, port, path="/", scheme="ws"):
    """Test case-sensitive headers (Vuln #10)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r\n
Host: {host}\r\n
uPgradE: websocket\r\n
cOnneCtion: Upgrade\r\n
sEc-websocKet-key: {key}\r\n
Sec-WebSocket-Version: 13\r\n
\r\n"""
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "uPgradE: websocket\r\n"
    "cOnneCtion: Upgrade\r\n"
    f"sEc-websocKet-key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return None
        return {
            'name': 'Case-Sensitive Headers',
            'risk': 'Low',
            'description': f"Server at {host}:{port} accepted case-sensitive headers.",
            'solution': 'Ensure case-insensitive header parsing as per RFC.',
            'affected_host': f"{host}:{port}",
            'impact': 'Inconsistent header parsing can lead to security bypasses.'
        } if "101 Switching Protocols" in response else None
    except Exception as e:
        logging.info(f"Error in test_case_sensitive_headers for {host}:{port}: {e}")
        return None

def test_non_get_method(host, port, path="/", scheme="ws"):
    """Test non-GET method for handshake (Vuln #11)."""
    key = b64encode(b"1234567890123456").decode()
    
    req = (
    f"POST {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return None
        return {
            'name': 'Non-GET Method',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted non-GET method (POST) for handshake.",
            'solution': 'Restrict WebSocket handshakes to GET method.',
            'affected_host': f"{host}:{port}",
            'impact': 'Non-GET methods can bypass standard handshake validation.'
        } if "101 Switching Protocols" in response else None
    except Exception as e:
        logging.info(f"Error in test_non_get_method for {host}:{port}: {e}")
        return None
    
from base64 import b64encode
import logging

def test_fake_http_status(host, port, path="/", scheme="ws"):
    """Test fake HTTP status code (Vuln #12)."""
    key = b64encode(b"1234567890123456").decode()

    # Proper WebSocket handshake
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )

    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return None

        # Extract the first status line from the response
        status_line = response.split("\r\n", 1)[0].strip()

        if status_line != "HTTP/1.1 101 Switching Protocols":
            return {
                'name': 'Fake HTTP Status',
                'risk': 'High',
                'description': f"Server at {host}:{port} returned unexpected status: {status_line}",
                'solution': 'Ensure server returns "HTTP/1.1 101 Switching Protocols" for valid handshakes.',
                'affected_host': f"{host}:{port}",
                'impact': 'Clients may be tricked into accepting invalid upgrades or downgrade attacks.'
            }

        # Server responded correctly — no issue
        return None

    except Exception as e:
        logging.info(f"Error in test_fake_http_status for {host}:{port}: {e}")
        return None

    
def test_wrong_sec_websocket_accept(host, port, path="/", scheme="ws"):
    """Test wrong Sec-WebSocket-Accept value from server (Vuln #13)."""

    key = b64encode(b"1234567890123456").decode()

    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return None

        # Parse response headers
        lines = response.split("\r\n")
        accept_header = [line.strip() for line in lines if line.lower().startswith("sec-websocket-accept:")]

        if not accept_header:
            return {
                'name': 'Wrong Sec-WebSocket-Accept',
                'risk': 'Medium',
                'description': f"Server at {host}:{port} did not return a Sec-WebSocket-Accept header.",
                'solution': 'Ensure server follows RFC 6455 and sends correct Sec-WebSocket-Accept header.',
                'affected_host': f"{host}:{port}",
                'impact': 'Clients may accept invalid or spoofed handshakes.'
            }

        server_accept = accept_header[0].split(":", 1)[1].strip()

        # Compute expected Sec-WebSocket-Accept value
        GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        expected_accept = b64encode(sha1((key + GUID).encode()).digest()).decode()

        if server_accept != expected_accept:
            return {
                'name': 'Wrong Sec-WebSocket-Accept',
                'risk': 'Medium',
                'description': f"Server at {host}:{port} returned invalid Sec-WebSocket-Accept: {server_accept}",
                'solution': 'Fix server to generate correct Sec-WebSocket-Accept header as per RFC 6455.',
                'affected_host': f"{host}:{port}",
                'impact': 'Clients may accept spoofed or malformed handshakes, risking data leakage.'
            }

        # All good — no issue found
        return None

    except Exception as e:
        logging.info(f"Error in test_wrong_sec_websocket_accept for {host}:{port}: {e}")
        return None

    
def test_oversized_headers(host, port, path="/", scheme="ws"):
    """Test oversized headers (Vuln #14)."""
    big_value = "A" * 8000
    key = b64encode(b"1234567890123456").decode()
    
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    f"X-Big-Header: {big_value}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return None
        return {
            'name': 'Oversized Headers',
            'risk': 'Medium',
            'description': f"Server at {host}:{port} accepted handshake with oversized headers.",
            'solution': 'Set limits for header size to prevent resource exhaustion.',
            'affected_host': f"{host}:{port}",
            'impact': 'Oversized headers can cause denial-of-service attacks.'
        } if "101 Switching Protocols" in response else None
    except Exception as e:
        logging.info(f"Error in test_oversized_headers for {host}:{port}: {e}")
        return None
    
def test_missing_host_header(host, port, path="/", scheme="ws"):
    """Test missing Host header (Vuln #15)."""
    key = b64encode(b"1234567890123456").decode()
    req = (
    f"GET {path} HTTP/1.1\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return None
        return {
            'name': 'Missing Host Header',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted handshake without Host header.",
            'solution': 'Enforce Host header validation.',
            'affected_host': f"{host}:{port}",
            'impact': 'Missing Host header can allow domain spoofing.'
        } if "101 Switching Protocols" in response else None
    except Exception as e:
        logging.info(f"Error in test_missing_host_header for {host}:{port}: {e}")
        return None

def test_fake_host_header(host, port, path="/", scheme="ws"):
    """Test fake Host header (Vuln #16)."""
    key = b64encode(b"1234567890123456").decode()
    req = (
    f"GET {path} HTTP/1.1\r\n"
    "Host: fake.example.com\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return None
        return {
            'name': 'Fake Host Header',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted handshake with incorrect Host header.",
            'solution': 'Validate Host header to match expected server domain.',
            'affected_host': f"{host}:{port}",
            'impact': 'Fake Host headers can enable domain spoofing attacks.'
        } if "101 Switching Protocols" in response else None
    except Exception as e:
        logging.info(f"Error in test_fake_host_header for {host}:{port}: {e}")
        return None

def test_multiple_host_headers(host, port, path="/", scheme="ws"):
    """Test multiple Host headers (Vuln #17)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r\n
Host: real.example.com\r\n
Host: fake.example.com\r\n
Upgrade: websocket\r\n
Connection: Upgrade\r\n
Sec-WebSocket-Key: {key}\r\n
Sec-WebSocket-Version: 13\r\n
\r\n"""
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: real.example.com\r\n"
    f"Host: fake.example.com\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return None
        return {
            'name': 'Multiple Host Headers',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted handshake with multiple Host headers.",
            'solution': 'Reject requests with duplicate Host headers.',
            'affected_host': f"{host}:{port}",
            'impact': 'Multiple Host headers can confuse server routing.'
        } if "101 Switching Protocols" in response else None
    except Exception as e:
        logging.info(f"Error in test_multiple_host_headers for {host}:{port}: {e}")
        return None

def test_long_url_path(host, port, path="/", scheme="ws"):
    """Test long URL path (Vuln #18)."""
    long_path = "/" + "a" * 2048
    key = b64encode(b"1234567890123456").decode()
    
    req = (
    f"GET {long_path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return None
        return {
            'name': 'Long URL Path',
            'risk': 'Low',
            'description': f"Server at {host}:{port} accepted handshake with long URL path (2KB).",
            'solution': 'Limit URL path length to prevent resource exhaustion.',
            'affected_host': f"{host}:{port}",
            'impact': 'Long URLs can cause server overload or crashes.'
        } if "101 Switching Protocols" in response else None
    except Exception as e:
        logging.info(f"Error in test_long_url_path for {host}:{port}: {e}")
        return None

def test_unicode_url(host, port, path="/", scheme="ws"):
    """Test Unicode URL (Vuln #19)."""
    unicode_path = "/%F0%9F%98%80"  # Smiling emoji
    key = b64encode(b"1234567890123456").decode()
    
    req = (
    f"GET {unicode_path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return None
        return {
            'name': 'Unicode URL',
            'risk': 'Medium',
            'description': f"Server at {host}:{port} accepted handshake with Unicode URL.",
            'solution': 'Sanitize and validate URL paths to handle Unicode correctly.',
            'affected_host': f"{host}:{port}",
            'impact': 'Improper Unicode handling can lead to parsing errors or bypasses.'
        } if "101 Switching Protocols" in response else None
    except Exception as e:
        logging.info(f"Error in test_unicode_url for {host}:{port}: {e}")
        return None

def test_http_0_9_handshake(host, port, path="/", scheme="ws"):
    """Test HTTP/0.9 handshake (Vuln #20)."""
    req = f"""GET {path}\r\n"""
    try:
        # HTTP/0.9 doesn't use headers
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return None
        return {
            'name': 'HTTP/0.9 Handshake',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted HTTP/0.9 handshake.",
            'solution': 'Require HTTP/1.1 or higher for WebSocket handshakes.',
            'affected_host': f"{host}:{port}",
            'impact': 'HTTP/0.9 lacks headers, enabling downgrade attacks.'
        } if "101 Switching Protocols" in response else None
    except Exception as e:
        logging.info(f"Error in test_http_0_9_handshake for {host}:{port}: {e}")
        return None
    

# def test_invalid_port(ws_url):
#     """Test if WebSocket accepts connections on invalid ports (Vuln #21)."""
#     try:
#         parsed_url = urlparse(ws_url)
#         invalid_port_url = f"{parsed_url.scheme}://{parsed_url.hostname}:99999{parsed_url.path}"
#         parsed_invalid_url = urlparse(invalid_port_url)
#         port = parsed_invalid_url.port
#         # Check if the port is invalid; if so, report without attempting connection
#         if port is None or not (0 <= port <= 65535):
#             return {
#                 'name': 'Invalid Port',
#                 'risk': 'Medium',
#                 'description': f"WebSocket URL {invalid_port_url} contains an invalid port 99999, which should be rejected by the server.",
#                 'solution': 'Ensure server validates port numbers and rejects invalid ones.',
#                 'affected_url': invalid_port_url,
#                 'impact': 'Invalid ports can cause unexpected behavior if not handled.'
#             }
#         # If the port is valid, attempt the connection (though this shouldn't happen with 99999)
#         ws = websocket.WebSocket()
#         ws.connect(invalid_port_url, timeout=5)
#         ws.close()
#         return {
#             'name': 'Invalid Port',
#             'risk': 'Medium',
#             'description': f"WebSocket at {invalid_port_url} accepted connection on invalid port 99999.",
#             'solution': 'Validate port numbers and reject invalid ones.',
#             'affected_url': invalid_port_url,
#             'impact': 'Invalid ports can cause unexpected behavior.'
#         }
#     except ValueError as e:
#         return None
#     except Exception as e:
#         print(colored(f"Invalid port test failed for {ws_url}: {e}", "yellow"))
#         return None
    
# def test_non_ws_scheme(ws_url):
#     """Test if WebSocket accepts non-WebSocket schemes (Vuln #22)."""
#     try:
#         parsed_url = urlparse(ws_url)
#         # Check if the scheme is invalid (not ws:// or wss://)
#         if parsed_url.scheme not in ['ws', 'wss']:
#             return {
#                 'name': 'Non-WebSocket Scheme',
#                 'risk': 'High',
#                 'description': f"WebSocket URL {ws_url} could be accessed with a non-WebSocket scheme 'http', which should be rejected by the server.",
#                 'solution': 'Reject connections with non-WebSocket schemes (only allow ws:// or wss://).',
#                 'affected_url': ws_url,
#                 'impact': 'Non-WebSocket schemes can lead to protocol misuse if not handled properly.'
#             }
#         # If the scheme is valid, this test isn't applicable
#         return None
#     except Exception as e:
#         print(colored(f"Non-WebSocket scheme test failed for {ws_url}: {e}", "yellow"))
#         return None

def test_undefined_opcode(ws_url):
    """Test undefined opcode (Vuln #23)."""
    try:
        frame = struct.pack("!B", 0x83) + struct.pack("!B", 0x04) + b"test"  # FIN=1, Opcode=0x3, Length=4
        response = send_custom_frame(ws_url, frame)
        return {
            'name': 'Undefined Opcode',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepted frame with undefined opcode 0x3.",
            'solution': 'Reject frames with undefined opcodes.',
            'affected_url': ws_url,
            'impact': 'Undefined opcodes can cause unexpected server behavior.'
        } if response else None
    except:
        return None

def test_reserved_opcode(ws_url):
    """Test reserved opcode (Vuln #24)."""
    frame = struct.pack("!B", 0x8B) + struct.pack("!B", 0x04) + b"test"  # FIN=1, Opcode=0xB, Length=4
    response = send_custom_frame(ws_url, frame)
    return {
        'name': 'Reserved Opcode',
        'risk': 'High',
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
            'risk': 'Low',
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
        'risk': 'Medium',
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
        'risk': 'High',
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
        'risk': 'Medium',
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
        'risk': 'High',
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
        'risk': 'Low',
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
            'risk': 'Low',
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
            'risk': 'Low',
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
            'risk': 'Medium',
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
            'risk': 'High',
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

def test_fake_extension(host, port, path="/", conn=None):
    """Test if WebSocket accepts a fake extension (Vuln #50)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r\n
Host: {host}\r\n
Upgrade: websocket\r\n
Connection: Upgrade\r\n
Sec-WebSocket-Key: {key}\r\n
Sec-WebSocket-Extensions: fake-extension\r\n
Sec-WebSocket-Version: 13\r\n
\r\n"""
    if conn:
        try:
            conn.request("GET", path, headers={
                "Host": host,
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": key,
                "Sec-WebSocket-Extensions": "fake-extension",
                "Sec-WebSocket-Version": "13"
            })
            response = conn.getresponse().read().decode()
            return {
                'name': 'Fake Extension',
                'risk': 'High',
                'description': f"Server at {host}:{port} accepted fake extension 'fake-extension'.",
                'solution': 'Validate Sec-WebSocket-Extensions against supported extensions.',
                'affected_host': f"{host}:{port}",
                'impact': 'Fake extensions can lead to unexpected server behavior.'
            } if "101 Switching Protocols" in response else None
        except Exception as e:
            logging.info(f"Error in test_fake_extension for {host}:{port}: {e}")
            return None
    else:
        response = send_raw_handshake(host, port, req)
        return {
            'name': 'Fake Extension',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted fake extension 'fake-extension'.",
            'solution': 'Validate Sec-WebSocket-Extensions against supported extensions.',
            'affected_host': f"{host}:{port}",
            'impact': 'Fake extensions can lead to unexpected server behavior.'
        } if "101 Switching Protocols" in response else None

def test_conflicting_extensions(host, port, path="/", conn=None):
    """Test if WebSocket accepts conflicting extensions (Vuln #51)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r\n
Host: {host}\r\n
Upgrade: websocket\r\n
Connection: Upgrade\r\n
Sec-WebSocket-Key: {key}\r\n
Sec-WebSocket-Extensions: permessage-deflate; permessage-deflate\r\n
Sec-WebSocket-Version: 13\r\n
\r\n"""
    if conn:
        try:
            conn.request("GET", path, headers={
                "Host": host,
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": key,
                "Sec-WebSocket-Extensions": "permessage-deflate; permessage-deflate",
                "Sec-WebSocket-Version": "13"
            })
            response = conn.getresponse().read().decode()
            return {
                'name': 'Conflicting Extensions',
                'risk': 'Medium',
                'description': f"Server at {host}:{port} accepted conflicting extensions.",
                'solution': 'Reject requests with duplicate or conflicting extensions.',
                'affected_host': f"{host}:{port}",
                'impact': 'Conflicting extensions can cause protocol errors.'
            } if "101 Switching Protocols" in response else None
        except Exception as e:
            logging.info(f"Error in test_conflicting_extensions for {host}:{port}: {e}")
            return None
    else:
        response = send_raw_handshake(host, port, req)
        return {
            'name': 'Conflicting Extensions',
            'risk': 'Medium',
            'description': f"Server at {host}:{port} accepted conflicting extensions.",
            'solution': 'Reject requests with duplicate or conflicting extensions.',
            'affected_host': f"{host}:{port}",
            'impact': 'Conflicting extensions can cause protocol errors.'
        } if "101 Switching Protocols" in response else None

def test_spoofed_connection_header(host, port, path="/", conn=None):
    """Test if WebSocket accepts a spoofed Connection header (Vuln #52)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r\n
Host: {host}\r\n
Upgrade: websocket\r\n
Connection: Keep-Alive\r\n
Sec-WebSocket-Key: {key}\r\n
Sec-WebSocket-Version: 13\r\n
\r\n"""
    if conn:
        try:
            conn.request("GET", path, headers={
                "Host": host,
                "Upgrade": "websocket",
                "Connection": "Keep-Alive",
                "Sec-WebSocket-Key": key,
                "Sec-WebSocket-Version": "13"
            })
            response = conn.getresponse().read().decode()
            return {
                'name': 'Spoofed Connection Header',
                'risk': 'High',
                'description': f"Server at {host}:{port} accepted spoofed Connection header 'Keep-Alive'.",
                'solution': 'Require Connection: Upgrade header for WebSocket handshake.',
                'affected_host': f"{host}:{port}",
                'impact': 'Spoofed headers can bypass handshake validation.'
            } if "101 Switching Protocols" in response else None
        except Exception as e:
            logging.info(f"Error in test_spoofed_connection_header for {host}:{port}: {e}")
            return None
    else:
        response = send_raw_handshake(host, port, req)
        return {
            'name': 'Spoofed Connection Header',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted spoofed Connection header 'Keep-Alive'.",
            'solution': 'Require Connection: Upgrade header for WebSocket handshake.',
            'affected_host': f"{host}:{port}",
            'impact': 'Spoofed headers can bypass handshake validation.'
        } if "101 Switching Protocols" in response else None

def test_http_1_0_downgrade(host, port, path="/", conn=None):
    """Test if WebSocket accepts HTTP/1.0 handshake (Vuln #53)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.0\r\n
Host: {host}\r\n
Upgrade: websocket\r\n
Connection: Upgrade\r\n
Sec-WebSocket-Key: {key}\r\n
Sec-WebSocket-Version: 13\r\n
\r\n"""
    if conn:
        try:
            conn.request("GET", path, headers={
                "Host": host,
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": key,
                "Sec-WebSocket-Version": "13"
            })
            response = conn.getresponse().read().decode()
            return {
                'name': 'HTTP/1.0 Downgrade',
                'risk': 'High',
                'description': f"Server at {host}:{port} accepted HTTP/1.0 handshake.",
                'solution': 'Require HTTP/1.1 or higher for WebSocket handshakes.',
                'affected_host': f"{host}:{port}",
                'impact': 'HTTP/1.0 lacks modern security features.'
            } if "101 Switching Protocols" in response else None
        except Exception as e:
            logging.info(f"Error in test_http_1_0_downgrade for {host}:{port}: {e}")
            return None
    else:
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
    """Test if WebSocket allows downgrade to insecure TLS versions (Vuln #54)."""
    try:
        parsed_url = urlparse(ws_url)
        if parsed_url.scheme != 'wss':
            return None  # Only applicable to wss:// URLs
        
        # Check if TLS 1.0 is supported
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # Force TLS 1.0 (insecure)
        except ValueError as e:
            print(colored(f"TLS downgrade test skipped for {ws_url}: TLS 1.0 not supported in this environment ({e}).", "yellow"))
            return None

        context.verify_mode = ssl.CERT_NONE
        ws = websocket.WebSocket(sslopt={"context": context})
        ws.connect(ws_url, timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
            'name': 'TLS Downgrade',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} allows downgrade to insecure TLS version (TLS 1.0).",
            'solution': 'Enforce modern TLS versions (e.g., TLS 1.2 or 1.3) and disable older versions.',
            'affected_url': ws_url,
            'impact': 'Insecure TLS versions are vulnerable to attacks like POODLE.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"TLS downgrade test failed for {ws_url}: {e}", "yellow"))
        return None
    except ssl.SSLError as e:
        print(colored(f"TLS downgrade test failed for {ws_url}: {e}", "yellow"))
        return None
    except Exception as e:
        print(colored(f"TLS downgrade test failed for {ws_url}: {e}", "yellow"))
        return None
    
def test_insecure_cipher(ws_url):
    """Test if WebSocket accepts insecure ciphers (Vuln #55)."""
    try:
        parsed_url = urlparse(ws_url)
        if parsed_url.scheme != 'wss':
            return None  # Only applicable to wss:// URLs
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)

        # List of insecure ciphers to test
        insecure_ciphers = ["RC4-MD5", "DES-CBC-SHA"]
        supported_cipher = None
        for cipher in insecure_ciphers:
            try:
                context.set_ciphers(cipher)
                supported_cipher = cipher
                break
            except ssl.SSLError:
                continue

        if not supported_cipher:
            print(colored(f"Insecure cipher test skipped for {ws_url}: No supported insecure ciphers available.", "yellow"))
            return None

        context.verify_mode = ssl.CERT_NONE
        ws = websocket.WebSocket(sslopt={"context": context})
        ws.connect(ws_url, timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
            'name': 'Insecure Cipher',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepts insecure cipher {supported_cipher}.",
            'solution': 'Disable insecure ciphers and use strong cipher suites.',
            'affected_url': ws_url,
            'impact': 'Insecure ciphers can be exploited to decrypt communications.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"Insecure cipher test failed for {ws_url}: {e}", "yellow"))
        return None
    except ssl.SSLError as e:
        print(colored(f"Insecure cipher test failed for {ws_url}: {e}", "yellow"))
        return None
    except Exception as e:
        print(colored(f"Insecure cipher test failed for {ws_url}: {e}", "yellow"))
        return None
    
def test_certificate_mismatch(ws_url):
    """Test if WebSocket endpoint's certificate matches the domain (Vuln #56)."""
    try:
        parsed_url = urlparse(ws_url)
        if parsed_url.scheme != 'wss':
            return None  # Only applicable to wss:// URLs
        host = parsed_url.hostname
        port = parsed_url.port or 443
        # Create a default SSL context to verify the certificate
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                # Check if the certificate matches the hostname
                ssl.match_hostname(cert, host)
        return None  # If no exception, certificate is valid
    except ssl.SSLCertVerificationError as e:
        return {
            'name': 'Certificate Mismatch',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} has a certificate mismatch: {e}.",
            'solution': 'Ensure the SSL certificate matches the domain and is issued by a trusted CA.',
            'affected_url': ws_url,
            'impact': 'Certificate mismatches can allow man-in-the-middle attacks.'
        }
    except Exception as e:
        print(colored(f"Certificate mismatch test failed for {ws_url}: {e}", "yellow"))
        return None
    
def test_connection_flood(ws_url):
    """Test if WebSocket server handles rapid connection flooding (Vuln #57)."""
    try:
        start_time = time.time()
        for _ in range(50):
            ws = websocket.WebSocket()
            ws.connect(ws_url, timeout=5)
            ws.close()
        elapsed = time.time() - start_time
        if elapsed < 5:  # Assuming a rate limit should slow this down
            return {
                'name': 'Connection Flood',
                'risk': 'High',
                'description': f"WebSocket at {ws_url} handles rapid connection flooding ({elapsed:.2f}s for 50 connections).",
                'solution': 'Implement connection rate limiting to prevent flooding.',
                'affected_url': ws_url,
                'impact': 'Connection flooding can exhaust server resources, leading to DoS.'
            }
        return None
    except websocket.WebSocketException as e:
        print(colored(f"Connection flood test failed for {ws_url}: {e}", "yellow"))
        return None

def test_oversized_message(ws_url):
    """Test if WebSocket accepts oversized messages (Vuln #58)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, timeout=5)
        payload = "A" * 10_000_000  # 10MB message
        ws.send(payload)
        response = ws.recv()
        ws.close()
        return {
            'name': 'Oversized Message',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepts oversized message (10MB).",
            'solution': 'Set a reasonable message size limit to prevent resource exhaustion.',
            'affected_url': ws_url,
            'impact': 'Oversized messages can cause server crashes or DoS.'
        }
    except (websocket.WebSocketException, ssl.SSLError, socket.error) as e:
        print(colored(f"Oversized message test failed for {ws_url}: {e}", "yellow"))
        return None

def test_max_connections(ws_url):
    """Test if WebSocket server enforces maximum connections limit (Vuln #59)."""
    try:
        connections = []
        for _ in range(100):  # Attempt to open 100 simultaneous connections
            ws = websocket.WebSocket()
            ws.connect(ws_url, timeout=5)
            connections.append(ws)
        for ws in connections:
            ws.close()
        return {
            'name': 'Max Connections',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} allows 100 simultaneous connections without restriction.",
            'solution': 'Enforce a maximum connection limit per client to prevent resource exhaustion.',
            'affected_url': ws_url,
            'impact': 'Excessive connections can lead to server overload and DoS.'
        }
    except (websocket.WebSocketException, ssl.SSLError, socket.error) as e:
        print(colored(f"Max connections test failed for {ws_url}: {e}", "yellow"))
        return None
    finally:
        for ws in connections:
            try:
                ws.close()
            except:
                pass

def test_idle_timeout_abuse(ws_url):
    """Test if WebSocket server allows idle connections to persist (Vuln #60)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, timeout=5)
        time.sleep(60)  # Remain idle for 60 seconds
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
            'name': 'Idle Timeout Abuse',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} allows idle connections to persist for 60 seconds.",
            'solution': 'Implement an idle timeout policy to close inactive connections.',
            'affected_url': ws_url,
            'impact': 'Idle connections can tie up server resources, enabling DoS.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"Idle timeout abuse test failed for {ws_url}: {e}", "yellow"))
        return None

def test_no_compression_negotiation(ws_url):
    """Test if WebSocket server fails to negotiate compression properly (Vuln #61)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, header=["Sec-WebSocket-Extensions: permessage-deflate"], timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()
        # Check if compression was negotiated but not enforced properly
        return {
            'name': 'No Compression Negotiation',
            'risk': 'Medium',
            'description': f"WebSocket at {ws_url} does not properly negotiate compression (permessage-deflate).",
            'solution': 'Ensure proper negotiation and validation of compression extensions.',
            'affected_url': ws_url,
            'impact': 'Improper compression handling can lead to resource exhaustion or DoS.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"No compression negotiation test failed for {ws_url}: {e}", "yellow"))
        return None

def test_high_compression_ratio(ws_url):
    """Test if WebSocket server handles high compression ratio messages (Vuln #62)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, header=["Sec-WebSocket-Extensions: permessage-deflate"], timeout=5)
        payload = "A" * 1_000_000  # 1MB of highly compressible data
        ws.send(payload)
        response = ws.recv()
        ws.close()
        return {
            'name': 'High Compression Ratio',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepts highly compressible messages (1MB of 'A').",
            'solution': 'Limit compression ratios or message sizes to prevent decompression bombs.',
            'affected_url': ws_url,
            'impact': 'High compression ratios can lead to decompression bombs, causing DoS.'
        }
    except (websocket.WebSocketException, ssl.SSLError, socket.error) as e:
        print(colored(f"High compression ratio test failed for {ws_url}: {e}", "yellow"))
        return None
    
def test_resource_leak(ws_url):
    """Test if WebSocket connection causes resource leaks (Vuln #63)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, timeout=5)
        for _ in range(100):
            ws.send("A" * 1_000_000)  # 1MB message
            time.sleep(0.1)
        ws.close()
        # Note: Actual resource leak detection requires server-side monitoring
        return {
            'name': 'Resource Leak',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} may leak resources with large messages.",
            'solution': 'Monitor server resource usage and fix leaks; set message size limits.',
            'affected_url': ws_url,
            'impact': 'Resource leaks can lead to server crashes over time.'
        }
    except websocket.WebSocketException as e:
        print(colored(f"Resource leak test failed for {ws_url}: {e}", "yellow"))
        return None

def test_no_timeout_policy(ws_url):
    """Test if WebSocket server lacks a connection timeout policy (Vuln #64)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, timeout=5)
        time.sleep(120)  # Remain connected for 120 seconds
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
            'name': 'No Timeout Policy',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} lacks a connection timeout policy (active for 120 seconds).",
            'solution': 'Implement a connection timeout policy to close long-lived connections.',
            'affected_url': ws_url,
            'impact': 'Lack of timeout policy can lead to resource exhaustion.'
        }
    except (websocket.WebSocketException, ssl.SSLError, socket.error) as e:
        print(colored(f"No timeout policy test failed for {ws_url}: {e}", "yellow"))
        return None
    finally:
        try:
            ws.close()
        except:
            pass

# Cross-Origin & Mixed Content (Vuln #65-69)

def test_missing_cors_headers(ws_url):
    """Test if WebSocket endpoint lacks CORS headers (Vuln #65)."""
    try:
        parsed_url = urlparse(ws_url)
        http_url = f"{'https' if parsed_url.scheme == 'wss' else 'http'}://{parsed_url.netloc}/"
        headers = {"Origin": "http://malicious.com"}
        response = requests.get(http_url, headers=headers, timeout=5)
        if "Access-Control-Allow-Origin" not in response.headers:
            return {
                'name': 'Missing CORS Headers',
                'risk': 'High',
                'description': f"WebSocket endpoint {ws_url} (HTTP equivalent) lacks CORS headers.",
                'solution': 'Implement proper CORS headers to restrict cross-origin access.',
                'affected_url': http_url,
                'impact': 'Missing CORS headers can lead to unauthorized cross-origin requests.'
            }
        return None
    except requests.RequestException as e:
        print(colored(f"Missing CORS headers test failed for {ws_url}: {e}", "yellow"))
        return None

def test_cross_origin_iframe(ws_url):
    """Test if WebSocket endpoint allows cross-origin iframe access (Vuln #66)."""
    try:
        parsed_url = urlparse(ws_url)
        http_url = f"{'https' if parsed_url.scheme == 'wss' else 'http'}://{parsed_url.netloc}/"
        response = requests.get(http_url, timeout=5)
        if "X-Frame-Options" not in response.headers or response.headers["X-Frame-Options"].lower() not in ["deny", "sameorigin"]:
            return {
                'name': 'Cross-Origin Iframe',
                'risk': 'High',
                'description': f"WebSocket endpoint {ws_url} (HTTP equivalent) allows cross-origin iframe access.",
                'solution': 'Set X-Frame-Options header to DENY or SAMEORIGIN.',
                'affected_url': http_url,
                'impact': 'Cross-origin iframes can be exploited for clickjacking attacks.'
            }
        return None
    except requests.RequestException as e:
        print(colored(f"Cross-origin iframe test failed for {ws_url}: {e}", "yellow"))
        return None

def test_mixed_content(ws_url):
    """Test if WebSocket endpoint serves mixed content (Vuln #67)."""
    try:
        parsed_url = urlparse(ws_url)
        if parsed_url.scheme != 'wss':
            return None  # Only applicable to wss:// URLs
        http_url = f"http://{parsed_url.netloc}/"
        response = requests.get(http_url, timeout=5, allow_redirects=True)
        if response.status_code == 200 and not response.url.startswith("https://"):
            return {
                'name': 'Mixed Content',
                'risk': 'High',
                'description': f"WebSocket endpoint {ws_url} (HTTP equivalent) serves mixed content over HTTP.",
                'solution': 'Ensure all resources are served over HTTPS to prevent mixed content issues.',
                'affected_url': http_url,
                'impact': 'Mixed content can expose sensitive data over unencrypted connections.'
            }
        return None
    except requests.RequestException as e:
        print(colored(f"Mixed content test failed for {ws_url}: {e}", "yellow"))
        return None

def test_postmessage_abuse(ws_url):
    """Test if WebSocket endpoint is vulnerable to postMessage abuse (Vuln #68)."""
    try:
        parsed_url = urlparse(ws_url)
        http_url = f"{'https' if parsed_url.scheme == 'wss' else 'http'}://{parsed_url.netloc}/"
        response = requests.get(http_url, timeout=5)
        # Check for HTML content that might include postMessage listeners
        if "text/html" in response.headers.get("Content-Type", "").lower():
            content = response.text.lower()
            if "postmessage" in content and "origin" not in content:
                return {
                    'name': 'PostMessage Abuse',
                    'risk': 'High',
                    'description': f"WebSocket endpoint {ws_url} (HTTP equivalent) may be vulnerable to postMessage abuse.",
                    'solution': 'Validate the origin of postMessage events in client-side code.',
                    'affected_url': http_url,
                    'impact': 'PostMessage abuse can allow cross-origin data leakage or script execution.'
                }
        return None
    except requests.RequestException as e:
        print(colored(f"PostMessage abuse test failed for {ws_url}: {e}", "yellow"))
        return None

def test_spoofed_url(ws_url):
    """Test if WebSocket endpoint allows spoofed URLs (Vuln #69)."""
    try:
        parsed_url = urlparse(ws_url)
        http_url = f"{'https' if parsed_url.scheme == 'wss' else 'http'}://{parsed_url.netloc}/"
        headers = {"Referer": "http://malicious.com"}
        response = requests.get(http_url, headers=headers, timeout=5)
        if response.status_code == 200 and "malicious.com" in response.text.lower():
            return {
                'name': 'Spoofed URL',
                'risk': 'High',
                'description': f"WebSocket endpoint {ws_url} (HTTP equivalent) reflects spoofed Referer URL.",
                'solution': 'Sanitize and validate Referer headers; avoid reflecting untrusted input.',
                'affected_url': http_url,
                'impact': 'Spoofed URLs can be used for phishing or redirection attacks.'
            }
        return None
    except requests.RequestException as e:
        print(colored(f"Spoofed URL test failed for {ws_url}: {e}", "yellow"))
        return None

# Other Vulnerabilities (Vuln #70-75)

def test_error_message_leak(ws_url):
    """Test if WebSocket server leaks sensitive error messages (Vuln #70)."""
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, timeout=5)
        ws.send("\x00" * 1000)  # Malformed input to trigger error
        response = ws.recv()
        ws.close()
        if any(keyword in response.lower() for keyword in ["stack trace", "exception", "sql", "database", "error at"]):
            return {
                'name': 'Error Message Leak',
                'risk': 'Medium',
                'description': f"WebSocket at {ws_url} leaks sensitive error messages: {response}.",
                'solution': 'Avoid exposing detailed error messages in production; use generic error responses.',
                'affected_url': ws_url,
                'impact': 'Error message leaks can expose server details to attackers.'
            }
        return None
    except websocket.WebSocketException as e:
        print(colored(f"Error message leak test failed for {ws_url}: {e}", "yellow"))
        return None

def test_server_disclosure(ws_url):
    """Test if WebSocket server discloses server information (Vuln #71)."""
    try:
        parsed_url = urlparse(ws_url)
        http_url = f"{'https' if parsed_url.scheme == 'wss' else 'http'}://{parsed_url.netloc}/"
        response = requests.get(http_url, timeout=5)
        server_header = response.headers.get("Server", "").lower()
        if server_header and any(keyword in server_header for keyword in ["apache", "nginx", "iis", "tomcat"]):
            return {
                'name': 'Server Disclosure',
                'risk': 'Medium',
                'description': f"WebSocket endpoint {ws_url} (HTTP equivalent) discloses server info: {server_header}.",
                'solution': 'Disable or obscure the Server header to prevent information disclosure.',
                'affected_url': http_url,
                'impact': 'Server disclosure can help attackers target specific vulnerabilities.'
            }
        return None
    except requests.RequestException as e:
        print(colored(f"Server disclosure test failed for {ws_url}: {e}", "yellow"))
        return None

def test_invalid_content_type(ws_url):
    """Test if WebSocket endpoint serves invalid Content-Type (Vuln #72)."""
    try:
        parsed_url = urlparse(ws_url)
        http_url = f"{'https' if parsed_url.scheme == 'wss' else 'http'}://{parsed_url.netloc}/"
        response = requests.get(http_url, timeout=5)
        content_type = response.headers.get("Content-Type", "").lower()
        if content_type and "text/html" in content_type and "upgrade: websocket" not in response.headers.get("Connection", "").lower():
            return {
                'name': 'Invalid Content-Type',
                'risk': 'Medium',
                'description': f"WebSocket endpoint {ws_url} (HTTP equivalent) serves invalid Content-Type: {content_type}.",
                'solution': 'Ensure WebSocket endpoints return appropriate Content-Type or upgrade headers.',
                'affected_url': http_url,
                'impact': 'Invalid Content-Type can confuse clients or enable XSS attacks.'
            }
        return None
    except requests.RequestException as e:
        print(colored(f"Invalid Content-Type test failed for {ws_url}: {e}", "yellow"))
        return None

def test_missing_security_headers(ws_url):
    """Test if WebSocket endpoint lacks security headers (Vuln #73)."""
    try:
        parsed_url = urlparse(ws_url)
        http_url = f"{'https' if parsed_url.scheme == 'wss' else 'http'}://{parsed_url.netloc}/"
        response = requests.get(http_url, timeout=5)
        missing_headers = []
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1; mode=block",
            "Content-Security-Policy": None,
        }
        for header, expected_value in security_headers.items():
            if header not in response.headers or (expected_value and response.headers[header] != expected_value):
                missing_headers.append(header)
        if missing_headers:
            return {
                'name': 'Missing Security Headers',
                'risk': 'Medium',
                'description': f"WebSocket endpoint {ws_url} (HTTP equivalent) lacks security headers: {', '.join(missing_headers)}.",
                'solution': 'Implement security headers like X-Content-Type-Options, X-XSS-Protection, and CSP.',
                'affected_url': http_url,
                'impact': 'Missing security headers can expose the server to various attacks.'
            }
        return None
    except requests.RequestException as e:
        print(colored(f"Missing security headers test failed for {ws_url}: {e}", "yellow"))
        return None

def test_url_path_traversal(ws_url):
    """Test if WebSocket endpoint is vulnerable to URL path traversal (Vuln #74)."""
    try:
        parsed_url = urlparse(ws_url)
        http_url = f"{'https' if parsed_url.scheme == 'wss' else 'http'}://{parsed_url.netloc}/../etc/passwd"
        response = requests.get(http_url, timeout=5)
        if response.status_code == 200 and "root:" in response.text:
            return {
                'name': 'URL Path Traversal',
                'risk': 'High',
                'description': f"WebSocket endpoint {ws_url} (HTTP equivalent) is vulnerable to path traversal.",
                'solution': 'Sanitize and validate URL paths to prevent directory traversal attacks.',
                'affected_url': http_url,
                'impact': 'Path traversal can allow access to sensitive files on the server.'
            }
        return None
    except requests.RequestException as e:
        print(colored(f"URL path traversal test failed for {ws_url}: {e}", "yellow"))
        return None

def test_query_parameter_flood(ws_url):
    """Test if WebSocket endpoint handles query parameter flooding (Vuln #75)."""
    try:
        parsed_url = urlparse(ws_url)
        base_url = f"{'https' if parsed_url.scheme == 'wss' else 'http'}://{parsed_url.netloc}{parsed_url.path}"
        params = "&".join([f"param{i}=value{i}" for i in range(1000)])  # 1000 query parameters
        flood_url = f"{base_url}?{params}"
        response = requests.get(flood_url, timeout=5)
        if response.status_code == 200:
            return {
                'name': 'Query Parameter Flood',
                'risk': 'High',
                'description': f"WebSocket endpoint {ws_url} (HTTP equivalent) handles query parameter flooding (1000 params).",
                'solution': 'Limit the number of query parameters and validate input to prevent flooding.',
                'affected_url': flood_url,
                'impact': 'Query parameter flooding can overload the server, leading to DoS.'
            }
        return None
    except requests.RequestException as e:
        print(colored(f"Query parameter flood test failed for {ws_url}: {e}", "yellow"))
        return None
    
def perform_websocket_tests(websocket_urls, payloads):
    """Perform WebSocket security tests."""
    ws_report = {}
    di1 = {
        "Origin":0,
        "Authentication":0,
        "Fuzzing":0,
        "Handshake":0,
        "Payload":0,
        "Session":0,
        "Subprotocol":0,
        "Security":0,
        "DOS":0,
        "Cross-Origin":0,
        "Others":0
    }

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
        test_wrong_sec_websocket_accept,  # 13 
        test_oversized_headers,  # 14
        test_missing_host_header,  # 15
        test_fake_host_header,  # 16
        test_multiple_host_headers,  # 17
        test_long_url_path,  # 18
        test_unicode_url,  # 19
        test_http_0_9_handshake,  # 20
    ]
    #21 and 22 are used to check if URL is valid.
    payload_tests = [
        test_undefined_opcode,  # 23
        test_reserved_opcode,  # 24
        test_zero_length_fragment,  # 25
        test_invalid_payload_length,  # 26
        test_negative_payload_length,  # 27
        test_mismatched_payload,  # 28
        test_invalid_masking_key,  # 29
        test_unmasked_client_frame,  # 30
        test_invalid_rsv_bits,  # 31
        test_oversized_control_frame,  # 32
        test_non_utf8_text,  # 33
        test_null_bytes_in_text,  # 34
        test_binary_as_text,  # 35
        test_text_as_binary,  # 36
        test_invalid_close_code,  # 37
        test_early_close_frame,  # 38
        test_no_close_frame,  # 39
        test_long_close_reason,  # 40
    ]
    auth_session_tests = [
        test_no_session_cookie,  # 41
        test_expired_cookie,  # 42
        test_fake_token,  # 43
        test_http_session_reuse,  # 44
        test_stale_session_reconnect,  # 45
        test_cross_site_cookie_hijack,  # 46
    ]
    ws_subprotocol_tests = [
        test_invalid_subprotocol,  # 47
        test_conflicting_subprotocols,  # 48
        test_unaccepted_subprotocol,  # 49
    ]
    subprotocol_tests = [
        test_fake_extension,  # 50
        test_conflicting_extensions,  # 51
    ]
    security_tests = [
        test_spoofed_connection_header,  # 52
        test_http_1_0_downgrade,  # 53
    ]
    ws_security_tests = [
        test_tls_downgrade,  # 54
        test_insecure_cipher,  # 55
        test_certificate_mismatch,  # 56
    ]
    ws_dos_tests = [
        test_connection_flood,  # 57
        test_oversized_message,  # 58
        test_max_connections,  # 59
        test_idle_timeout_abuse,  # 60
        test_high_compression_ratio,  # 62
        test_resource_leak,  # 63
        test_no_compression_negotiation,  # 61
        test_no_timeout_policy,  # 64
    ]
    cross_origin_tests = [
        test_missing_cors_headers,  # 65
        test_cross_origin_iframe,  # 66
        test_mixed_content,  # 67
        test_postmessage_abuse,  # 68
        test_spoofed_url,  # 69
    ]
    ws_other_tests = [
        test_error_message_leak,  # 70
        test_server_disclosure,  # 71
        test_invalid_content_type,  # 72
        test_missing_security_headers,  # 73
        test_url_path_traversal,  # 74
        test_query_parameter_flood,  # 75
    ]
        
    for ws_url in websocket_urls:
        parsed_url = urlparse(ws_url)
        host = parsed_url.hostname
        scheme = parsed_url.scheme
        port = parsed_url.port or (443 if scheme == 'wss' else 80)
        path = parsed_url.path or "/"
        vulnerabilities = []

        # 4️⃣ Handshake & HTTP Request Tests (Vuln #1-22)
        handshake_res = []
        if scheme not in ['ws', 'wss']:
            handshake_res.append(
                {
                'name': 'Non-WebSocket Scheme',
                'risk': 'High',
                'description': f"WebSocket URL {ws_url} could be accessed with a non-WebSocket scheme 'http', which should be rejected by the server.",
                'solution': 'Reject connections with non-WebSocket schemes (only allow ws:// or wss://).',
                'affected_url': ws_url,
                'impact': 'Non-WebSocket schemes can lead to protocol misuse if not handled properly.'
                }
            )
            ws_report[ws_url] = handshake_res
            continue
        
        # Validate port range
        try:
            port = int(port)  # Ensure port is an integer
            if not (0 <= port <= 65535):
                handshake_res.append(
                {
                'name': 'Invalid Port',
                'risk': 'Medium',
                'description': f"WebSocket URL {parsed_url} contains an invalid port, which should be rejected by the server.",
                'solution': 'Ensure server validates port numbers and rejects invalid ones.',
                'affected_url': parsed_url,
                'impact': 'Invalid ports can cause unexpected behavior if not handled.'
                }
                )
                ws_report[ws_url] = handshake_res
                continue
        except (TypeError, ValueError):
            logging.info(f"Invalid port for {ws_url}: {parsed_url.port}. Skipping this URL.")
            continue
            
        print("Starting primary checks: Origin Check, Authentication, Protocol Fuzzing")

        origin_results = []
        auth_results = []
        fuzz_results = []

        # 1️⃣ Origin Check
        origin_result = test_origin_check(ws_url)
        if origin_result:
            origin_results.append(origin_result)
        
        # 2️⃣ Authentication Check
        auth_result = test_authentication(ws_url)
        if auth_result:
            auth_results.append(auth_result)
        
        # 3️⃣ Protocol Fuzzing for each payload
        for payload in payloads:
            fuzz_result = test_fuzzing(ws_url, payload)
            if fuzz_result:
                fuzz_results.append(fuzz_result)

        # Store results
        vulnerabilities.extend(origin_results)
        di1['Origin'] += len(origin_results)

        vulnerabilities.extend(auth_results)
        di1['Authentication'] += len(auth_results)

        vulnerabilities.extend(fuzz_results)
        di1["Fuzzing"] += len(fuzz_results)

        print("Starting Handshake & HTTP Request Tests")
        i=1
        for test_func in handshake_tests:
            print(i)
            i+=1
            result = test_func(host, port, path,scheme)
            if result:
                handshake_res.append(result)

        vulnerabilities.extend(handshake_res)
        di1["Fuzzing"] += len(handshake_res)

        # 5️⃣ Payload Handling & Fragmentation Tests (Vuln #23-40)
        payload_res = []
        print("Starting Payload Handling & Fragmentation Tests")

        #it works but get rid of yellow error msg
        for test_func in payload_tests:
            print(i)
            i+=1
            result = test_func(ws_url)
            if result:
                payload_res.append(result)

        vulnerabilities.extend(payload_res)
        di1["Payload"] += len(payload_res)
        
        # # 6️⃣ Authentication & Session Management Tests (Vuln #41-46)
        session_res = []
        print("Starting Authentication & Session Management Tests")
        
        for test_func in auth_session_tests:
            print(i)
            i+=1
            result = test_func(ws_url)
            if result:
                session_res.append(result)

        vulnerabilities.extend(session_res)
        di1["Session"] += len(session_res)

        # # 7️⃣ Subprotocol & Extension Tests (Vuln #47-51)
        subprotocol_res = []
        print('Subprotocol & Extension Tests')
        
        for test_func in subprotocol_tests:
            print(i)
            i+=1
            result = test_func(host, port, path)
            if result:
                subprotocol_res.append(result)    
    #it works ig but get rid of yellow error msg

        for test_func in ws_subprotocol_tests:
            print(i)
            i+=1
            result = test_func(ws_url)
            if result:
                subprotocol_res.append(result)

        vulnerabilities.extend(subprotocol_res)
        di1['Subprotocol'] += len(subprotocol_res)

        # # 8️⃣ Security & Encryption Tests (Vuln #52-56)
        print('Starting Security & Encryption Tests')
        security_results = []

        for test_func in security_tests:
            print(i)
            i+=1
            result = test_func(host, port, path)
            if result:
                security_results.append(result)

        for test_func in ws_security_tests:
            print(i)
            i+=1
            result = test_func(ws_url)
            if result:
                security_results.append(result)

        vulnerabilities.extend(security_results)
        di1['Security'] += len(security_results)

        # # 9️⃣ DoS & Resource Management Tests (Vuln #57-64)
        dos_res = []
        print('Starting DoS & Resource Management Tests')
                
        for test_func in ws_dos_tests:
            print(i)
            i+=1
            result = test_func(ws_url)
            if result:
                dos_res.append(result)

        vulnerabilities.extend(dos_res)
        di1['DOS'] += len(dos_res)

        # # 🔟 Cross-Origin & Mixed Content Tests (Vuln #65-69)
        print("Starting Cross-Origin & Mixed Content Tests")
        cos_res = []
        
        for test_func in cross_origin_tests:
            print(i)
            i+=1
            result = test_func(ws_url)
            if result:
                cos_res.append(result)

        vulnerabilities.extend(cos_res)
        di1['Cross-Origin'] += len(cos_res)

        # # 1️⃣1️⃣ Other Vulnerabilities Tests (Vuln #70-75)
        print("Starting Other Vulnerabilities Tests")
        others = []
        
        for test_func in ws_other_tests:
            print(i)
            i+=1
            result = test_func(ws_url)
            if result:
                others.append(result)

        vulnerabilities.extend(others)
        di1['Others'] += len(others)

        ws_report[ws_url] = vulnerabilities
    print("All tests completed.")
    return ws_report, di1