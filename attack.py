import os
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import time
import websocket
import logging
from base64 import b64encode
import socket
from urllib.parse import urlparse
from termcolor import colored
import requests
import urllib3

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_payload(file_name):
    """Load payloads from the specified file in the script's directory."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(base_dir, file_name)
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Payload file not found: {file_path}")
    with open(file_path, "r", encoding='utf-8', errors='ignore') as file:
        return [line.strip() for line in file.readlines() if line.strip()]

def attack_website(target_url, websocket_urls, attack_type="all"):
    """Main function to handle attack logic."""
    mode = attack_type
    websocket_payloads = load_payload("websocket_payload.txt")
    
    vulnerabilities = []

    if mode == "websocket" or mode == "all":
        print(colored("Starting WebSocket tests...", "yellow"))
        vulnerabilities += perform_websocket_tests(websocket_urls, websocket_payloads)

    return vulnerabilities

def perform_attack(zap, target_url, payloads, attack_type):
    """Perform the attack using the provided payloads."""
    def send_payload(payload):
        try:
            response = zap.urlopen(f"{target_url}?input={payload}", timeout=10)
            time.sleep(0.1)
            return zap.core.alerts()
        except (requests.exceptions.SSLError, urllib3.exceptions.SSLError) as ssl_err:
            logging.error(f"SSL error for URL {target_url}?input={payload}: {ssl_err}")
            return []
        except requests.exceptions.RequestException as req_err:
            logging.error(f"Request error for URL {target_url}?input={payload}: {req_err}")
            return []

    vulnerabilities = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(tqdm(executor.map(send_payload, payloads), total=len(payloads)))

    for result in results:
        vulnerabilities.extend(result)

    return vulnerabilities

def test_origin_check(ws_url):
        """Test for missing origin checks."""
        try:
            ws = websocket.WebSocket()
            ws.connect(ws_url, origin="http://malicious-site.com", timeout=5)
            ws.send("test")
            response = ws.recv()
            ws.close()
            return {
                'name': 'Missing Origin Check',
                'risk': 'High',
                'description': f"WebSocket at {ws_url} accepts connections with invalid Origin header.",
                'solution': 'Implement strict Origin header validation on the server.',
                'affected_url': ws_url,
                'impact': 'Allows unauthorized access, potentially leading to session hijacking or data exposure.'
            }
        except websocket.WebSocketException as e:
            print(colored(f"Origin check failed for {ws_url}: {e}", "yellow"))
            return None
        
def test_authentication(ws_url):
        """Test for weak or missing authentication."""
        try:
            ws = websocket.WebSocket()
            ws.connect(ws_url, timeout=5)
            ws.send("test")
            response = ws.recv()
            ws.close()
            return {
                'name': 'Missing Authentication',
                'risk': 'High',
                'description': f"WebSocket at {ws_url} allows connections without authentication.",
                'solution': 'Implement strong authentication mechanisms (e.g., tokens, API keys).',
                'affected_url': ws_url,
                'impact': 'Unauthorized users can access WebSocket data, leading to data leakage or manipulation.'
            }
        except websocket.WebSocketException as e:
            print(colored(f"Authentication test failed for {ws_url}: {e}", "yellow"))
            return None

def test_fuzzing(ws_url, payload):
        """Perform protocol fuzzing."""
        try:
            ws = websocket.WebSocket()
            ws.connect(ws_url, timeout=5)
            ws.send(payload)
            response = ws.recv()
            ws.close()
            if response:
                return {
                    'name': 'Protocol Fuzzing Vulnerability',
                    'risk': 'Medium',
                    'description': f"WebSocket at {ws_url} responds to malformed payload: {payload}",
                    'solution': 'Validate and sanitize all incoming WebSocket messages.',
                    'affected_url': ws_url,
                    'impact': 'Malformed messages could crash the server or expose sensitive data.'
                }
            return None
        except websocket.WebSocketException as e:
            print(colored(f"Fuzzing test failed for {ws_url}: {e}", "yellow"))
            return None
        
def send_raw_handshake(host, port, request_headers):
    """Send a raw WebSocket handshake to the server and capture response."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.send(request_headers.encode())
    response = s.recv(4096).decode()
    s.close()
    return response

def test_omit_sec_websocket_key(host, port, path="/"):
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
        'result': 'Vulnerable' if "101 Switching Protocols" in response else 'Secure',
        'details': response
    }

def test_non_base64_sec_websocket_key(host, port, path="/"):
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
        'result': 'Vulnerable' if "101 Switching Protocols" in response else 'Secure',
        'details': response
    }

def test_oversized_sec_websocket_key(host, port, path="/"):
    big_key = b64encode(b"A" * 64).decode()
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
        'result': 'Vulnerable' if "101 Switching Protocols" in response else 'Secure',
        'details': response
    }

def test_duplicate_sec_websocket_key(host, port, path="/"):
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
        'result': 'Vulnerable' if "101 Switching Protocols" in response else 'Secure',
        'details': response
    }

def test_missing_sec_websocket_version(host, port, path="/"):
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
        'result': 'Vulnerable' if "101 Switching Protocols" in response else 'Secure',
        'details': response
    }

def test_invalid_sec_websocket_version(host, port, path="/"):
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
        'result': 'Vulnerable' if "101 Switching Protocols" in response else 'Secure',
        'details': response
    }

def test_conflicting_sec_websocket_version(host, port, path="/"):
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
        'result': 'Vulnerable' if "101 Switching Protocols" in response else 'Secure',
        'details': response
    }

import socket
import ssl

def send_custom_handshake(host, port, request):
    """Send a custom handshake request and return response."""
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(request.encode())
        response = sock.recv(4096).decode()
        return response

def test_wrong_upgrade_header(host, port, path="/"):
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocketty\r\n"  # intentionally wrong
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: testtesttesttesttesttest==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    response = send_custom_handshake(host, port, request)
    if "101" in response:
        return {
            'name': 'Wrong Upgrade Header',
            'risk': 'High',
            'description': 'Server accepted handshake with wrong Upgrade header.',
            'solution': 'Enforce strict Upgrade header validation.',
            'affected_host': f"{host}:{port}"
        }

def test_missing_connection_header(host, port, path="/"):
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Key: testtesttesttesttesttest==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    response = send_custom_handshake(host, port, request)
    if "101" in response:
        return {
            'name': 'Missing Connection Header',
            'risk': 'High',
            'description': 'Server accepted handshake without Connection header.',
            'solution': 'Connection: Upgrade header is required for security.',
            'affected_host': f"{host}:{port}"
        }

def test_case_sensitive_headers(host, port, path="/"):
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "uPgradE: websocket\r\n"  # intentionally mixed-case
        "cOnneCtion: Upgrade\r\n"
        "sEc-websocKet-key: testtesttesttesttesttest==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    response = send_custom_handshake(host, port, request)
    if "101" in response:
        return {
            'name': 'Case-Sensitive Headers',
            'risk': 'Medium',
            'description': 'Server did not validate header names as case-insensitive.',
            'solution': 'Ensure case-insensitive header parsing as per RFC.',
            'affected_host': f"{host}:{port}"
        }

def test_oversized_headers(host, port, path="/"):
    big_value = "A" * 8000
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"X-Big-Header: {big_value}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: testtesttesttesttesttest==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    response = send_custom_handshake(host, port, request)
    if "101" in response:
        return {
            'name': 'Oversized Headers',
            'risk': 'Medium',
            'description': 'Server accepted handshake with oversized headers.',
            'solution': 'Set limits for header size to prevent resource exhaustion.',
            'affected_host': f"{host}:{port}"
        }

def test_missing_host_header(host, port, path="/"):
    request = (
        f"GET {path} HTTP/1.1\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: testtesttesttesttesttest==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    response = send_custom_handshake(host, port, request)
    if "101" in response:
        return {
            'name': 'Missing Host Header',
            'risk': 'High',
            'description': 'Server accepted handshake without Host header.',
            'solution': 'Enforce Host header validation.',
            'affected_host': f"{host}:{port}"
        }

def test_fake_host_header(host, port, path="/"):
    request = (
        f"GET {path} HTTP/1.1\r\n"
        "Host: fake.example.com\r\n"  # intentionally fake
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: testtesttesttesttesttest==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    response = send_custom_handshake(host, port, request)
    if "101" in response:
        return {
            'name': 'Fake Host Header',
            'risk': 'Medium',
            'description': 'Server accepted handshake with incorrect Host header.',
            'solution': 'Validate Host header to match expected server domain.',
            'affected_host': f"{host}:{port}"
        }

def test_multiple_host_headers(host, port, path="/"):
    request = (
        f"GET {path} HTTP/1.1\r\n"
        "Host: real.example.com\r\n"
        "Host: fake.example.com\r\n"  # multiple Host headers
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: testtesttesttesttesttest==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    response = send_custom_handshake(host, port, request)
    if "101" in response:
        return {
            'name': 'Multiple Host Headers',
            'risk': 'High',
            'description': 'Server accepted handshake with multiple Host headers.',
            'solution': 'Reject requests with duplicate Host headers.',
            'affected_host': f"{host}:{port}"
        }

def perform_websocket_tests(websocket_urls, payloads):
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

        # 4️⃣ Handshake Tests
        handshake_results = []
        for ws_url in websocket_urls:
            parsed_url = urlparse(ws_url)
            host = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == "wss" else 80)
            path = parsed_url.path or "/"

            handshake_tests = [
                test_omit_sec_websocket_key,
                test_non_base64_sec_websocket_key,
                test_oversized_sec_websocket_key,
                test_duplicate_sec_websocket_key,
                test_missing_sec_websocket_version,
                test_invalid_sec_websocket_version,
                test_conflicting_sec_websocket_version,
                test_wrong_upgrade_header,
                test_missing_connection_header,
                test_case_sensitive_headers,
                test_oversized_headers,
                test_missing_host_header,
                test_fake_host_header,
                test_multiple_host_headers
            ]

            for test_func in handshake_tests:
                result = test_func(host, port, path)
                if result:
                    vulnerabilities.append(result)

        

    return vulnerabilities