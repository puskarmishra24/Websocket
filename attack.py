import os
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import time
import websocket
import logging
from termcolor import colored

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

def perform_websocket_tests(websocket_urls, payloads):
    """Perform WebSocket-specific tests."""
    vulnerabilities = []

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

    with ThreadPoolExecutor(max_workers=5) as executor:
        origin_results = executor.map(test_origin_check, websocket_urls)
        vulnerabilities.extend([v for v in origin_results if v])
        auth_results = executor.map(test_authentication, websocket_urls)
        vulnerabilities.extend([v for v in auth_results if v])

        fuzz_results = []
        for ws_url in websocket_urls:
            fuzz_results.extend(executor.map(lambda p: test_fuzzing(ws_url, p), payloads))
        vulnerabilities.extend([v for v in fuzz_results if v])

    return vulnerabilities