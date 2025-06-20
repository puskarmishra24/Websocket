import socket
from base64 import b64encode
import ssl
import logging
from urllib.parse import urlparse
import csv
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


def test_working_websocket(host, port, path="/", scheme="ws"):
    """Test non-base64 Sec-WebSocket-Key header (Vuln #2)."""
    
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
        response = send_raw_handshake(host, port, req, scheme=scheme)
        print(response)
        if response is None:
            return None
        if "101 Switching Protocols" in response:
            return True
        
    except Exception as e:
        logging.info(f"Error in test_non_base64_sec_websocket_key for {host}:{port}: {e}")
        

lastone = ['wss://socketsbay.com/wss/v2/1/demo/','wss://streamer.cryptocompare.com/v2','wss://demos.kaazing.com/echo','wss://public-btc.nownodes.io/wss'
]
ls = []
for ws_url in lastone:
        if ws_url == '':
            continue
        parsed_url = urlparse(ws_url)
        
        host = parsed_url.hostname
        port = parsed_url.port or (443 if parsed_url.scheme == 'wss' else 80)

        # Validate port range
        try:
            port = int(port)  # Ensure port is an integer
            if not (0 <= port <= 65535):
                continue
        except (TypeError, ValueError):
            logging.info(f"Invalid port for {ws_url}: {parsed_url.port}. Skipping this URL.")
            continue
        path = parsed_url.path or "/"
        
        yesno = test_working_websocket(host, port, path, parsed_url.scheme)
        if yesno != True:
            ls.append(ws_url)
print(ls)

#safety = ['wss://streamer.cryptocompare.com', 'wss://data.tradingview.com/socket.io', 'wss://irc-ws.chat.twitch.tv', 'wss://gateway.discord.gg', 'wss://stream.binance.com:9443/ws', 'wss://echo.websocket.org', 'ws://demos.kaazing.com/amqp', 'wss://ws.ifelse.io', 'wss://ws.postman-echo.com/raw', 'wss://public-eth.nownodes.io/ws', 'wss://rpc.publicnode.com/ws', 'wss://ws.coinsdo.com/ws', 'ws://ws.vi-server.org/mirror', 'ws://websocket-echo-intustack.koyeb.app', 'wss://echo-websocket.fly.dev/.ws', 'ws://echo-server/ws', 'ws://echo.websocket.org']

#web_sockets = ['wss://echo.websocket.events/', 'wss://ws.ifelse.io/', 'wss://stream.binance.com:9443/ws/btcusdt@trade', 'wss://ws.coincap.io/prices?assets=bitcoin,ethereum', 'wss://api.gemini.com/v1/marketdata/btcusd', 'wss://ws.bitstamp.net', 'wss://api-pub.bitfinex.com/ws/2', 'wss://ws.blockchain.info/inv', 'wss://ws.kraken.com', 'wss://ws.okx.com:8443/ws/v5/public']

#checkthese = ['wss://socketsbay.com/wss/v2/<strong>1</strong>/<strong>demo</strong>/', 'wss://socketsbay.com/wss/v2/11/', 'wss://socketsbay.com/wss/v2/10/', 'wss://socketsbay.com/wss/v2/1/demo/', 'wss://syscoin-evm-rpc.publicnode.com', 'wss://ethereum-sepolia-rpc.publicnode.com', 'wss://terra-classic-rpc.publicnode.com:443/websocket', 'wss://arbitrum-sepolia-rpc.publicnode.com', 'wss://polygon-amoy-bor-rpc.publicnode.com', 'wss://kava-rpc.publicnode.com:443/websocket', 'wss://oraichain-rpc.publicnode.com:443/websocket', 'wss://opbnb-testnet-rpc.publicnode.com', 'wss://arbitrum-nova-rpc.publicnode.com', 'wss://cronos-rpc.publicnode.com:443/websocket', 'wss://injective-testnet-rpc.publicnode.com:443/websocket', 'wss://dora-rpc.publicnode.com:443/websocket', 'wss://haqq-rpc.publicnode.com:443/websocket', 'wss://avail-rpc.publicnode.com', 'wss://optimism-rpc.publicnode.com', 'wss://elys-rpc.publicnode.com:443/websocket', 'wss://babylon-rpc.publicnode.com:443/websocket', 'wss://fantom-rpc.publicnode.com', 'wss://asset-mantle-rpc.publicnode.com:443/websocket', 'wss://base-sepolia-rpc.publicnode.com']

#blah = ['wss://berachain-bepolia-rpc.publicnode.com', 'wss://bsc-rpc.publicnode.com', 'wss://fetch-rpc.publicnode.com:443/websocket', 'wss://moonriver-rpc.publicnode.com', 'wss://peaq-agung-rpc.publicnode.com', 'wss://linea-sepolia-rpc.publicnode.com', 'wss://opbnb-rpc.publicnode.com', 'wss://passage-rpc.publicnode.com:443/websocket', 'wss://tenet-rpc.publicnode.com:443/websocket', 'wss://taiko-hekla-rpc.publicnode.com', 'wss://cronos-pos-rpc.publicnode.com:443/websocket', 'wss://stride-rpc.publicnode.com:443/websocket', 'wss://polygon-bor-rpc.publicnode.com', 'wss://migaloo-rpc.publicnode.com:443/websocket', 'wss://polygon-amoy-heimdall-rpc.publicnode.com:443/websocket', 'wss://juno-rpc.publicnode.com:443/websocket', 'wss://ethereum-rpc.publicnode.com', 'wss://starknet-rpc.publicnode.com', 'wss://dymension-rpc.publicnode.com:443/websocket', 'wss://xpla-rpc.publicnode.com:443/websocket', 'wss://celestia-mocha-rpc.publicnode.com:443/websocket', 'wss://celer-rpc.publicnode.com:443/websocket', 'wss://sui-testnet-rpc.publicnode.com', 'wss://fantom-testnet-rpc.publicnode.com', 'wss://cosmos-rpc.publicnode.com:443/websocket', 'wss://iris-rpc.publicnode.com:443/websocket', 'wss://evmos-testnet-rpc.publicnode.com:443/websocket', 'wss://scroll-rpc.publicnode.com', 'wss://kava-evm-rpc.publicnode.com', 'wss://metis-sepolia-rpc.publicnode.com:443', 'wss://nibiru-rpc.publicnode.com:443/websocket', 'wss://sui-rpc.publicnode.com', 'wss://nibiru-evm-rpc.publicnode.com', 'wss://arbitrum-one-rpc.publicnode.com', 'wss://xpla-evm-rpc.publicnode.com', 'wss://ethereum-holesky-rpc.publicnode.com', 'wss://cheqd-rpc.publicnode.com:443/websocket', 'wss://evmos-evm-rpc.publicnode.com', 'wss://neutron-rpc.publicnode.com:443/websocket', 'wss://quicksilver-rpc.publicnode.com:443/websocket', 'wss://starknet-sepolia-rpc.publicnode.com', 'wss://chihuahua-rpc.publicnode.com:443/websocket']

#onemore = ['wss://polygon-heimdall-rpc.publicnode.com:443/websocket', 'wss://bahamut-rpc.publicnode.com', 'wss://taiko-rpc.publicnode.com', 'wss://mantra-testnet-rpc.publicnode.com:443/websocket', 'wss://axelar-rpc.publicnode.com:443/websocket', 'wss://atomone-rpc.publicnode.com:443/websocket', 'wss://fraxtal-holesky-rpc.publicnode.com:443', 'wss://berachain-rpc.publicnode.com', 'wss://soneium-rpc.publicnode.com', 'wss://terra-rpc.publicnode.com:443/websocket', 'wss://celestia-rpc.publicnode.com:443/websocket', 'wss://solana-rpc.publicnode.com', 'wss://evmos-rpc.publicnode.com:443/websocket', 'wss://chiliz-spicy-rpc.publicnode.com', 'wss://dymension-evm-rpc.publicnode.com', 'wss://blast-rpc.publicnode.com', 'wss://ethereum-hoodi-rpc.publicnode.com', 'wss://comdex-rpc.publicnode.com:443/websocket', 'wss://side-rpc.publicnode.com:443/websocket', 'wss://haqq-evm-rpc.publicnode.com', 'wss://medibloc-rpc.publicnode.com:443/websocket', 'wss://mantra-rpc.publicnode.com:443/websocket', 'wss://persistence-rpc.publicnode.com:443/websocket', 'wss://moonbeam-rpc.publicnode.com', 'wss://syscoin-tanenbaum-evm-rpc.publicnode.com', 'wss://avalanche-c-chain-rpc.publicnode.com', 'wss://omniflix-rpc.publicnode.com:443/websocket', 'wss://analog-rpc.publicnode.com', 'wss://saga-rpc.publicnode.com:443/websocket', 'wss://dymension-testnet-rpc.publicnode.com:443/websocket', 'wss://evmos-testnet-evm-rpc.publicnode.com', 'wss://unichain-rpc.publicnode.com', 'wss://injective-rpc.publicnode.com:443/websocket', 'wss://pulsechain-testnet-rpc.publicnode.com', 'wss://rebus-rpc.publicnode.com:443/websocket', 'wss://avail-turing-rpc.publicnode.com', 'wss://shentu-rpc.publicnode.com:443/websocket', 'wss://nolus-rpc.publicnode.com:443/websocket', 'wss://sifchain-rpc.publicnode.com:443/websocket', 'wss://celo-rpc.publicnode.com', 'wss://linea-rpc.publicnode.com', 'wss://rizon-rpc.publicnode.com:443/websocket', 'wss://polkadot-rpc.publicnode.com', 'wss://mantle-rpc.publicnode.com', 'wss://aurora-rpc.publicnode.com', 'wss://unichain-sepolia-rpc.publicnode.com']


#another = ['wss://bsc-testnet-rpc.publicnode.com', 'wss://sentinel-rpc.publicnode.com:443/websocket', 'wss://bitcanna-rpc.publicnode.com:443/websocket', 'wss://kujira-rpc.publicnode.com:443/websocket', 'wss://avalanche-fuji-c-chain-rpc.publicnode.com', 'wss://lava-rpc.publicnode.com:443/websocket', 'wss://sonic-blaze-rpc.publicnode.com:443', 'wss://dymension-testnet-evm-rpc.publicnode.com', 'wss://soneium-minato-rpc.publicnode.com', 'wss://osmosis-rpc.publicnode.com:443/websocket', 'wss://scroll-sepolia-rpc.publicnode.com', 'wss://metis-rpc.publicnode.com:443', 'wss://tenet-evm-rpc.publicnode.com', 'wss://dydx-rpc.publicnode.com:443/websocket', 'wss://iris-evm-rpc.publicnode.com', 'wss://solana-testnet-rpc.publicnode.com', 'wss://chiliz-rpc.publicnode.com', 'wss://akash-rpc.publicnode.com:443/websocket', 'wss://peaq-rpc.publicnode.com', 'wss://coreum-rpc.publicnode.com:443/websocket', 'wss://teritori-rpc.publicnode.com:443/websocket', 'wss://optimism-sepolia-rpc.publicnode.com', 'wss://elys-testnet-rpc.publicnode.com:443/websocket', 'wss://cronos-evm-rpc.publicnode.com', 'wss://base-rpc.publicnode.com', 'wss://sonic-rpc.publicnode.com:443', 'wss://stargaze-rpc.publicnode.com:443/websocket', 'wss://sei-rpc.publicnode.com:443/websocket', 'wss://regen-rpc.publicnode.com:443/websocket', 'wss://gnosis-rpc.publicnode.com', 'wss://gnosis-chiado-rpc.publicnode.com', 'wss://sei-evm-rpc.publicnode.com', 'wss://pulsechain-rpc.publicnode.com', 'wss://fraxtal-rpc.publicnode.com:443', 'wss://kusama-rpc.publicnode.com']

#lastone = ['wss://example.com:8443/serviceB&lt;/accept&gt;', 'ws://example.com:8000/echo', 'ws://example.com:8000/echo</code>', 'ws://73.12.130.25:8080/kwic&lt;/socks.transport&gt;', 'ws://73.12.130.25:8080/serviceB&lt;/connect&gt;', 'ws://73.12.130.25:8080/kwic,', 'ws://73.12.130.25:8080</code>.', 'ws://73.12.130.25:8080/serviceB</code>', 'wss://example.com:8443/serviceB&lt;/accept&gt;', 'ws://example.com:8000/echo', 'ws://example.com:8000/echo</code>', 'ws://73.12.130.25:8080/kwic&lt;/socks.transport&gt;', 'ws://73.12.130.25:8080/serviceB&lt;/connect&gt;', 'ws://73.12.130.25:8080/kwic,', 'ws://73.12.130.25:8080</code>.', 'ws://73.12.130.25:8080/serviceB</code>', 'wss://data.tradingview.com/socket.io/websocket?from=chart%2FXAUUSD%2FynDM0LUe-GOLD-ROUTE-MAP-UPDATE%2F&date=2025-06-19T11%3A31%3A14', 'wss://data.tradingview.com/socket.io/websocket?from=chart%2FTSLA%2Fj6CRTWOw-TSLA-It-s-still-downtrend%2F&date=2025-06-19T11%3A31%3A14', 'wss://data.tradingview.com/socket.io/websocket?from=chart%2FBTCUSDT%2Fqbmem81U-BTC-USD-4H-CHART-PATTERN%2F&date=2025-06-19T11%3A31%3A14']