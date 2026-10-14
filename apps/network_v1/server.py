"""Loopback-only cached public API/site. No wallet/admin/payment HTTP endpoints."""
import http.server
import json
from pathlib import Path
import threading
import time
from urllib.parse import parse_qs, urlsplit

from .rpc import GENESIS, NETWORK, PROFILE, VERSION

WEB = Path(__file__).with_name('web')


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, port, index):
        self.index = index
        self.slots = threading.BoundedSemaphore(8)
        self.budget_lock = threading.Lock()
        self.tokens, self.refilled = 120.0, time.monotonic()
        super().__init__(('127.0.0.1', port), Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def admit(self):
        with self.budget_lock:
            now = time.monotonic()
            self.tokens = min(120, self.tokens + (now-self.refilled)*10)
            self.refilled = now
            if self.tokens < 1:
                return False
            self.tokens -= 1
            return True


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    server_version = 'PCNetworkV1'
    sys_version = ''

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_):
        pass

    def respond(self, status, body, content='application/json'):
        raw = json.dumps(body, separators=(',', ':')).encode() if content == 'application/json' else body
        self.send_response(status)
        self.send_header('Content-Type', content + '; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.send_header('Referrer-Policy', 'no-referrer')
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def do_POST(self):
        self.respond(405, dict(error='READ_ONLY_API'))

    do_PUT = do_DELETE = do_PATCH = do_POST

    def do_GET(self):
        host = self.headers.get_all('Host', [])
        allowed = {'127.0.0.1:'+str(self.server.server_port), 'localhost:'+str(self.server.server_port)}
        if len(host) != 1 or host[0] not in allowed:
            self.respond(403, dict(error='HOST_DENIED'))
            return
        origins=self.headers.get_all('Origin',[])
        if len(origins)>1 or origins and origins[0] not in {'http://'+h for h in allowed} or self.headers.get('Sec-Fetch-Site')=='cross-site':
            self.respond(403,dict(error='ORIGIN_DENIED'));return
        if len(self.path) > 1024 or self.headers.get('Transfer-Encoding') or self.headers.get('Content-Length', '0') != '0':
            self.respond(400, dict(error='REQUEST_BOUNDS'))
            return
        if not self.server.admit():
            self.respond(429, dict(error='RATE_LIMIT'))
            return
        try:
            url = urlsplit(self.path)
            if url.scheme or url.netloc or url.fragment:
                raise ValueError('TARGET')
            params = parse_qs(url.query, strict_parsing=True, max_num_fields=4)
            if any(len(v) != 1 for v in params.values()):
                raise ValueError('QUERY')
            p = {k:v[0] for k,v in params.items()}
            static = {'/':'index.html', '/app.js':'app.js', '/style.css':'style.css'}
            if url.path in static and not p:
                name = static[url.path]
                content = {'html':'text/html', 'js':'text/javascript', 'css':'text/css'}[name.split('.')[-1]]
                self.respond(200, (WEB/name).read_bytes(), content)
                return
            index = self.server.index
            if url.path == '/api/v1/network' and not p:
                value = dict(version=VERSION, network=NETWORK, genesis=GENESIS, profile=PROFILE, **index.state())
            elif url.path == '/api/v1/blocks' and set(p) <= {'offset','limit'}:
                value = dict(blocks=index.blocks(int(p.get('offset', 0)), int(p.get('limit', 25))))
            elif url.path.startswith('/api/v1/blocks/') and not p:
                value = index.block(url.path.removeprefix('/api/v1/blocks/'))
                if value is None:
                    self.respond(404, dict(error='BLOCK_NOT_INDEXED'))
                    return
            elif url.path == '/api/v1/leaderboard' and set(p) <= {'day'}:
                value = index.leaderboard(p.get('day'))
            elif url.path == '/api/v1/capabilities' and not p:
                value = dict(read_only=True, smart_contracts=False, token_issuance=False,
                             payment_http=False, mining_http=False, wallet_http=False,
                             documentation='docs/network-v1', release='BLOCKED_ENGINEERING_CANDIDATE')
            else:
                self.respond(404, dict(error='ENDPOINT_NOT_FOUND'))
                return
            self.respond(200, value)
        except (ValueError, TypeError, KeyError):
            self.respond(400, dict(error='INVALID_QUERY'))
        except Exception:
            self.respond(503, dict(error='INDEX_UNAVAILABLE'))
