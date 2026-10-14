"""Loopback-only HTTP transport bridge. No settlement or storage decisions."""
from common import *
from tor_transport import onion_address,COMMANDS,LIMIT
from http.server import BaseHTTPRequestHandler,HTTPServer
import argparse,signal
from n1_diagnostics import Diagnostics,emit
import re,time

def serve(port,upstream,host,diagnostics=None):
    c.harden();f.integer(port,1024,65535);f.integer(upstream,1024,65535);onion_address(host)
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError()))
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def setup(self):
            super().setup();self.connection.settimeout(5)
        def handle(self):
            # The deadline begins BEFORE BaseHTTPRequestHandler reads its first
            # line/header. An idle/partial Tor stream cannot block indefinitely.
            signal.alarm(5)
            try:super().handle()
            finally:signal.alarm(0)
        def do_POST(self):
            signal.alarm(15);connection=None
            trace=self.headers.get('X-PC-Trace','');trace=trace if re.fullmatch('[0-9a-f]{16}',trace) else 'none';started=time.monotonic()
            operation=self.path[1:] if self.path in {'/'+x for x in COMMANDS} else 'invalid'
            emit(diagnostics,'bridge_received',trace=trace,operation=operation)
            try:
                h=self.headers
                if h.get('Host')!=host+':80' or len(h.get_all('Host',[]))!=1 or len(h.get_all('Authorization',[]))>1 or len(h.get_all('Content-Length',[]))!=1 or h.get('Origin') is not None or h.get('Sec-Fetch-Site') is not None or h.get('Transfer-Encoding') is not None or h.get('Content-Type')!='application/json' or self.path not in {'/'+x for x in COMMANDS}:raise ValueError()
                size=int(h['Content-Length']);f.integer(size,0,LIMIT);raw=self.rfile.read(size)
                if len(raw)!=size:raise ValueError()
                f.decode(raw);headers={'Content-Type':'application/json'}
                if h.get('Authorization') is not None:
                    value=h['Authorization']
                    if not value.startswith('Bearer '):raise ValueError()
                    identity(value[7:]);headers['Authorization']=value
                signal.alarm(35);connection=http.client.HTTPConnection('127.0.0.1',upstream,timeout=30)
                connection.request('POST',self.path,body=raw,headers=headers)
                emit(diagnostics,'upstream_sent',trace=trace,operation=operation)
                response=connection.getresponse();body=response.read(LIMIT+1)
                if len(body)>LIMIT:raise ValueError()
                f.decode(body);status=response.status
            except Exception as error:
                emit(diagnostics,'bridge_error',trace=trace,operation=operation,code=type(error).__name__)
                status=400;body=f.canonical(dict(ok=False,code='TRANSPORT_REJECTED_OR_UNKNOWN'))
            finally:
                if connection is not None:connection.close()
            self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store');self.end_headers()
            try:self.wfile.write(body)
            except OSError:pass
            emit(diagnostics,'bridge_complete',trace=trace,operation=operation,status=status,elapsed_ms=(time.monotonic()-started)*1000)
    server=HTTPServer(('127.0.0.1',port),Handler)
    server.handle_error=lambda *_:None  # no request/exception diagnostic disclosure
    try:server.serve_forever(poll_interval=.1)
    finally:server.server_close()

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--port',type=int,required=True);p.add_argument('--upstream',type=int,required=True);p.add_argument('--onion',required=True);p.add_argument('--diagnostics',type=Path);a=p.parse_args()
    try:serve(a.port,a.upstream,a.onion,Diagnostics(a.diagnostics) if a.diagnostics else None)
    except Exception:sys.exit(1)
