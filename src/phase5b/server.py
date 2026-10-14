"""TLS sidecar over a fully validating local devnet node. Public cache only."""
from pathlib import Path
import importlib.util,argparse,os,json,socketserver,ssl,struct,time,zlib,sqlite3,threading
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('sync_transport',ROOT/'src/phase5b/transport.py');t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
w=t.w;f=t.f

class Service:
    def __init__(self,port,role,index):
        self.port=port;self.role=role;self.index=Path(index)
        self.index.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        parent=self.index.parent.stat()
        if parent.st_uid!=os.getuid() or parent.st_mode&0o777!=0o700 or self.index.is_symlink() or (self.index.exists() and self.index.stat().st_size>32*1024*1024):raise ValueError('private bounded index directory required')
        self.db=sqlite3.connect(self.index,check_same_thread=False)
        if self.db.execute('PRAGMA page_size').fetchone()[0]!=4096:self.db.close();raise ValueError('unsupported index page size')
        self.db.execute('PRAGMA max_page_count=8192');self.db.execute('CREATE TABLE IF NOT EXISTS pages (key TEXT PRIMARY KEY,next INTEGER,body BLOB)');self.db.commit();os.chmod(self.index,0o600);self.lock=threading.Lock()
        # Public immutable pages only; never cache a current-tip assertion.
        self.manifest_snapshot=None;self.manifests={};self.manifest_bytes=0
    def close(self):self.db.close()
    def response(self,q):
        if type(q.get('version')) is not int or q.get('version')!=1 or q.get('role')!=self.role or q.get('profile')!=w.PROFILE or not isinstance(q.get('nonce'),str) or len(q['nonce'])!=64 or set(q)-{'version','role','profile','nonce','command','offset','count','tip','revision','instance'}:raise ValueError('identity')
        command=q.get('command');begin=time.perf_counter();hit=False
        if self.role=='anchor':
            allowed={'snapshot_id','sync_manifest','pool_page','history'}
            if command not in allowed:raise ValueError('anchor command')
            fields={k:q[k] for k in ('offset','count','tip','revision','instance') if k in q};extra={}
            if command=='sync_manifest':
                current=w.rpc(self.port,'snapshot_id')
                snapshot=tuple(current[k] for k in ('tip','height','revision','instance'))
                if type(fields.get('revision')) is not int or any(fields.get(k)!=current[k] for k in ('tip','revision','instance')):raise ValueError('snapshot changed')
                offset=fields.get('offset');count=fields.get('count')
                if type(offset) is not int or type(count) is not int or not 1<=offset<=current['height']+1 or not 1<=count<=32:raise ValueError('manifest bounds')
                if snapshot!=self.manifest_snapshot:
                    self.manifests.clear();self.manifest_bytes=0;self.manifest_snapshot=snapshot
                cachekey=(offset,count);payload=self.manifests.get(cachekey)
                # Keep the pre-existing anchor header unchanged: do not expose
                # a new shared-cache hit oracle. Timing is still observable.
                if payload is None:
                    response=w.rpc(self.port,command,**fields);payload=zlib.compress(f.canonical(response),6)
                    if len(payload)>t.MAX_WIRE:raise ValueError('response bound')
                    if len(self.manifests)>=64 or self.manifest_bytes+len(payload)>16*1024*1024:
                        self.manifests.clear();self.manifest_bytes=0
                    self.manifests[cachekey]=payload;self.manifest_bytes+=len(payload)
            else:
                response=w.rpc(self.port,command,**fields);payload=zlib.compress(f.canonical(response),6)
        else:
            if command!='history' or type(q.get('offset')) is not int or not 1<=q['offset']<=1024 or q.get('count')!=32:raise ValueError('data bounds')
            current=w.rpc(self.port,'snapshot_id')
            if q.get('tip')!=current['tip']:raise ValueError('data source not at anchored tip')
            key=w.PROFILE+'/'+current['tip']+'/'+str(q['offset'])
            row=self.db.execute('SELECT next,body FROM pages WHERE key=?',(key,)).fetchone()
            if row:next_height,payload=row;hit=True
            else:
                page=w.rpc(self.port,'pruned_history',offset=q['offset'],count=32,**{k:current[k] for k in ('tip','revision','instance')})
                payload=zlib.compress(t.p.pack(page['records'],True),6);next_height=page['next']
                self.db.execute('INSERT OR REPLACE INTO pages VALUES (?,?,?)',(key,next_height,payload));self.db.commit()
                if self.db.execute('SELECT COALESCE(SUM(length(body)),0) FROM pages').fetchone()[0]>16*1024*1024:
                    self.db.execute('DELETE FROM pages WHERE key != ?',(key,));self.db.commit()
            extra=dict(tip=current['tip'],height=current['height'],offset=q['offset'],next=next_height)
        if len(payload)>t.MAX_WIRE:raise ValueError('response bound')
        header=dict(version=1,role=self.role,profile=w.PROFILE,nonce=q['nonce'],preprocess_ms=(time.perf_counter()-begin)*1000,cache_hit=hit,**extra)
        return header,payload

class Server(socketserver.TCPServer):
    allow_reuse_address=True
    def get_request(self):
        sock,address=super().get_request();sock.settimeout(30)
        try:return self.context.wrap_socket(sock,server_side=True),address
        except Exception:sock.close();raise

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.sync_deadline=time.monotonic()+30
            q=t.decode(t.frame(self.request,8192))
            with self.server.service.lock:header,payload=self.server.service.response(q)
            if self.server.mutate:header,payload=self.server.mutate(q,header,payload)
            h=f.canonical(header);data=struct.pack('>I',len(h))+h+struct.pack('>I',len(payload))+payload
            if self.server.latency:time.sleep(self.server.latency)
            begin=time.perf_counter()
            for offset in range(0,len(data),8192):
                self.request.sendall(data[offset:offset+8192])
                if self.server.rate:time.sleep(max(0,min(offset+8192,len(data))/self.server.rate-(time.perf_counter()-begin)))
        except Exception:
            # Do not send exception strings or log request contents.
            return

def start(port,role,index,certificate,key,listen=0,rate=None,latency=0,mutate=None):
    service=Service(port,role,index);server=Server(('127.0.0.1',listen),Handler)
    server.context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);server.context.minimum_version=ssl.TLSVersion.TLSv1_3;server.context.load_cert_chain(str(certificate),str(key))
    server.context.maximum_version=ssl.TLSVersion.TLSv1_3
    server.service=service;server.rate=rate;server.latency=latency;server.mutate=mutate
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();return server,thread

def main():
    p=argparse.ArgumentParser(description='Opt-in keyless development sync sidecar')
    p.add_argument('--node-rpc-port',type=int,required=True);p.add_argument('--role',choices=['anchor','data'],required=True);p.add_argument('--index',type=Path,required=True)
    p.add_argument('--certificate',type=Path,required=True);p.add_argument('--key-file',type=Path,required=True);p.add_argument('--listen-port',type=int,required=True)
    a=p.parse_args();f.read_private(a.key_file);server,thread=start(a.node_rpc_port,a.role,a.index,a.certificate,a.key_file,a.listen_port)
    try:thread.join()
    except KeyboardInterrupt:server.shutdown();thread.join()
    finally:server.server_close();server.service.close()
if __name__=='__main__':main()
