"""Actual framed-RPC monitor costs, separate from selection-model measurements."""
from pathlib import Path
import importlib.util,json,os,random,time,tempfile,socket,struct,subprocess,resource,tracemalloc
ROOT=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('phase5d_research',ROOT/'tests/phase5d/research.py');r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
h=r.h;f=r.f;OUT=r.OUT
def raw_rpc(node,cmd):
    q=f.canonical(dict(network=h.w.NETWORK,genesis=h.w.GENESIS,profile=h.w.PROFILE,command=cmd))
    with socket.create_connection(('127.0.0.1',node.rpc),timeout=3) as sock:
        sock.sendall(b'PrivacyCoinRPC04'+struct.pack('!I',len(q))+q)
        head=r.c.read(sock,20);assert head[:16]==b'PrivacyCoinRPC04'
        n=struct.unpack('!I',head[16:])[0];assert n<1024*1024
        data=json.loads(r.c.read(sock,n));assert data['profile']==h.w.PROFILE
        return data,40+len(q)+n
def usage():
    child=resource.getrusage(resource.RUSAGE_CHILDREN)
    return time.process_time()+child.ru_utime+child.ru_stime
def main():
    if (OUT/'overhead.json').exists():raise ValueError('Do not overwrite evidence')
    rows=[];rng=random.Random(51005)
    with tempfile.TemporaryDirectory(prefix='privacycoin-phase5d-overhead-') as tmp:
        base=Path(tmp);os.chmod(base,0o700);pwd=base/'a.password';password=os.urandom(32).hex().encode();f.write_private(pwd,password);h.g.cli('create',base/'a.wallet',pwd)
        wallet=f.load(base/'a.wallet',password);address=f.address(wallet,0);a=h.Node(base,'anchor');b=h.Node(base,'client');a.start()
        try:
            timestamp=int(time.time())-1200
            for i in range(3):a.mine(address,timestamp+120*i)
            b.start(peers=[a]);h.g.converge(a,b);fresh=a.status()
            key=base/'observer.key';pub=base/'observer.pub';msg=base/'observation';sig=base/'signature'
            def openssl(args):subprocess.run(['openssl']+args,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            openssl(['genpkey','-algorithm','ED25519','-out',str(key)]);os.chmod(key,0o600);openssl(['pkey','-in',str(key),'-pubout','-out',str(pub)])
            observation=r.canon(dict(profile=h.w.PROFILE,chain=fresh,sequence=1,issued=int(time.time())))
            msg.write_bytes(observation);openssl(['pkeyutl','-sign','-inkey',str(key),'-rawin','-in',str(msg),'-out',str(sig)])
            signature_bytes=sig.stat().st_size
            for trial in range(60):
                order=['baseline','monitor'];rng.shuffle(order)
                for mode in order:
                    tracemalloc.start();t=time.perf_counter();tcpu=usage();ac=r.cpu(a.p.pid);bc=r.cpu(b.p.pid)
                    local,nbytes=raw_rpc(b,'status');wire=nbytes
                    if mode=='monitor':
                        remote,n=raw_rpc(a,'status');wire+=n
                        assert all(local[k]==remote[k] for k in ('height','tip','work'))
                        chain,n=raw_rpc(b,'chain');wire+=n
                        assert fresh['tip'] in chain['chain']
                        openssl(['pkeyutl','-verify','-pubin','-inkey',str(pub),'-rawin','-in',str(msg),'-sigfile',str(sig)])
                        wire+=len(observation)+signature_bytes
                    elapsed=(time.perf_counter()-t)*1000;node_cpu=(r.cpu(a.p.pid)-ac)+(r.cpu(b.p.pid)-bc);parent_child_cpu=(usage()-tcpu)*1000
                    allocated=tracemalloc.get_traced_memory()[1];tracemalloc.stop()
                    rows.append(dict(trial=trial,mode=mode,wall_ms=elapsed,parent_and_crypto_child_cpu_ms=parent_child_cpu,node_cpu_ms=node_cpu*1000,application_plus_frame_bytes=wire,python_peak_allocated_bytes=allocated))
            result=dict(result='PASS',paired_trials=60,rows=rows,commands=h.g.commands,anchor_rss_bytes=r.rss(a.p.pid),client_rss_bytes=r.rss(b.p.pid),signature_bytes=signature_bytes,observation_bytes=len(observation),measurement='Counts actual framed request/response bytes plus signed-observation representation; no IP/TCP/TLS overhead. Signature observation transfer modeled by exact bytes, local file verification real. CPU includes OpenSSL child plus sampled nodes; /proc CPU quantized to ticks.',limitations=['Loopback only; no remote signature-delivery measurements','OS RSS is absolute, not incremental defense memory; allocation peaks scoped to each operation','Fixed valid checkpoint; issuance/expiry/replay predicates exercised in separate research matrix'])
            encoded=json.dumps(result,indent=2)+'\n'
            for secret in [password.decode(),wallet['seed'],wallet['view']]+f.crypto('derive',wallet['seed'])[:2]:assert secret not in encoded
            (OUT/'overhead.json').write_text(encoded);print('PASS 60 paired actual framed-RPC overhead trials',flush=True)
        finally:
            for node in h.g.nodes:node.stop()
if __name__=='__main__':main()
