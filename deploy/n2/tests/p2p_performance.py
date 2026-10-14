"""Twenty alternating loopback direct/mTLS status pairs, no payment or mining."""
from p2p_connectivity import *
import statistics,math
def main():
    c.harden();base=private_dir(NATIVE/'build/privacycoin-n2-connectivity'/('performance-'+str(time.time_ns())))
    node=OwnedNode(base,'node');channels=[];rows=[]
    try:
        keys,pin=certificates(base/'tls');node.start()
        sv=configuration(keys,pin,'acceptor',h.g.port(),node.p2p);cv=configuration(keys,pin,'connector',h.g.port(),sv['listen_port'])
        for v in (sv,cv):
            obj=pc.Channel(v);t=threading.Thread(target=obj.run);t.start();channels.append((obj,t))
        for i in range(20):
            for kind,port in ([('direct',node.p2p),('mtls',cv['listen_port'])] if i%2==0 else [('mtls',cv['listen_port']),('direct',node.p2p)]):
                t=time.monotonic();value=request(port);assert value['tip']==w.GENESIS
                rows.append(dict(pair=i,kind=kind,ms=(time.monotonic()-t)*1000))
        report=dict(result='PASS_PAIRED_LOCAL_P2P_LATENCY',samples=rows,summary={k:dict(n=20,median_ms=statistics.median([x['ms'] for x in rows if x['kind']==k]),p95_ms=sorted(x['ms'] for x in rows if x['kind']==k)[math.ceil(.95*20)-1]) for k in ('direct','mtls')},scope='Actual loopback P2P status; full fresh TLS handshake per request; not remote throughput/Internet latency or consensus performance',private_fixture=str(base),failures=0)
        (OUT/('performance-'+str(time.time_ns())+'.json')).write_bytes(f.canonical(report)+b'\n');print(json.dumps(report['summary']))
    finally:
        for obj,t in channels:obj.close();t.join(timeout=15)
        node.stop()
if __name__=='__main__':main()
