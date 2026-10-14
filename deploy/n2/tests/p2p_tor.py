"""Actual P2P/TLS over official isolated TestingTorNetwork; NOT public Tor."""
from p2p_connectivity import *
from tor_runtime import PrivateNetwork
def main():
    c.harden();start=time.monotonic();base=private_dir(NATIVE/'build/privacycoin-n2-connectivity'/('tor-'+str(time.time_ns())))
    nodes=[];channels=[];tor=None;checks=[];metrics={};report={};stage='LOCAL_SETUP'
    def check(label,value=True):
        if not value:raise AssertionError(label)
        checks.append(label);print('PASS',label,flush=True)
    def start_channel(v):
        obj=pc.Channel(v);t=threading.Thread(target=obj.run);t.start();channels.append((obj,t));return obj
    try:
        keys,pin=certificates(base/'tls');A=OwnedNode(base,'node-A');B=OwnedNode(base,'node-B');nodes=[A,B];A.start();B.start()
        server=start_channel(configuration(keys,pin,'acceptor',h.g.port(),A.p2p))
        tor=PrivateNetwork(base/'isolated-tor',server.v['listen_port']);t=time.monotonic();stage='PRIVATE_TOR_BOOTSTRAP';tor.start();metrics['bootstrap_ms']=(time.monotonic()-t)*1000
        stage='CHANNEL_CONFIGURATION'
        v=configuration(keys,pin,'connector',h.g.port(),1024);v.update(target_port=80,endpoint=tor.hostname,socks_port=tor.socks_port)
        connector=start_channel(v);until=time.monotonic()+90;errors=0;t=time.monotonic();stage='ONION_PROTOCOL_READINESS'
        while True:
            try:observed=request(v['listen_port']);break
            except (OSError,ValueError):
                errors+=1
                if time.monotonic()>=until:raise AssertionError('private onion P2P readiness')
                time.sleep(.2)
        metrics['first_protocol_readiness_ms']=(time.monotonic()-t)*1000;metrics['readiness_failed_attempts']=errors
        check('real isolated Tor SOCKS plus mutual TLS genesis observation',observed['tip']==w.GENESIS)
        stage='ONION_NODE_SYNC';B.stop();B.start(peer=types.SimpleNamespace(p2p=v['listen_port']))
        address=f.address(f.full(),0);stamp=int(time.time())-120*500
        for _ in range(3):stamp+=120;A.mine(address,stamp)
        until=time.monotonic()+90;t=time.monotonic()
        while B.status()!=A.status() and time.monotonic()<until:time.sleep(.05)
        check('three real blocks independently synchronized over onion P2P',B.status()==A.status());metrics['sync_ms']=(time.monotonic()-t)*1000
        for _ in range(5):check('repeated actual onion TLS P2P status',request(v['listen_port'])['tip']==A.status()['tip'])
        tor.close();tor=None
        try:request(v['listen_port'])
        except (OSError,ValueError):check('stopped Tor fails closed without direct connection')
        else:raise AssertionError('Tor outage must fail')
        report['result']='PASS_ISOLATED_TOR_P2P'
    except Exception as e:
        safe={'PRIVATE_TOR_BOOTSTRAP_TIMEOUT','PRIVATE_TOR_CONSENSUS_TIMEOUT','PRIVATE_TOR_PROCESS_FAILED','PRIVATE_TOR_RELAY_FAILED','PORT'}
        report.update(result='INCOMPLETE_WITH_BLOCKERS',failure_stage=stage,failure_type=type(e).__name__,failure_label=str(e) if isinstance(e,AssertionError) or str(e) in safe else 'Private details withheld')
    finally:
        for obj,t in reversed(channels):obj.close();t.join(timeout=15)
        for node in nodes:node.stop()
        if tor:tor.close()
        report.update(checks=checks,passed=len(checks),metrics=metrics,seconds=time.monotonic()-start,private_fixture=str(base),public_onion=False,physical_host='NOT_TESTED',owned_services_remaining=0)
        (OUT/('tor-'+str(time.time_ns())+'.json')).write_bytes(f.canonical(report)+b'\n');print(report['result'])
    if not report['result'].startswith('PASS'):sys.exit(1)
if __name__=='__main__':main()
