"""Bound native node behind real ticket-free TLS and local SOCKS fixture.
No Internet Tor: Tor is only asked to verify its networking-disabled config.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,os,socket,ssl,subprocess,threading,time
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--installed',type=Path,required=True);p.add_argument('--profile',type=Path,required=True);p.add_argument('--work',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    os.umask(0o077)
    if a.work.exists() or not a.work.name.startswith('pc-candidate-profile-binding-'):raise ValueError('FRESH_PRIVATE_WORK_REQUIRED')
    a.work.mkdir(mode=0o700)
    os.environ.update(PC_DEVELOPMENT_NETWORK='candidate-lab',PC_CANDIDATE_PROFILE=str(a.profile),PC_OFFLINE_BINDING=str(a.installed/'candidate-native/full/BINDING.json'),PC_DEVNET_NATIVE_ROOT=str(a.installed))
    from apps.network_v1.candidate_runtime import Runtime
    from apps.network_v1.public_network import PublicTorSession,PublicChannel,Directory,require_public_context
    from apps.network_v1 import onion
    from apps.network_v1.tests.test_public_network import descriptor
    from apps.network_v1.tests.local_socks import Socks
    from src.network_identity import NETWORK,GENESIS,PROFILE
    checks=[];objects=[];threads=[];failure=None;began=time.monotonic()
    def check(name,ok):
        if not ok:raise AssertionError(name)
        checks.append(name)
    def port():
        with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
    try:
        runtime=Runtime(a.work/'node',a.installed/'candidate-native/full',a.profile,32281,32282,32290);objects.append(runtime)
        check('compiled native context matches validated transport context',runtime.identity==require_public_context())
        session=PublicTorSession(a.work/'disabled-tor',a.installed/'runtime/bin/tor',32282,32283,32284,32285,connector_base=32290,upstream=dict(host='127.0.0.1',port=22307));objects.append(session)
        check('bound Tor constructor accepts validated context without activation',session.owned.process is None and 'DisableNetwork 1' in session.config.read_text())
        check('explicit proxy retained without direct fallback','Socks5Proxy 127.0.0.1:22307' in session.config.read_text())
        identities=[]
        for i in (1,2):
            key,cert=a.work/('key'+str(i)),a.work/('cert'+str(i))
            subprocess.run([onion.openssl_binary(),'req','-x509','-newkey','ed25519','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=disposable-bound-test'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=10)
            key.chmod(0o600);cert.chmod(0o600);d=descriptor(i);d['certificate_sha256']=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest();identities.append((d,key,cert))
        own,key,cert=identities[0];remote,rkey,rcert=identities[1];ingress=port()
        server=PublicChannel(ingress,32282,own=lambda:own,key=key,certificate=cert,directory=Directory());objects.append(server)
        t=threading.Thread(target=server.run);t.start();threads.append(t)
        socks=Socks({own['onion']:ingress},seed=1401,chunk=37);objects.append(socks)
        slot=port();client=PublicChannel(slot,80,peer=own,socks=socks.port,own=lambda:remote,key=rkey,certificate=rcert,directory=Directory());objects.append(client)
        t=threading.Thread(target=client.run);t.start();threads.append(t)
        def query(change=None):
            q=dict(network=NETWORK,genesis=GENESIS,profile=PROFILE,command='status');q.update(change or {})
            raw=json.dumps(q,separators=(',',':')).encode()
            with socket.create_connection(('127.0.0.1',slot),timeout=5) as s:
                s.settimeout(15);s.sendall(NETWORK.encode()+len(raw).to_bytes(4,'big')+raw)
                frame=client.pc.frame(s,time.monotonic()+15,False)
                return json.loads(frame[20:])
        first=query();second=query()
        check('native status through real TLS pin proof framing and SOCKS',first['genesis']==GENESIS and first['network']==NETWORK and 'error' not in first)
        check('authenticated session reused for native responses',client.connections==1 and second==first)
        try:query(dict(genesis='a'*64))
        except (OSError,ValueError,TimeoutError):check('wrong Genesis rejected before native forwarding',True)
        else:raise AssertionError('wrong Genesis accepted')
    except BaseException as e:failure=type(e).__name__+': '+str(e);raise
    finally:
        for obj in reversed(objects):obj.close()
        for t in threads:t.join(3)
        if any(t.is_alive() for t in threads):failure=failure or 'OWNED_THREAD_LEAK'
        result=dict(result='FAIL' if failure else 'PASS',failure=failure,checks=checks,seconds=round(time.monotonic()-began,3),real_native=True,real_tls=True,socks='local controlled fixture',internet_tor=False)
        a.report.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
    if failure:raise RuntimeError(failure)
if __name__=='__main__':main()
