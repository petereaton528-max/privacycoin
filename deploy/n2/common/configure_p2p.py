"""Write one private channel configuration; no processes or network started."""
from pathlib import Path
import argparse,hashlib,ssl
import p2p_channel as pc
from common import c,save_json
def main():
    p=argparse.ArgumentParser()
    p.add_argument('--role',choices=['acceptor','connector'],required=True)
    p.add_argument('--listen-port',type=int,required=True);p.add_argument('--target-port',type=int,required=True)
    p.add_argument('--endpoint',default='127.0.0.1');p.add_argument('--socks-port',type=int)
    for name in ('cert','key','ca','peer-cert','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();c.harden()
    # Only a public certificate is used to derive the exact remote pin.
    peer=ssl.PEM_cert_to_DER_cert(c.read_private(a.peer_cert).decode('ascii'))
    value=dict(version=1,role=a.role,listen_port=a.listen_port,target_port=a.target_port,endpoint=a.endpoint,socks_port=a.socks_port,cert=str(a.cert),key=str(a.key),ca=str(a.ca),peer_sha256=hashlib.sha256(peer).hexdigest())
    pc.validate(value);pc.context(value);save_json(a.output,value)
    print('Private P2P configuration created; no channel, Tor, mining or payment started.')
if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('P2P configuration rejected. Inspect paths, permissions, certificates and ports; private details withheld.')
