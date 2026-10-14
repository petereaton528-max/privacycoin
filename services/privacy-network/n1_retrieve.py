"""Independent Bob console. No payer wallet or private key is opened."""
from common import *
from tor_transport import OnionTransport
from client import retrieve
import argparse,getpass

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--socks-port',type=int,required=True);a=p.parse_args()
    print('DEVNET ONLY. Requires an already running Tor client. No direct fallback.')
    source=Path(input('Private encrypted retrieval bundle path: ').strip());password=getpass.getpass('Password: ').encode()
    bundle=f.open_sealed(c.read_private(source),password,'privacy-network-retrieval-v01')
    if bundle.get('version')!=2:raise ValueError('Requires explicitly Tor-bound bundle V2')
    endpoint=bundle['transport'];f.fields(endpoint,'kind host port provider')
    if endpoint['kind']!='tor-onion-v3' or endpoint['provider']!=bundle['provider']:raise ValueError('endpoint')
    transport=OnionTransport(endpoint['host'],endpoint['provider'],a.socks_port,endpoint['port'])
    dest=Path(input('NEW output under private 0700 WSL directory: ').strip());plain=retrieve(bundle,transport);c.write_private(dest,plain)
    print('Recovered bytes:',len(plain),'SHA256:',digest(plain))
if __name__=='__main__':
    try:main()
    except (Exception,EOFError,KeyboardInterrupt):print('Recovery rejected or UNKNOWN; no output overwritten, payment created or secret displayed.');sys.exit(1)
