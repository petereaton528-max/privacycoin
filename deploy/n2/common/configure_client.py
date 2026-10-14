"""Create private client configuration; public endpoint and private enrollment separate."""
from pathlib import Path
import argparse,getpass,json,os,sys
from role import ROOT,bootstrap,checked_path
def main():
    p=argparse.ArgumentParser();p.add_argument('--home',type=Path,required=True);p.add_argument('--endpoint',type=Path,required=True);p.add_argument('--node-rpc',type=int,required=True);p.add_argument('--socks-port',type=int,required=True);a=p.parse_args()
    bootstrap()
    from common import private_dir,save_json,f,identity
    from tor_transport import onion_address
    home=checked_path(str(a.home))
    if 'privacycoin-n2' not in home.name or home.exists() or home.is_symlink():raise ValueError('NEW_N2_HOME_REQUIRED')
    e=f.decode(a.endpoint.read_bytes());f.fields(e,'version devnet_only onion provider')
    if type(e['version']) is not int or e['version']!=1 or e['devnet_only'] is not True:raise ValueError('ENDPOINT')
    onion_address(e['onion']);identity(e['provider']);f.integer(a.node_rpc,1024,65535);f.integer(a.socks_port,1024,65535)
    enrollment=identity(getpass.getpass('Private provider quote-enrollment capability (never public endpoint): ').strip())
    home=private_dir(home)
    save_json(home/'remote-profile.json',dict(version=1,devnet_only=True,home=str(home),node_rpc=a.node_rpc,socks_port=a.socks_port,onion=e['onion'],provider=e['provider'],quote_admin=enrollment))
    save_json(home/'client.json',dict(version=1,devnet_only=True,role='client',profile=str(home/'remote-profile.json')))
    print('Private client configuration created. No connection, mining or payment. Global freshness UNKNOWN.')
if __name__=='__main__':
    try:main()
    except Exception:print('Configuration rejected; secrets withheld. Nothing paid or connected.');sys.exit(1)
