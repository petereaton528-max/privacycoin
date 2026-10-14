"""Create disabled, secret-free host setup templates. Never starts a public service."""
from common import *
from tor_runtime import prepare_public,OwnedTor,TOR
import argparse

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--home',type=Path,required=True);p.add_argument('--bridge-port',type=int,default=19381);p.add_argument('--socks-port',type=int,default=19050);a=p.parse_args()
    if a.home.exists() or a.home.is_symlink():raise ValueError('New private destination required; no overwrite')
    home=private_dir(a.home);path=prepare_public(home/'tor-disabled',a.bridge_port,a.socks_port);OwnedTor(TOR,path).verify()
    # Placeholders intentionally cannot launch or authorize payment. Enrollment
    # secret must be delivered separately over a private authenticated channel.
    save_json(home/'client.template',dict(version=1,devnet_only=True,home=str(home/'disposable-client'),node_rpc='REPLACE_WITH_NEW_ISOLATED_DEVNET_RPC_PORT',socks_port=a.socks_port,onion='REPLACE_WITH_VERIFIED_V3_ONION',provider='REPLACE_WITH_PROVIDER_ID',quote_admin='PRIVATE_ENROLLMENT_CAPABILITY_REQUIRED'))
    c.write_private(home/'README.txt',b'DISABLED CROSS-HOST TEMPLATE. No Tor, provider or node was started. Read docs/privacy-network/n1/CROSS_HOST_SETUP.md. Public onion activation needs explicit additional authorization. Never use TestingTorNetwork configuration on the public Tor network.\n')
    print('Disabled setup prepared:',home,'No onion endpoint published. Fill private configuration only after separate authorization.')
if __name__=='__main__':
    try:main()
    except Exception:print('Setup rejected. Check runtime, new private destination and N1 instructions. No existing data overwritten.');sys.exit(1)
