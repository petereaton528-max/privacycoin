"""Bob's standalone retrieval: no wallet configuration or spending API."""
from common import *
from client import restore_bundle
import argparse,getpass
def main():
    p=argparse.ArgumentParser();p.add_argument('--bundle',type=Path,required=True);p.add_argument('--destination',type=Path,required=True);a=p.parse_args();c.harden()
    password=getpass.getpass('Private retrieval-bundle password: ').encode()
    result=restore_bundle(a.bundle,password,a.destination);print('Integrity verified:',result['sha256'],'Bytes:',result['bytes'])
if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt):print('Retrieval rejected. Check private bundle/password, provider, retention, node and NEW private destination. No file was accepted without integrity verification.');sys.exit(1)
