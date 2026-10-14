"""Isolated demonstration roles; secrets only on inherited stdin or getpass."""
from common import *
from client import Client,restore_bundle
import argparse,getpass
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--role',choices=['alice','bob'],required=True);a=parser.parse_args();c.harden();session=None
    try:
        q=f.decode(sys.stdin.buffer.readline(16385))
        if a.role=='alice':
            if q['consent']!='CONFIRM':raise ValueError('explicit consent required')
            session=Session(q['wallets'],q['node']);session.dispatch(dict(command='open',name='DisposableAlice',password=q['wallet_password']));session.refresh()
            client=Client(q['client'],q['provider'],q['admin']);plain=c.read_private(Path(q['source']));quote=client.quote(len(plain));client.encrypt(quote['id'],plain);client.pay(quote['id'],session,q['consent'])
            print(f.canonical(dict(state='SUBMITTED_NOT_SETTLED',quote=quote['id'])).decode(),flush=True)
            if sys.stdin.buffer.readline(100).strip()!=b'CONTINUE':raise ValueError('confirmation reconciliation required')
            if client.status(quote['id'])['state']!='CONFIRMED_LOCAL':raise ValueError('not confirmed')
            client.upload(quote['id']);client.export(quote['id'],q['bundle'],q['bundle_password'].encode());print('{"stored":true}',flush=True)
        else:
            result=restore_bundle(q['bundle'],q['bundle_password'].encode(),q['destination']);print(f.canonical(result).decode(),flush=True)
    finally:
        if session:session.close()
if __name__=='__main__':
    try:main()
    except Exception:print('{"error":"REJECTED_OR_UNKNOWN_NO_AUTOMATIC_REPAYMENT"}',flush=True);sys.exit(1)
