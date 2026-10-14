"""Explicit local operator entry points. Never exposes sensitive RPC on HTTP."""
import argparse
import getpass
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import sys

from .index import Index, Native, hex32, alias_name
from .rpc import rpc
from .server import Server

ROOT = Path(__file__).resolve().parents[2]


def wallet_module():
    spec = importlib.util.spec_from_file_location('v1_wallet_foundation', ROOT/'src/wallet/wallet.py')
    f = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(f)
    return f

def wallet_password():
    # Desktop mining uses its anonymous input pipe. Windows getpass otherwise
    # reads the console rather than that pipe. Never echo or log this input.
    if sys.stdin.isatty():return getpass.getpass('Wallet password: ').encode()
    raw=sys.stdin.buffer.readline(4097)
    if len(raw)>4096 or not raw.endswith(b'\n'):raise ValueError('BOUNDED_PRIVATE_PASSWORD_INPUT_REQUIRED')
    return raw.rstrip(b'\r\n')

def load_wallet(value,password):
    from src.phase6a import wallet as c
    c.harden();return c.load(value,password)


def mine(port, f, wallet, helper, count, budget=16, pause=0):
    """One owned CPU worker. Ctrl+C kills only worker; never kills the node."""
    if type(count) is not int or not 1 <= count <= 100 or not 1 <= budget <= 4096:
        raise ValueError('EXPLICIT_BLOCK_BOUND_REQUIRED')
    if pause not in (0,.1,1):raise ValueError('CPU_PAUSE_BOUND')
    for _ in range(count):
        D, C = f.crypto('address', wallet['view'], wallet['public'], 0)
        while True:
            R, P = f.crypto('output', D, C, 0, 0)
            template = rpc(port, 'template', control=True, reward_key=P, R=R)
            if os.name=='nt':
                from .windows_owned import spawn
                child=spawn([str(helper.resolve())],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
            else:child = subprocess.Popen([sys.executable,str(ROOT/'apps/network_v1/owned_exec.py'),str(os.getpid()),str(helper.resolve())], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            try:
                output, _err = child.communicate(('mine-template-stats '+template['block']+' '+template['seed']+' '+template['difficulty']+' '+str(budget)+'\n').encode(), timeout=120)
                if child.returncode:
                    raise ValueError('MINING_WORKER_REJECTED')
            finally:
                if os.name=='nt':
                    from .windows_owned import stop
                    stop(child)
                elif child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        child.kill(); child.wait()
            measured=json.loads(output)
            mined=measured['block'];hashes=measured['hashes'];elapsed=measured['elapsed_seconds']
            if type(hashes) is not int or not 1<=hashes<=budget or not isinstance(elapsed,(int,float)) or elapsed<=0:raise ValueError('WORKER_MEASUREMENT')
            hashrate=round(hashes/elapsed,3)
            if pause:time.sleep(pause)
            if mined == 'NOT_FOUND':
                print(json.dumps(dict(state='SEARCHING_NEW_TEMPLATE', worker_threads=1,hashes=hashes,observed_hashrate=hashrate)), flush=True)
                continue
            # Node remains the authoritative PoW/reward/transaction validator.
            try:
                accepted = rpc(port, 'submit', control=True, block=mined)['accepted']
            except ValueError:
                print(json.dumps(dict(state='SUBMISSION_REJECTED_OR_UNKNOWN', retry_payment=False)), flush=True)
                raise
            print(json.dumps(dict(state='BLOCK_SUBMITTED', accepted=accepted,
                                  height=template['height'], reward_atomic=str(template['reward']), worker_threads=1,hashes=hashes,observed_hashrate=hashrate)), flush=True)
            break


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser()
    p.add_argument('action', choices=['serve', 'index', 'claim', 'proof', 'mine','export-claims','import-claims'])
    p.add_argument('--claims-file',type=Path)
    p.add_argument('--rpc', type=int, default=29881)
    p.add_argument('--port', type=int, default=29880)
    p.add_argument('--index', type=Path, default=Path('build/network-v1/public-index.sqlite'))
    p.add_argument('--helper', type=Path, required=True)
    p.add_argument('--wallet', type=Path)
    p.add_argument('--block')
    p.add_argument('--alias')
    p.add_argument('--signature', help='Public ownership proof only, never secret material')
    p.add_argument('--blocks', type=int, default=1)
    p.add_argument('--cpu-preset',choices=('light','balanced','maximum'),default='maximum')
    p.add_argument('--authorize-cpu-mining', action='store_true')
    p.add_argument('--consent-public-output-link', action='store_true')
    a = p.parse_args()
    native = Native(a.helper)
    if a.action == 'mine':
        if not a.authorize_cpu_mining or a.wallet is None:
            raise ValueError('EXPLICIT_MINING_CONSENT_AND_WALLET_REQUIRED')
        f = wallet_module()
        wallet = load_wallet(a.wallet,wallet_password())
        if wallet['authority'] != 'full':
            raise ValueError('FULL_RECOVERABLE_WALLET_REQUIRED')
        print('CPU MINING: one owned worker; Ctrl+C stops worker. No payment authorization.', flush=True)
        budget,pause={'light':(4,1),'balanced':(8,.1),'maximum':(16,0)}[a.cpu_preset]
        mine(a.rpc, f, wallet, a.helper, a.blocks,budget=budget,pause=pause)
        return
    if a.action == 'proof':
        if not a.consent_public_output_link:
            raise ValueError('VOLUNTARY_PUBLIC_OUTPUT_LINK_CONSENT_REQUIRED')
        block, alias = hex32(a.block), alias_name(a.alias)
        f = wallet_module()
        wallet = load_wallet(a.wallet,wallet_password())
        b = rpc(a.rpc, 'get_block', hash=block)
        d = native.describe(b['block'])
        spend = f.crypto('derive', wallet['seed'])[0]
        # Secrets travel only through child stdin and remain private in memory.
        signature = native.call('claim '+' '.join(map(str, (wallet['view'], wallet['public'], wallet['count'],
                                      d['R'], d['output_key'], 0, spend, block, alias))))
        print(json.dumps(dict(block=block, alias=alias, signature=signature)))
        return
    a.index.parent.mkdir(parents=True, exist_ok=True)
    index = Index(a.index, native)
    try:
        if a.action == 'claim':
            index.claim(a.block, a.alias, a.signature)
            print('PUBLIC_OUTPUT_OWNERSHIP_CLAIM_ACCEPTED')
        elif a.action == 'index':
            print(json.dumps(dict(indexed_blocks=index.refresh(a.rpc,force=True))))
        elif a.action=='export-claims':
            with a.claims_file.open('x',encoding='utf-8') as stream:json.dump(index.export_claims(),stream,sort_keys=True)
            print('PUBLIC_PROOF_DOCUMENT_EXPORTED')
        elif a.action=='import-claims':
            if a.claims_file.stat().st_size>1024*1024:raise ValueError('PROOF_DOCUMENT_BOUND')
            from .rpc import unique
            print(json.dumps(dict(imported=index.import_claims(json.loads(a.claims_file.read_bytes(),object_pairs_hook=unique)))))
        else:
            stop = threading.Event()
            def refresh():
                while not stop.is_set():
                    try:
                        index.refresh(a.rpc, stop=stop)
                    except Exception:
                        print('INDEX_REFRESH_UNAVAILABLE; cached indexed_at retained', flush=True)
                    stop.wait(15)
            thread = threading.Thread(target=refresh, daemon=True); thread.start()
            server = Server(a.port, index)
            try:
                print(f'READ_ONLY_SITE http://127.0.0.1:{server.server_port}; public release BLOCKED', flush=True)
                server.serve_forever()
            finally:
                server.server_close(); stop.set(); thread.join(timeout=25)
    finally:
        index.close()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('OPERATOR_CANCELLED')
    except Exception:
        raise SystemExit('V1_OPERATION_REJECTED; inspect safe prerequisites; no automatic retry')
