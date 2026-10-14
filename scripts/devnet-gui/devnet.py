"""Local disposable node lifecycle and public-address faucet; no wallet secrets."""
from pathlib import Path
import argparse, os, signal, subprocess, time
from backend import c, f, w, NATIVE, DEFAULT_HOME

def main():
    c.harden();parser=argparse.ArgumentParser(description='DEVNET ONLY — no valuable funds')
    parser.add_argument('command',choices=['serve','mine','status','stop']);parser.add_argument('--port',type=int,default=48081)
    parser.add_argument('--p2p-port',type=int,default=48080);parser.add_argument('--data',type=Path,default=DEFAULT_HOME/'node')
    parser.add_argument('--address');parser.add_argument('--blocks',type=int,default=80);args=parser.parse_args()
    c.f.integer(args.port,1024,65535);c.f.integer(args.p2p_port,1024,65535)
    if args.command=='serve':
        signal.signal(signal.SIGTERM,lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
        args.data.mkdir(parents=True,mode=0o700,exist_ok=True)
        with c.directory(args.data):pass
        node=subprocess.Popen([str(NATIVE/'build/monero-linux/phase4/privacycoin-hardened-devnet'),'--data-dir',str(args.data),'--rpc-port',str(args.port),'--p2p-port',str(args.p2p_port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(600):
                if node.poll() is not None:raise ValueError('Node did not start; check port and data directory')
                try:w.rpc(args.port,'status');break
                except (ValueError,OSError):time.sleep(.05)
            else:raise ValueError('Node startup timeout')
            print('DEVNET ONLY node on loopback RPC '+str(args.port)+'. Keep this terminal open. Ctrl+C stops it.',flush=True)
            node.wait()
        except KeyboardInterrupt:pass
        finally:
            if node.poll() is None:
                node.terminate()
                try:node.wait(timeout=10)
                except subprocess.TimeoutExpired:node.kill();node.wait()
    elif args.command=='mine':
        f.integer(args.blocks,1,120);D,C,sub=f.parse_address(args.address)
        state=w.rpc(args.port,'status')
        # The original devnet's monotonic timestamps are public header data.
        block=w.rpc(args.port,'get_block',hash=state['tip'])
        # Read the three existing CryptoNote header varints; no ledger change.
        raw=bytes.fromhex(block['block']);offset=0;values=[]
        for _ in range(3):
            value=0
            for shift in range(0,70,7):
                byte=raw[offset];offset+=1;value|=(byte&127)<<shift
                if byte<128:break
            else:raise ValueError('header varint')
            values.append(value)
        stamp=values[2] if state['height'] else int(time.time())-120*500
        if stamp+120*args.blocks>int(time.time()):raise ValueError('disposable timestamp headroom exhausted')
        for i in range(args.blocks):
            R,P=f.crypto('output',D,C,sub,0)
            stamp+=120;w.rpc(args.port,'mine',reward_key=P,R=R,timestamp=stamp)
            print('Mined disposable block '+str(i+1)+'/'+str(args.blocks),flush=True)
    elif args.command=='stop':
        w.rpc(args.port,'shutdown');print('Local disposable node shutdown requested.')
    else:
        status=w.rpc(args.port,'status');print('DEVNET ONLY height='+str(status['height'])+' tip='+status['tip']+' work='+str(status['work']))

if __name__=='__main__':
    try:main()
    except Exception:
        print('Devnet operation failed. Check local ports, public address, timestamp and private data directory. No secrets logged.');raise SystemExit(1)
