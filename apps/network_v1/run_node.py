"""Foreground operator-owned node; fresh V1 data only, no mining by default."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time

from .rpc import GENESIS, PROFILE

ROOT=Path(__file__).resolve().parents[2]


def main():
    from src.phase6a import wallet as c
    c.harden()
    p=argparse.ArgumentParser()
    p.add_argument('--data',type=Path,required=True)
    p.add_argument('--rpc',type=int,default=29881)
    p.add_argument('--p2p',type=int,default=29882)
    p.add_argument('--peer-loopback',type=int,action='append',default=[])
    p.add_argument('--resume-v1-data',action='store_true')
    a=p.parse_args()
    if os.name=='posix' and os.getuid()==0 or not a.data.is_absolute() or any('privacycoin-n2' in x.lower() for x in a.data.parts) or len(a.peer_loopback)>8 or a.rpc==a.p2p:
        raise ValueError('NEW_PRIVATE_V1_DATA_NONROOT_REQUIRED')
    if any(type(x)is not int or not 1024<=x<=65535 for x in [a.rpc,a.p2p,*a.peer_loopback]) or a.p2p in a.peer_loopback:
        raise ValueError('PORTS')
    with c.directory(a.data.parent):pass
    marker=a.data/'V1_OWNED_DATA.json'
    binary=ROOT/('build/monero-windows/phase4/privacycoin-hardened-devnet.exe' if os.name=='nt' else 'build/monero-linux/phase4/privacycoin-hardened-devnet')
    identity=dict(version=1,profile=PROFILE,genesis=GENESIS,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    if a.resume_v1_data:
        if c.f.decode(c.read_private(marker))!=identity:raise ValueError('NOT_MATCHING_V1_DATA')
    else:
        if os.name=='nt':c.win.mkdir(a.data,exclusive=True)
        else:a.data.mkdir(mode=0o700,exist_ok=False)
        c.write_private(marker,c.f.canonical(identity))
    with c.directory(a.data):pass
    for port in [a.rpc,a.p2p]:
        with socket.socket() as s:
            # Match the native acceptor's reuse behavior: a closed connection's
            # TIME_WAIT is not a foreign listener. Active listeners still reject.
            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            s.bind(('127.0.0.1',port))
    args=[str(binary),'--data-dir',str(a.data/'node'),'--rpc-port',str(a.rpc),'--p2p-port',str(a.p2p)]
    from src.network_identity import selected
    if selected()[0]!='PrivacyCoinDev01':args+=['--development-network','open-dev02']
    for port in a.peer_loopback:args+=['--peer-port',str(port)]
    parent=os.getpid()
    def guard():
        libc=ctypes.CDLL(None,use_errno=True)
        if libc.prctl(1,signal.SIGTERM,0,0,0)!=0 or os.getppid()!=parent:os._exit(125)
    with c.lock(a.data/'supervisor'):
        if os.name=='nt':
            from .windows_owned import spawn
            child=spawn(args,stdin=subprocess.DEVNULL)
        else:child=subprocess.Popen(args,stdin=subprocess.DEVNULL,preexec_fn=guard)
        try:
            print('V1_OWNED_NODE; no automatic mining/payment/Tor; Ctrl+C stops ONLY this node',flush=True)
            while child.poll() is None:time.sleep(.2)
            if child.returncode:raise ValueError('OWNED_NODE_FAILED')
        finally:
            if os.name=='nt':
                from .windows_owned import stop
                stop(child)
            elif child.poll() is None:
                child.terminate()
                try:child.wait(timeout=10)
                except subprocess.TimeoutExpired:child.kill();child.wait()


if __name__=='__main__':
    try:main()
    except KeyboardInterrupt:print('OWNED_NODE_STOPPED')
    except Exception:raise SystemExit('V1_NODE_REFUSED; existing N2 stores must not be reused')
