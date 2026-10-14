"""Exercise the documented real-node helper and repeated public-address funding."""
from pathlib import Path
import json, os, subprocess, sys, tempfile, time
from backend import c,f,w,native,SOURCE

def main():
    out=SOURCE/'docs/evidence/devnet-gui-v1/helpers.json';assert not out.exists()
    h=native('gui_helpers_nodes','tests/phase4/gates.py');checks=[]
    with tempfile.TemporaryDirectory(prefix='privacycoin-gui-helpers-') as temp:
        base=Path(temp);os.chmod(base,0o700);port=h.g.port();p2p=h.g.port();script=str(Path(__file__).with_name('devnet.py'))
        child=subprocess.Popen([sys.executable,script,'serve','--data',str(base/'node'),'--port',str(port),'--p2p-port',str(p2p)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        try:
            assert b'DEVNET ONLY node on loopback' in child.stdout.readline();checks.append('documented serve starts real loopback node')
            address=f.address(f.full(),0)
            for blocks in (1,79,2):
                p=subprocess.run([sys.executable,script,'mine','--address',address,'--blocks',str(blocks),'--port',str(port)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=180)
                assert p.returncode==0;checks.append('documented miner repeated call '+str(blocks)+' blocks')
            assert w.rpc(port,'status')['height']==82;checks.append('first payment funding sequence actual 82 blocks')
            p=subprocess.run([sys.executable,script,'status','--port',str(port)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
            assert p.returncode==0 and b'height=82' in p.stdout;checks.append('documented status matches actual node')
            p=subprocess.run([sys.executable,script,'stop','--port',str(port)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
            assert p.returncode==0;child.wait(timeout=15);assert child.returncode==0;checks.append('documented stop shuts down node and wrapper')
            # SIGTERM cleanup must not leave a detached native daemon behind.
            child=subprocess.Popen([sys.executable,script,'serve','--data',str(base/'node'),'--port',str(port),'--p2p-port',str(p2p)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
            assert b'DEVNET ONLY' in child.stdout.readline();child.terminate();child.wait(timeout=15)
            try:w.rpc(port,'status');raise AssertionError('orphan node')
            except OSError:checks.append('wrapper SIGTERM cleans native node')
        finally:
            if child.poll() is None:child.terminate();child.wait(timeout=15)
    out.write_bytes(json.dumps(dict(result='PASS_HELPER_COMMANDS',checks=checks),indent=2).encode()+b'\n');print('PASS helper checks '+str(len(checks)))
if __name__=='__main__':main()
