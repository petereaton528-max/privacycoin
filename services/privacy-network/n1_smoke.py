"""Private Tor bootstrap diagnostic. No public Tor, wallets or payments."""
from common import *
from tor_runtime import PrivateNetwork
import time
if __name__=='__main__':
    c.harden();base=NATIVE/'build/privacy-network-n1'/('smoke-'+str(time.time_ns()));network=None
    try:
        network=PrivateNetwork(base,19381);print('PRIVATE_FIXTURE',base,flush=True)
        for node in network.nodes:
            try:node.verify();print('CONFIG_OK',node.config.parent.name,flush=True)
            except Exception:
                import subprocess
                result=subprocess.run([str(node.binary),'-f',str(node.config),'--verify-config'],capture_output=True,text=True,timeout=10)
                print(result.stdout,result.stderr);raise
        network.start();print('PRIVATE_TOR_BOOTSTRAP_PASS',flush=True)
    finally:
        if network:network.close()
