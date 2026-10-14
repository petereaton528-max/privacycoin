"""Focused Windows Tk shutdown regression after full GUI run; no wallet secrets."""
from pathlib import Path
import json, os, subprocess, uuid
from gui import App,safe_root
from bridge import Bridge
from test_gui import wait

def main():
    assert os.name=='nt';out=Path(__file__).resolve().parents[2]/'docs/evidence/devnet-gui-v1/lifecycle.json';assert not out.exists()
    home='/tmp/privacycoin-gui-lifecycle-'+uuid.uuid4().hex;checks=[]
    for i in range(7):
        root=safe_root();root.withdraw();b=Bridge(home);app=App(root,b);wait(root,app)
        assert root.tk.call('after','info');app.shutdown()
        assert not root.tk.call('after','info');assert b.process.poll() is not None
        checks.append('Tk poll timer cancelled and WSL bridge exited '+str(i+1))
    # This test directory is empty and uniquely generated, never contains wallets.
    cleanup='from pathlib import Path; Path('+repr(home)+').rmdir()'
    subprocess.run(['wsl.exe','-d','Ubuntu-24.04','-u','privacydev','--','python3','-c',cleanup],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
    out.write_bytes(json.dumps(dict(result='PASS_FOCUSED_SHUTDOWN',checks=checks,reason='Full GUI run passed but repeated root destruction printed harmless pending-Tk-callback warnings; cancel timer explicitly and verify seven exits.'),indent=2).encode()+b'\n');print('PASS seven clean Tk/WSL exits')
if __name__=='__main__':main()
