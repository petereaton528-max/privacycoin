"""TEST ONLY public control pipe to a disposable real node for Windows Tk tests."""
from pathlib import Path
import json, os, sys, tempfile, time
from backend import native
h=native('gui_node_fixture','tests/phase4/gates.py')
with tempfile.TemporaryDirectory(prefix='privacycoin-tk-node-') as temp:
    base=Path(temp);os.chmod(base,0o700);home=base/'wallets';home.mkdir(mode=0o700)
    node=h.Node(base,'node');node.start();stamp=int(time.time())-120*500
    print(json.dumps(dict(home=str(home),port=node.rpc)),flush=True)
    try:
        for raw in sys.stdin:
            q=json.loads(raw)
            if q['command']=='mine':
                for _ in range(q['blocks']):stamp+=120;node.mine(q['address'],stamp)
                result=node.status()
            elif q['command']=='pool':result=node.call('pool')
            elif q['command']=='stop':node.stop();result=dict(stopped=True)
            elif q['command']=='start':node.start();result=dict(started=True)
            else:raise ValueError('test control')
            print(json.dumps(result),flush=True)
    finally:node.stop(crash=True)
