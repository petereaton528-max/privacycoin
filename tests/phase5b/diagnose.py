"""Public-only failure diagnosis for an interrupted disposable workload."""
from pathlib import Path
import importlib.util,json
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('gates',ROOT/'tests/phase5b/gates.py');g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
def main():
    run=ROOT/'build/phase5b-workload';scale=json.loads(next(run.glob('scale-*.json')).read_text());password=g.f.read_private(run/'fixture.password');node=g.h.Node(run,'node');node.start(ttl=3600)
    try:
        state=g.w.snapshot(node.rpc);counts={};diff={}
        for n in 'ABC':
            wallet=g.f.load(run/(n+'.wallet'),password);actual={(x['global_index'],x['amount'],x['spent']) for x in g.w.scan(wallet,state)['owned']};expected={(j,x['amount'],x['spent']) for j,x in enumerate(scale['model']) if x['owner']==n}
            counts[n]=dict(actual=len(actual),expected=len(expected));diff[n]=dict(missing=sorted(expected-actual)[:20],extra=sorted(actual-expected)[:20])
        result=dict(height=state['height'],model_outputs=len(scale['model']),private_in_model=len(scale['intents']),private_on_chain=sum(not x['coinbase'] for x in state['chain']),counts=counts,diff=diff)
        print(json.dumps(result));g.OUT.mkdir(parents=True,exist_ok=True);(g.OUT/'workload-diagnostic.json').write_text(json.dumps(result,indent=2)+'\n')
    finally:node.stop(crash=True)
if __name__=='__main__':main()
