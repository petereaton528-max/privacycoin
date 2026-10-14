"""Consolidate declared final cohorts; preserve earlier attempts and failure."""
from pathlib import Path
import json,statistics,math
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'docs/evidence/privacy-network-v01'
FILES=['attempt-1791518005306829313.json','supplement-1791518076468360714.json','lifecycle-1791517920683131792.json','expiry-race-after.json','windows-launch-final.json','demo-flow-1791518246633272952.json','regressions/backend/backend.json']
def distribution(values):
    return dict(n=len(values),median=statistics.median(values),p95_nearest_rank=sorted(values)[math.ceil(.95*len(values))-1])
def main():
    files=FILES+[p.name for p in sorted(OUT.glob('maximum-*.json'))]
    reports={name:json.loads((OUT/name).read_text()) for name in files}
    rows=[]
    for name,r in reports.items():
        assert r['result'].startswith('PASS'),name
        count=r.get('passed',len(r.get('checks',[])))
        if name=='expiry-race-after.json':count=1
        rows.append(dict(file=name,result=r['result'],passed=count,seconds=r.get('seconds')))
    a=reports[FILES[0]];b=reports[FILES[1]];metrics={}
    for key in a['trials'][0]:
        if key.endswith('_ms') or key.endswith('_per_second'):metrics[key]=distribution([t[key] for t in a['trials']])
    for key in b['trials'][0]:
        if key.endswith('_ms'):metrics['64KiB_'+key]=distribution([t[key] for t in b['trials']])
    value=dict(result='PASS_DECLARED_FINAL_COHORTS',final_checks=sum(row['passed'] for row in rows),cohorts=rows,metrics=metrics,resource_samples=a['resource_samples'],historical_failure_preserved='expiry-race-before.json: FAIL_REPRODUCED; fixed, final regression passes',notes='Counts are checks, not independent payments or formal security proofs. Earlier passing attempts are excluded. p95 nearest rank; small n. Upload/download include receiver rescan and persistence. Encryption includes durable local cache. Test mining is accelerated disposable Devnet, not network finality.')
    destination=OUT/'summary.json';assert not destination.exists();destination.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n',encoding='utf-8');print(json.dumps(value,indent=2))
if __name__=='__main__':main()
