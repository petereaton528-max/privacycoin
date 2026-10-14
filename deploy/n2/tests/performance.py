"""Paired local dependency/provenance checks; no remote-performance claims."""
from pathlib import Path
import json,math,statistics,subprocess,sys,time
ROOT=Path(__file__).resolve().parents[3]
BUILT=Path('/home/privacydev/privacycoin-dev/Privacy_Coin/build/privacycoin-n2-preparation/source-candidate-4')
def dist(values):return dict(n=len(values),median_ms=statistics.median(values),p95_ms=sorted(values)[math.ceil(.95*len(values))-1],max_ms=max(values))
def main():
    samples=[]
    for i in range(10):
        for label,root in ([('historical_default',ROOT),('portable_built_source',BUILT)] if i%2==0 else [('portable_built_source',BUILT),('historical_default',ROOT)]):
            start=time.monotonic();p=subprocess.run([sys.executable,str(root/'deploy/n2/common/role.py'),'linux-check'],capture_output=True,timeout=15)
            samples.append(dict(trial=i,mode=label,ms=(time.monotonic()-start)*1000,result='PASS' if p.returncode==0 else 'FAIL'))
    report=dict(result='PASS' if all(s['result']=='PASS' for s in samples) else 'FAIL',scope='LOCAL paired Python-process + dependency/provenance validation, warm filesystem. Different mounted/native filesystems; not provider/network throughput or pure added overhead.',samples=samples,distributions={mode:dist([s['ms'] for s in samples if s['mode']==mode]) for mode in ('historical_default','portable_built_source')},remote_performance='PENDING')
    (ROOT/'docs/evidence/privacy-network-n2'/('performance-'+str(time.time_ns())+'.json')).write_text(json.dumps(report,indent=2));print(json.dumps(report['distributions']))
    if report['result']!='PASS':sys.exit(1)
if __name__=='__main__':main()
