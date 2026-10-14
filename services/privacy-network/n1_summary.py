"""Explicit final cohort, failures retained, descriptive performance summaries."""
from common import *
import time,statistics,math,platform
OUT=ROOT/'docs/evidence/privacy-network-n1'
def newest(pattern):
    path=sorted(OUT.glob(pattern))[-1];return path,json.loads(path.read_bytes())
def metrics(rows):
    names=sorted(set(x['operation'] for x in rows));result={}
    for name in names:
        values=sorted(x['ms'] for x in rows if x['operation']==name)
        result[name]=dict(n=len(values),median_ms=statistics.median(values),p95_ms=values[math.ceil(.95*len(values))-1],min_ms=min(values),max_ms=max(values))
    return result
def main():
    cohorts=[]
    for label,pattern,countkey in [('Tor/PC integration','integration-*.json','passed'),('Transport/bridge unit','unit-*.json','tests'),('V0.1 core','attempt-*.json','passed'),('V0.1 supplement','supplement-*.json','passed'),('Expiry repair','tests-*.json','passed'),('Windows launcher','windows-*.json','checks')]:
        path,report=newest(pattern);count=report[countkey];count=len(count) if isinstance(count,list) else count
        okay=report.get('result','PASS').startswith('PASS') and not report.get('errors',0) and not report.get('failures',0)
        cohorts.append(dict(cohort=label,path=path.relative_to(ROOT).as_posix(),checks=count,seconds=report['seconds'],result='PASS' if okay else 'FAIL'))
    folder=sorted(p for p in OUT.glob('wallet-*') if p.is_dir())[-1];wallet=json.loads((folder/'backend.json').read_bytes());timing=json.loads((folder/'timing.json').read_bytes())
    cohorts.append(dict(cohort='Wallet/backend',path=(folder/'backend.json').relative_to(ROOT).as_posix(),checks=timing['checks'],seconds=timing['seconds'],result='PASS' if wallet['result'].startswith('PASS') else 'FAIL'))
    integration_path,integration=newest('integration-*.json');perf_path,perf=newest('performance-*.json');probe_path,probe=newest('probe-*.json')
    failures=[]
    for path in sorted(OUT.glob('*.json')):
        if path.name in ('summary.json','audit.json'):continue
        report=json.loads(path.read_bytes());failed=report.get('result','').startswith('INCOMPLETE') or report.get('errors',0) or report.get('failures',0)
        if failed:failures.append(dict(path=path.name,result=report.get('result','FAILED_UNIT'),passed=report.get('passed'),errors=report.get('errors',0),label=report.get('failure_label',report.get('failure_code','See declared fixture result'))))
    con=perf.get('connections',[]);connection_stats={}
    if con:
        for key in con[0]:
            values=sorted(x[key] for x in con);connection_stats[key]=dict(n=len(values),median_ms=statistics.median(values),p95_ms=values[math.ceil(.95*len(values))-1])
    report=dict(starting_head='70a8f16893f9025ea1f869313ed410b5b1e95c54',final_cohorts=cohorts,final_cohort_checks=sum(x['checks'] for x in cohorts),final_cohort_failed_runs=sum(x['result']!='PASS' for x in cohorts),historical_failed_runs_retained=failures,invalid_zero_test_harness='wallet-1791524466748685114.json: NO TESTS RAN, excluded; corrected custom main runs 71 checks',integration_evidence=integration_path.name,integration_metrics=metrics(integration['metrics']),performance_evidence=perf_path.name,performance_result=perf['result'],performance_metrics=metrics(perf['metrics']),connection_metrics=connection_stats,resources=perf.get('resources',[]),probe_evidence=probe_path.name,probe_result=probe.get('result','FAIL_REPEATED_READ_PROBE'),probe_passed=sum(x['result']=='PASS' for x in probe['events']),paid_trials_in_final_integration=integration['paid_trials'],public_tor_routing=False,cross_physical_hosts='PENDING',independently_validating_hosts='NOT ACHIEVED',formal_security_proof=False,independent_audit=False)
    (OUT/'summary.json').write_bytes(json.dumps(report,indent=2,sort_keys=True).encode()+b'\n')
    # Provenance is public package metadata, not a secret-bearing private store.
    provenance=json.loads((NATIVE/'build/privacy-network-n1/tor-runtime/provenance.json').read_bytes());(OUT/'tor-provenance.json').write_bytes(f.canonical(provenance)+b'\n')
    print(json.dumps({k:report[k] for k in ('final_cohort_checks','final_cohort_failed_runs','performance_result','probe_result')}))
if __name__=='__main__':main()
