"""Summarize final N1-R cohorts and retain all preceding failed artifacts."""
from common import *
import argparse,math,datetime
OUT=ROOT/'docs/evidence/privacy-network-n1-repair'

def distribution(values):
    values=sorted(values)
    return dict(n=len(values),median=(values[(len(values)-1)//2]+values[len(values)//2])/2,p95=values[math.ceil(.95*len(values))-1],min=values[0],max=values[-1]) if values else dict(n=0)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--campaign',type=Path,required=True);args=parser.parse_args()
    assert args.campaign.resolve().parent==OUT.resolve()
    campaign=json.loads(args.campaign.read_bytes());integrations=[(name,json.loads((OUT/name).read_bytes())) for name in campaign['acceptance_integrations']]
    def select(pattern,home,field,value):
        found=[(p,json.loads(p.read_bytes())) for p in OUT.glob(pattern)]
        found=[(p,r) for p,r in found if r.get('private_fixture')==home and r.get(field)==value]
        assert len(found)==1,(pattern,len(found));return found[0]
    first=integrations[0][1]['private_fixture'];last=integrations[-1][1]['private_fixture']
    stress=[(p,json.loads(p.read_bytes())) for p in OUT.glob('stress-*.json')]
    cycles=[(p,r) for p,r in stress if r['private_fixture']==first and r['requested']['provider_restarts']==20];assert len(cycles)==1
    soaks=[(p,r) for p,r in stress if r['private_fixture']==last and r['requested']['soak_seconds']==2700];assert len(soaks)==1
    performance=select('performance-*.json',last,'scope','Same provider and existing object, paired health-pinned decrypting retrieval; explicit in-memory V1 direct control only, never production fallback; all failures retained')
    artifact,soak=soaks[0];cycle_path,cycle=cycles[0];perf_path,perf=performance
    operations={}
    for _,r in integrations:
        for m in r['metrics']:operations.setdefault(m['operation'],[]).append(m['ms'])
    integration_performance={k:distribution(v) for k,v in operations.items()}
    tor_phases=[]
    for name,r in integrations:
        trace=Path(r['private_fixture'])/'client-diagnostics';events=[json.loads(x) for x in trace.read_bytes().splitlines()]
        starts=[i for i,x in enumerate(events) if x['event']=='tor_process_started' and x.get('role')=='auth0']
        for index,begin in enumerate(starts):
            end=starts[index+1] if index+1<len(starts) else len(events);part=events[begin:end]
            bootstrap={}
            for x in part:
                if x['event']=='tor_bootstrap' and x.get('progress')==100 and x.get('role') in ('client','service') and x['role'] not in bootstrap:bootstrap[x['role']]=x['monotonic_ns']
            ready=next((x['monotonic_ns'] for x in part if x['event']=='onion_service_ready'),None)
            if len(bootstrap)==2 and ready:
                complete=max(bootstrap.values());tor_phases.append(dict(evidence=name,phase='cold' if index==0 else 'warm',bootstrap_ms=(complete-part[0]['monotonic_ns'])/1e6,post_bootstrap_onion_ready_ms=(ready-complete)/1e6))
    perf_operations={}
    for m in perf['metrics']:perf_operations.setdefault(m['operation'],[]).append(m)
    paired={k:dict(all_samples=distribution([x['ms'] for x in v]),failures=sum(x['result']!='PASS' for x in v)) for k,v in perf_operations.items()}
    cycle_operations={}
    for event in cycle['events']:cycle_operations.setdefault(event['operation'],[]).append(event)
    cycle_latency={k:dict(all_samples=distribution([x['ms'] for x in v]),failures=sum(x['result']!='PASS' for x in v)) for k,v in cycle_operations.items()}
    soak_operations={}
    for event in soak['events']:soak_operations.setdefault(event['operation'],[]).append(event)
    soak_latency={k:dict(all_samples=distribution([x['ms'] for x in v]),failures=sum(x['result']!='PASS' for x in v)) for k,v in soak_operations.items()}
    warm=[x for x in soak['samples'] if x['elapsed']>=300];roles={}
    for sample in warm:
        for process in sample['processes']:roles.setdefault(process['role'],[]).append(process)
    resources={}
    for role,samples in roles.items():
        values=[x['rss_kib']/1024 for x in samples]
        resources[role]=dict(rss_mib=distribution(values),first_warm_mib=values[0],last_mib=values[-1],fds_min=min(x['fds'] for x in samples),fds_max=max(x['fds'] for x in samples),pid_lifetimes=len({x['pid'] for x in samples}))
        lifetimes={}
        for item in samples:lifetimes.setdefault(item['pid'],[]).append(item['cpu_seconds'])
        cpu=sum(v[-1]-v[0] for v in lifetimes.values())
        resources[role].update(sampled_cpu_delta_seconds=cpu,average_one_core_percent=100*cpu/(warm[-1]['elapsed']-warm[0]['elapsed']))
    all_artifacts=[]
    for p in sorted(OUT.rglob('*.json')):
        if p.name in ('summary.json','audit.json'):continue
        r=json.loads(p.read_bytes());checks=r.get('checks',[]);count=r.get('tests',r.get('passed',len(checks) if isinstance(checks,list) else checks))
        all_artifacts.append(dict(path=p.relative_to(OUT).as_posix(),result=r.get('result','INFORMATION'),checks_or_tests=count,failures=r.get('failures'),errors=r.get('errors'),skipped=r.get('skipped',0),seconds=r.get('seconds')))
    directory=[]
    home=Path(last)
    for log in (home/'tor').glob('*/notice.log'):
        lines=log.read_text(errors='replace').splitlines()
        directory.append(dict(role=log.parent.name,oom_events=sum("We're low on memory" in x for x in lines),late_vote_rejections=sum('cutoff for received votes' in x for x in lines)))
    gates=dict(consecutive_integrations=len(integrations)==3 and all(r['result']=='PASS_REAL_PRIVATE_TOR_AND_PC' and r['passed']==72 and r['paid_trials']==6 for _,r in integrations),cycles=cycle['result']=='PASS' and cycle['requested']==dict(reads=200,provider_restarts=20,tor_restarts=20,soak_seconds=0) and all(x['result']=='PASS' for x in cycle['events']),soak=soak['result']=='PASS' and soak.get('soak_elapsed',0)>=2700 and all(x['result']=='PASS' for x in soak['events']),performance=perf['result']=='PASS' and all(x['result']=='PASS' for x in perf['metrics']),source_stable=campaign.get('source_unchanged') is True,supervisor=campaign['result']=='PASS')
    result=dict(starting_commit='7b23fe66139add6a375ad1ee25104faa3c7cb7e2',started_at_utc='2026-10-09T06:33:03+00:00',observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),final_campaign=args.campaign.name,campaign_result=campaign['result'],source_unchanged=campaign.get('source_unchanged'),integrations=[dict(evidence=name,result=r['result'],passed=r['passed'],paid_trials=r['paid_trials']) for name,r in integrations],integration_performance_ms=integration_performance,paired_performance_evidence=perf_path.name,paired_performance_ms=paired,cycle_evidence=cycle_path.name,cycle_result=cycle['result'],cycle_latency_ms=cycle_latency,soak_evidence=artifact.name,soak_result=soak['result'],soak_elapsed=soak.get('soak_elapsed'),soak_latency_ms=soak_latency,soak_transport_failed_attempts=soak.get('transport_attempts',[]),soak_resource_after_300s=resources,sampled_peak_aggregate_rss_mib=max(sum(p['rss_kib'] for p in s['processes'])/1024 for s in soak['samples']),soak_storage_growth_bytes=soak['samples'][-1]['fixture_bytes']-soak['samples'][0]['fixture_bytes'],soak_resource_scope='Node, provider A, bridge and private Tor; excludes idle provider B and driver Python. PID lifetimes separated; not leak proof.',final_fixture_tor_notice_counts=directory,artifacts=all_artifacts,scope='All failed artifacts retained; latency samples separated by cohort; isolated loopback official Tor and disposable PC only')
    result['acceptance_gates']=gates;result['all_declared_acceptance_gates_pass']=all(gates.values())
    result['tor_phase_samples']=tor_phases
    result['paired_health_connection_components_ms']={k:distribution([x[k] for x in perf['connections']]) for k in ('proxy_tcp_ms','socks_onion_connect_ms','application_ms','total_ms')}
    path=OUT/'summary.json';assert not path.exists();path.write_bytes(json.dumps(result,indent=2,sort_keys=True).encode()+b'\n');print(path.name,campaign['result'],gates)
if __name__=='__main__':main()
