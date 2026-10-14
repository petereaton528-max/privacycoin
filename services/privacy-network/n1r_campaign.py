"""Bounded sequential N1-R acceptance supervisor; owned process groups only."""
from common import *
import subprocess,time,signal,datetime,argparse
OUT=ROOT/'docs/evidence/privacy-network-n1-repair'
DEADLINE=datetime.datetime.fromisoformat('2026-10-09T11:33:03+00:00').timestamp()
def main():
    c.harden();parser=argparse.ArgumentParser();parser.add_argument('--first-integration',type=Path,default=OUT/'integration-1791529074723498126.json');args=parser.parse_args()
    stages=[];report={};start=time.monotonic();first=args.first_integration
    assert first.resolve().parent==OUT.resolve()
    initial=json.loads(first.read_bytes());assert initial['result']=='PASS_REAL_PRIVATE_TOR_AND_PC'
    home=Path(initial['private_fixture'])
    source_paths=['n1_runtime.py','tor_runtime.py','tor_transport.py','onion_bridge.py','runtime.py','n1_diagnostics.py','n1_tests.py']
    source={name:digest(Path(__file__).with_name(name).read_bytes()) for name in source_paths}
    campaign_home=private_dir(NATIVE/'build/privacy-network-n1-repair'/('supervisor-'+str(time.time_ns())))
    def run(name,args,bound):
        remaining=DEADLINE-time.time()
        if remaining<bound:stages.append(dict(stage=name,result='SKIP_CAMPAIGN_BOUND'));return False
        before=time.monotonic();log=campaign_home/(name+'.log');process=None
        with log.open('xb') as output:
            process=subprocess.Popen([sys.executable,str(Path(__file__).with_name(args[0]))]+args[1:],stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
            try:
                while process.poll() is None:
                    if time.monotonic()-before>bound or time.time()>DEADLINE:raise subprocess.TimeoutExpired(name,bound)
                    if log.stat().st_size>2*1024*1024:raise ValueError('BOUNDED_OUTPUT_LIMIT')
                    time.sleep(.2)
                result='PASS' if process.returncode==0 else 'FAIL'
            except (subprocess.TimeoutExpired,ValueError):
                os.killpg(process.pid,signal.SIGTERM)
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5)
                result='TIMEOUT_OR_LOG_BOUND'
        stage=dict(stage=name,result=result,exit_code=process.returncode,seconds=time.monotonic()-before)
        stages.append(stage);print(json.dumps(stage),flush=True)
        return result=='PASS'
    try:
        run('cycles',['n1r_stress.py','--home',str(home),'--reads','200','--provider-restarts','20','--tor-restarts','20'],1800)
        integrations=[first.name]
        for trial in (2,3):
            old=set(OUT.glob('integration-*.json'));run('integration'+str(trial),['n1r_run.py'],900);new=set(OUT.glob('integration-*.json'))-old
            if len(new)==1:integrations.append(next(iter(new)).name)
        report['acceptance_integrations']=integrations
        latest=json.loads((OUT/integrations[-1]).read_bytes())
        if latest['result']=='PASS_REAL_PRIVATE_TOR_AND_PC':
            home=Path(latest['private_fixture']);run('performance',['n1r_performance.py','--home',str(home)],600)
            run('soak',['n1r_stress.py','--home',str(home),'--reads','0','--soak-seconds','2700'],3000)
        run('final_unit',['n1r_unit.py'],120)
    finally:
        unchanged=source=={name:digest(Path(__file__).with_name(name).read_bytes()) for name in source_paths}
        report.update(stages=stages,seconds=time.monotonic()-start,private_fixture=str(campaign_home),source_sha256=source,source_unchanged=unchanged,result='PASS' if unchanged and stages and all(x['result']=='PASS' for x in stages) else 'INCOMPLETE_WITH_BLOCKERS')
        out=OUT/('campaign-'+str(time.time_ns())+'.json');out.write_bytes(f.canonical(report)+b'\n');print(report['result'],out.name,flush=True)
    if report['result']!='PASS':sys.exit(1)
if __name__=='__main__':main()
