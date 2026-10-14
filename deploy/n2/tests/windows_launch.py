"""Actual Windows CMD provider launcher; isolated new WSL store, no Tor/payment."""
from pathlib import Path
import json,re,subprocess,time,sys
ROOT=Path(__file__).resolve().parents[3]
def command(*args):
    # cmd /s strips one outer quote pair. Fixed, non-secret test paths only.
    if any(not re.fullmatch(r'[A-Za-z0-9_:./\\ -]+',str(x)) for x in args):raise ValueError('Unsafe test command path')
    return 'cmd.exe /d /s /c "'+subprocess.list2cmdline(list(map(str,args)))+'"'
def main():
    start=time.monotonic();home='/home/privacydev/privacycoin-dev/Privacy_Coin/build/privacycoin-n2-preparation/privacycoin-n2-windows-'+str(time.time_ns());checks=[]
    prepare=subprocess.run(['wsl.exe','-d','Ubuntu-24.04','--cd',str(ROOT),'--','python3','deploy/n2/common/role.py','prepare','--home',home],capture_output=True,timeout=30)
    if prepare.returncode:raise ValueError('Fresh Windows fixture preparation failed')
    p=subprocess.run(command(ROOT/'deploy/n2/START_N2_PROVIDER.cmd','/mnt/d/grok Projects/Privacy_Coin',home+'/provider.json'),input='EXIT\n',capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=120)
    if p.returncode==0 and 'LOCAL_PROVIDER_READY' in p.stdout:checks+=['actual CMD WSL provider startup','scripted EXIT returns owned services']
    missing=subprocess.run(command(ROOT/'deploy/n2/START_N2_PROVIDER.cmd'),capture_output=True,timeout=10)
    if missing.returncode==2:checks.append('missing provider arguments rejected')
    absent=subprocess.run(command(ROOT/'deploy/n2/START_N2_CLIENT.cmd','/mnt/d/grok Projects/Privacy_Coin',home+'/absent-client.json'),capture_output=True,timeout=20)
    if absent.returncode!=0:checks.append('client missing profile fails closed')
    report=dict(result='PASS' if len(checks)==4 else 'FAIL',checks=checks,seconds=time.monotonic()-start,private_fixture=home,provider_returncode=p.returncode,client_missing_returncode=absent.returncode,scope='Actual Windows CMD local-role automation, no human or physical cross-host acceptance, no public Tor/mining/payment')
    (ROOT/'docs/evidence/privacy-network-n2'/('windows-launch-'+str(time.time_ns())+'.json')).write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))
    if report['result']!='PASS':sys.exit(1)
if __name__=='__main__':main()
