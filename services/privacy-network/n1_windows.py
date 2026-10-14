"""Windows launcher automation with a new disposable private WSL home."""
from pathlib import Path
import json,subprocess,time,sys

def main():
    root=Path(__file__).resolve().parents[2];out=root/'docs/evidence/privacy-network-n1';start=time.monotonic()
    home='/home/privacydev/privacycoin-dev/Privacy_Coin/build/privacy-network-n1/windows-'+str(time.time_ns())
    result=subprocess.run(['cmd.exe','/d','/c',str(root/'Open-Privacy-Network-N1.cmd'),'--home',home],input='0\n\n',capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=420)
    report=dict(result='PASS' if result.returncode==0 and 'CONNECTED to pinned Provider 1' in result.stdout else 'FAIL',checks=['actual cmd launcher starts WSL and verified private Tor provider','scripted exit returns from owned runtime'],returncode=result.returncode,seconds=time.monotonic()-start,private_fixture=home,scope='Automated Windows console launcher, no human acceptance, payment, mining or public Tor activation')
    out.mkdir(parents=True,exist_ok=True);(out/('windows-'+str(time.time_ns())+'.json')).write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
    if report['result']!='PASS':sys.exit(1)
if __name__=='__main__':main()
