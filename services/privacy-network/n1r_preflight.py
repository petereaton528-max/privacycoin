"""Read-only N1-R inventory: tracked evidence and prior campaign diagnostics only."""
from common import *
from tor_runtime import TOR
import subprocess,time,platform,re,datetime

OUT=ROOT/'docs/evidence/privacy-network-n1-repair'
BASE='7b23fe66139add6a375ad1ee25104faa3c7cb7e2'
def main():
    c.harden();OUT.mkdir(parents=True,exist_ok=True)
    git=['git','--git-dir='+str(ROOT/'.phase0-git'),'--work-tree='+str(ROOT)]
    head=subprocess.check_output(git+['rev-parse','HEAD']).decode().strip();assert head==BASE
    inventory={}
    for name in subprocess.check_output(git+['ls-tree','-r','--name-only',BASE]).decode().splitlines():
        if name.startswith('docs/evidence/'):
            inventory[name]=digest((ROOT/name).read_bytes())
    previous=[]
    for evidence in sorted((ROOT/'docs/evidence/privacy-network-n1').glob('integration-*.json')):
        report=json.loads(evidence.read_bytes());home=Path(report['private_fixture'])
        assert home.is_relative_to(NATIVE/'build/privacy-network-n1')
        logs=[]
        for log in (home/'tor').glob('*/notice.log'):
            # Aggregate messages, never emit onion identities or control data.
            raw=log.read_text(errors='replace')
            logs.append(dict(role=log.parent.name,lines=len(raw.splitlines()),warnings=raw.count('[warn]'),errors=raw.count('[err]'),bootstrap100=raw.count('Bootstrapped 100%'),consensus_errors=len(re.findall('consensus.*(?:expired|unusable|not live)',raw,re.I)),circuit_failures=len(re.findall('(?:failed|failure).*circuit',raw,re.I)),relay_client_only='ClientOnly 1' in (log.parent/'torrc').read_text()))
        previous.append(dict(evidence=evidence.name,result=report['result'],passed=report['passed'],logs=logs))
    result=dict(starting_head=head,started_at_utc='2026-10-09T06:33:03+00:00',deadline_utc='2026-10-09T11:33:03+00:00',observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),frozen_evidence_sha256=inventory,frozen_count=len(inventory),python=platform.python_version(),platform=platform.platform(),tor=subprocess.check_output([str(TOR),'--version']).decode().splitlines()[0],tor_sha256=digest(TOR.read_bytes()),native=NATIVE.as_posix(),new_fixture_root=str(NATIVE/'build/privacy-network-n1-repair'),original_private_stores='NOT ACCESSED',previous_diagnostics=previous,acceptance=dict(consecutive_integrations=3,repeated_reads=100,provider_restarts=20,tor_start_stop=20,soak_seconds=2700,request_deadline_seconds=40,ordinary_operation_bound_seconds=120,startup_bound_seconds=360,max_campaign_hours=5,max_new_bytes=3*1024**3,heavy_workers=2,public_tor=False))
    target=OUT/'preflight.json';assert not target.exists();target.write_bytes(f.canonical(result)+b'\n')
    print(json.dumps(dict(head=head,frozen_count=len(inventory),tor=result['tor'],previous_runs=[dict(evidence=x['evidence'],passed=x['passed'],roles=[dict(role=l['role'],warnings=l['warnings'],errors=l['errors'],bootstrap100=l['bootstrap100'],relay_client_only=l['relay_client_only']) for l in x['logs']]) for x in previous])))
if __name__=='__main__':main()
