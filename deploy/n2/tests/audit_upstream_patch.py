"""Read-only preservation/scope/package audit, new evidence destination only."""
from pathlib import Path
import hashlib,json,platform,subprocess,sys,zipfile
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'deploy/n2/common'),str(ROOT/'services/privacy-network'),str(ROOT/'scripts/devnet-gui')]
from tor_runtime import TOR
OUT=ROOT/'docs/evidence/privacy-network-n2-upstream-socks5'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main():
    pre=json.loads((OUT/'preflight.json').read_bytes());changed=[name for name,digest in pre['frozen'].items() if sha((ROOT/name).read_bytes())!=digest]
    assert not changed,changed
    git=['git','--git-dir='+str(ROOT/'.phase0-git'),'--work-tree='+str(ROOT)]
    names=subprocess.check_output(git+['diff','--name-only'],cwd=ROOT,text=True).splitlines()
    allowed={'STATUS.md','docs/design/ROADMAP.md','docs/strategy/DECISION_LOG.md','deploy/n2/common/n2_start_diagnostic.py'}
    assert set(names)<=allowed,names
    for name in names:
        if name.startswith(('services/','scripts/','src/')):raise AssertionError('PROTECTED_CODE_CHANGE')
    files=['deploy/n2/common/n2_start_diagnostic.py','deploy/n2/common/n2_upstream_socks5.py','deploy/n2/common/n2_install_upstream.py','deploy/n2/tests/test_upstream_socks5.py','deploy/n2/tests/build_upstream_patch.py','deploy/n2/tests/audit_upstream_patch.py']
    for name in files:compile((ROOT/name).read_bytes(),name,'exec')
    package=json.loads((OUT/'package.json').read_bytes());archive=ROOT/package['archive']
    assert sha(archive.read_bytes())==package['sha256']
    with zipfile.ZipFile(archive) as z:
        assert set(z.namelist())==set(package['manifest']['files'])|{'N2_UPSTREAM_MANIFEST.json'}
        for name,digest in package['manifest']['files'].items():assert sha(z.read(name))==digest==sha((ROOT/name).read_bytes())
    reports=[dict(path=p.relative_to(ROOT).as_posix(),**json.loads(p.read_bytes())) for p in sorted(OUT.glob('checks-*.json'))]
    assert reports[-1]['result']=='PASS'
    runtime_doc=TOR.parents[3]/'usr/share/doc/tor/tor.html'
    # Infer extracted runtime root without executing or contacting any network.
    if not runtime_doc.exists():runtime_doc=TOR.parent.parent/'share/doc/tor/tor.html'
    evidence=dict(starting_head=pre['head'],frozen_evidence=len(pre['frozen']),changed_frozen=changed,tracked_changes=names,protected_implementation_changes=[],syntax_files=len(files),syntax='PASS',package_integrity='PASS',python=platform.python_version(),system=platform.system(),kernel=platform.release(),tor_version=subprocess.check_output([str(TOR),'--version'],timeout=10,text=True).splitlines()[0],tor_binary_sha256=sha(TOR.read_bytes()),official_local_manual_sha256=sha(runtime_doc.read_bytes()),suite_runs=[{k:r[k] for k in ('path','result','tests','failures','errors','skipped','seconds')} for r in reports],public_activation=False,cross_host_payments=False,user_wallet_access=False)
    path=OUT/'audit.json'
    if path.exists():raise ValueError('PRESERVE_AUDIT')
    path.write_text(json.dumps(evidence,indent=2)+'\n');print(json.dumps(evidence,indent=2))
if __name__=='__main__':main()
