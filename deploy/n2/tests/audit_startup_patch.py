"""Read only frozen evidence, new test fixtures and owned-process inventory."""
from pathlib import Path
import ast,hashlib,json,os,platform,ssl,zipfile,subprocess
ROOT=Path(__file__).resolve().parents[3]
OUT=ROOT/'docs/evidence/privacy-network-n2-startup-diagnostics'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main():
    baseline=json.loads((OUT/'preflight.json').read_bytes());changed=[name for name,value in baseline['frozen'].items() if sha((ROOT/name).read_bytes())!=value]
    fixture=Path('/home/privacydev/privacycoin-dev/Privacy_Coin/build/privacycoin-n2-startup-diagnostics');secrets=set();size=0
    for p in fixture.rglob('*'):
        if p.is_symlink() or not p.is_file():continue
        size+=p.stat().st_size
        if p.name=='own.key':secrets.add(p.read_bytes())
    code=[ROOT/'deploy/n2/common'/name for name in ('n2_start_diagnostic.py','n2_tor_diagnostics.py')]
    code+=list((ROOT/'deploy/n2/tests').glob('*startup*.py'))
    for p in code:ast.parse(p.read_text())
    package=json.loads((OUT/'package.json').read_bytes());archive=ROOT/package['archive'];leaks=[]
    inspect=code+list(OUT.glob('*.json'))+list((ROOT/'docs/privacy-network/n2').glob('TOR_STARTUP*.md'))
    for p in inspect:
        if any(secret in p.read_bytes() for secret in secrets):leaks.append(p.relative_to(ROOT).as_posix())
    with zipfile.ZipFile(archive) as z:
        for name in z.namelist():
            if any(secret in z.read(name) for secret in secrets):leaks.append('ZIP:'+name)
    # Allowlisted logs must never retain the deliberately injected fake bearer.
    redaction_fail=[]
    for p in fixture.rglob('events.jsonl'):
        raw=p.read_bytes()
        if b'FIXTURE-BEARER-SECRET-DO-NOT-LOG' in raw or b'PRIVATE-test-secret-do-not-export' in raw:redaction_fail.append(p.name)
    remaining=[]
    for p in Path('/proc').iterdir():
        if not p.name.isdigit() or int(p.name)==os.getpid():continue
        try:raw=(p/'cmdline').read_bytes()
        except OSError:continue
        if str(fixture).encode() in raw:remaining.append(int(p.name))
    git=['git',f'--git-dir={ROOT/".phase0-git"}',f'--work-tree={ROOT}']
    modified=subprocess.check_output(git+['diff','--name-only',baseline['head']]).decode().splitlines()
    protected_changes=[name for name in modified if name.startswith(('src/','tests/phase','services/','scripts/devnet-gui/'))]
    previous=json.loads((ROOT/'docs/evidence/privacy-network-n2-deployment-patch/package.json').read_bytes())
    old=ROOT/previous['archive'].replace('\\','/');old_ok=sha(old.read_bytes())==previous['sha256']
    report=dict(result='PASS' if not changed and not leaks and not remaining and not protected_changes and not redaction_fail and old_ok else 'FAIL',starting_head=baseline['head'],frozen_evidence_files=len(baseline['frozen']),changed_frozen=changed,protected_source_changes=protected_changes,old_operator_package_unchanged=old_ok,syntax_files=len(code),fixture_bytes=size,fixture_tls_keys_checked=len(secrets),secret_leak_paths=leaks,log_redaction_failures=redaction_fail,owned_fixture_processes_remaining=remaining,environment=dict(platform=platform.platform(),python=platform.python_version(),openssl=ssl.OPENSSL_VERSION),public_tor_activated=False,cross_host_payment=False,original_user_stores_accessed=False)
    (OUT/'audit.json').write_bytes((json.dumps(report,indent=2)+'\n').encode());print(json.dumps(report,indent=2))
    if report['result']!='PASS':raise SystemExit(1)
if __name__=='__main__':main()
