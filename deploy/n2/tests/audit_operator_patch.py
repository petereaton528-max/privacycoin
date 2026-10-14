"""Read-only preservation and campaign-secret audit; never opens original wallets."""
from pathlib import Path
import hashlib,json,os,re,subprocess,zipfile,platform,ssl,ast
ROOT=Path(__file__).resolve().parents[3]
OUT=ROOT/'docs/evidence/privacy-network-n2-deployment-patch'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main():
    before=json.loads((OUT/'preflight.json').read_text());bad=[name for name,value in before['frozen'].items() if sha((ROOT/name).read_bytes())!=value]
    fixture=Path('/home/privacydev/privacycoin-dev/Privacy_Coin/build/privacycoin-n2-deployment-patch')
    secrets=set();size=0
    def collect(value):
        if isinstance(value,dict):
            for key,item in value.items():
                if key in ('password','admin','key','seed','spend_key','view_key') and isinstance(item,str) and len(item)>=16:secrets.add(item.encode())
                collect(item)
        elif isinstance(value,list):
            for item in value:collect(item)
    for p in fixture.rglob('*'):
        if p.is_symlink() or not p.is_file():continue
        size+=p.stat().st_size
        if p.stat().st_size<=65536:
            if p.name=='own.key':secrets.add(p.read_bytes())
            try:collect(json.loads(p.read_bytes()))
            except (ValueError,UnicodeError):pass
    package=json.loads((OUT/'package.json').read_text());archive=ROOT/package['archive'].replace('\\','/')
    files=list((ROOT/'deploy/n2').rglob('n2_*.py'))+list((ROOT/'deploy/n2/tests').glob('*operator_patch.py'))+list(OUT.glob('*.json'))+list((ROOT/'docs/privacy-network/n2').glob('DEPLOYMENT_PATCH*.md'))
    syntax=list((ROOT/'deploy/n2/common').glob('n2_*.py'))+list((ROOT/'deploy/n2/tests').glob('*patch*.py'))
    for p in syntax:ast.parse(p.read_text())
    leaks=[]
    for p in files:
        raw=p.read_bytes()
        if any(secret in raw for secret in secrets):leaks.append(str(p.relative_to(ROOT)))
    with zipfile.ZipFile(archive) as z:
        for name in z.namelist():
            raw=z.read(name)
            if any(secret in raw for secret in secrets) or re.search(rb'(?m)^-----BEGIN (?:RSA )?PRIVATE KEY-----',raw):leaks.append('ZIP:'+name)
    remaining=[]
    for p in Path('/proc').iterdir():
        if not p.name.isdigit() or int(p.name)==os.getpid():continue
        try:raw=(p/'cmdline').read_bytes()
        except OSError:continue
        if str(fixture).encode() in raw:remaining.append(int(p.name))
    old_packages=[]
    # Old bundled source manifests must remain byte-bound after additive install.
    for name in ('PrivacyNetwork-N2-source.zip','PrivacyNetwork-N2-connectivity-source.zip'):
        old=ROOT/'build/n2-deployment'/name
        with zipfile.ZipFile(old) as z:
            manifest=json.loads(z.read('N2_SOURCE_MANIFEST.json'))
            overlap=[n for n in package['manifest']['files'] if n in manifest['files']]
            conflicts=[n for n in overlap if package['manifest']['files'][n]!=manifest['files'][n]]
            old_packages.append(dict(name=name,sha256=sha(old.read_bytes()),patch_overlap=overlap,conflicts=conflicts))
    result=dict(starting_head=before['head'],environment=dict(platform=platform.platform(),python=platform.python_version(),openssl=ssl.OPENSSL_VERSION),syntax_files_checked=len(syntax),frozen_files=len(before['frozen']),changed_frozen=bad,private_fixture_bytes=size,secret_values_checked=len(secrets),secret_leak_paths=leaks,campaign_owned_processes_remaining=remaining,old_packages=old_packages,public_tor_activated=False,physical_hosts_tested=False,original_user_stores_accessed=False)
    result['result']='PASS' if not bad and not leaks and not remaining and size<2*1024**3 and not any(p['conflicts'] for p in old_packages) else 'FAIL'
    (OUT/'audit.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
    if result['result']!='PASS':raise SystemExit(1)
if __name__=='__main__':main()
