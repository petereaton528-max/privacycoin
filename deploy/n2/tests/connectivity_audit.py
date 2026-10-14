"""Preserve historical bytes; scan only this task's new disposable secrets."""
from pathlib import Path
import sys,os,json,hashlib,subprocess,re,sqlite3,zipfile
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'deploy/n2/common'),str(ROOT/'services/privacy-network')]
from common import c,f,load_json,NATIVE
from bundle import inspect,sha
BASE='ce12009574353a5df850e4576a0c852c240032d5'
OUT=ROOT/'docs/evidence/privacy-network-n2-connectivity'
G=['git',f'--git-dir={ROOT/".phase0-git"}',f'--work-tree={ROOT}']
EDIT={'STATUS.md','docs/design/ROADMAP.md','docs/strategy/DECISION_LOG.md','deploy/n2/README.md','deploy/n2/common/bundle.py'}
def git(*args):return subprocess.check_output(G+list(args),stderr=subprocess.PIPE)
def main():
    c.harden();target=OUT/'audit.json';assert not target.exists();assert git('rev-parse','HEAD').decode().strip()==BASE
    pre=json.loads((OUT/'preflight.json').read_bytes())
    for n,h in pre['frozen'].items():assert sha((ROOT/n).read_bytes())==h,n
    unchanged=0
    for entry in git('ls-tree','-rz',BASE).split(b'\0'):
        if not entry:continue
        meta,name=entry.split(b'\t');n=name.decode();old=git('cat-file','blob',meta.split()[2].decode());now=(ROOT/n).read_bytes()
        a=old.replace(b'\r\n',b'\n');b=now.replace(b'\r\n',b'\n')
        if n in EDIT:
            if n.endswith('.md'):assert b.startswith(a.rstrip()) if n.endswith('DECISION_LOG.md') else b.endswith(a)
            continue
        assert now==old if n.startswith('docs/evidence/') else b==a,n;unchanged+=1
    changed=[]
    for line in git('status','--porcelain','--untracked-files=all').decode().splitlines():
        n=line[3:].strip('"');assert n in EDIT or n.startswith(('deploy/n2/','docs/privacy-network/n2/','docs/evidence/privacy-network-n2-connectivity/')),n;changed.append(ROOT/n)
    roots={NATIVE/'build/privacycoin-n2-connectivity'}
    for p in OUT.rglob('*.json'):
        r=json.loads(p.read_bytes());v=r.get('private_fixture')
        if v:
            p=Path(v);assert p.is_relative_to(NATIVE/'build') and any(p.is_relative_to(NATIVE/'build'/x) for x in ('privacycoin-n2-connectivity','privacycoin-n2-preparation'))
            if not p.is_relative_to(NATIVE/'build/privacycoin-n2-connectivity'):roots.add(p)
    known=set();wallets=set();size=0
    def add(v):
        if isinstance(v,str):v=v.encode()
        if isinstance(v,bytes) and len(v)>=16:known.add(v)
    def wallet(v):
        wallets.add(f.wallet_id(v))
        for k in ('seed','view'):
            if k in v:add(bytes.fromhex(v[k]))
        if 'seed' in v:
            for key in f.crypto('derive',v['seed'])[:2]:add(bytes.fromhex(key))
    for root in roots:
        for p in root.rglob('*'):
            if p.is_symlink() or not p.is_file():continue
            size+=p.stat().st_size
            if p.name=='control' and 'provider' in p.parent.name:
                record=load_json(p);add(record['password']);add(record['admin'])
                with sqlite3.connect('file:'+str(p.parent/'state.sqlite')+'?mode=ro',uri=True) as db:
                    for row in db.execute('SELECT wallet FROM quotes'):wallet(f.open_sealed(row[0],record['password'].encode(),'resource-invoice-wallet'))
            elif p.name=='runtime-config':
                r=load_json(p);add(r['password']);wallet(c.load(p.parent/'alice-wallets/DisposableAlice.wallet',r['password'].encode()))
            elif p.suffix=='.intent':
                r=load_json(p)['quote'];add(r['owner']);add(r['retriever'])
            elif p.suffix=='.upload':
                r=load_json(p)['bundle'];add(r['retriever']);add(bytes.fromhex(r['key']))
            elif p.suffix=='.key' or p.name in ('control_auth_cookie','hs_ed25519_secret_key','authority_identity_key','authority_signing_key','secret_id_key','ed25519_master_id_secret_key'):
                assert p.stat().st_mode&0o077==0;raw=p.read_bytes();add(raw)
                if raw.startswith(b'-----BEGIN'):add(b''.join(raw.splitlines()[1:-1]))
    package=ROOT/'build/n2-deployment/PrivacyNetwork-N2-connectivity-source.zip';m=inspect(package)
    assert sha((ROOT/'build/n2-deployment/PrivacyNetwork-N2-source.zip').read_bytes())=='dec06400f17a275f0caba180779dee8b329e2c9e7f399679a52adb76967328fb'
    assert size+package.stat().st_size<2*1024**3
    def scan(raw):
        assert not re.search(rb'(?m)^-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----',raw)
        for secret in known:assert secret not in raw and secret.hex().encode() not in raw,'Known disposable secret withheld'
    for p in changed:
        if not p.is_file():continue
        scan(p.read_bytes())
        if p.suffix=='.py':compile(p.read_bytes(),str(p),'exec')
        if p.suffix=='.md':
            for link in re.findall(r'\]\(([^)]+)\)',p.read_text(encoding='utf-8')):
                if '://' in link or link.startswith('#'):continue
                dest=(p.parent/link.split('#')[0]).resolve();assert dest.exists() or dest==target,(str(p),link)
    with zipfile.ZipFile(package) as z:
        for name in z.namelist():scan(z.read(name))
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():continue
        try:args=(p/'cmdline').read_bytes().split(b'\0')
        except OSError:continue
        assert not any(a.startswith(str(root).encode()) for root in roots for a in args),'Owned process still running'
    old=json.loads((ROOT/'docs/evidence/privacy-network-n2/audit.json').read_bytes())
    assert {p.name:sha(p.read_bytes()) for p in (NATIVE/'build/monero-linux/phase4').glob('privacycoin-hardened-*')}==old['original_native_binary_sha256']
    ordinary=json.loads((ROOT/'docs/evidence/overnight-v1/audit.json').read_bytes())['ordinary_git_control_sha256']
    assert {n:sha((ROOT/'.git'/n).read_bytes()) for n in ('HEAD','config')}==ordinary
    assert git('rev-parse','strategic-pause-2026-10-09^{}').decode().strip()=='4d8a3c9e7d6258a9408698c6b1ea5de3b321e0d6'
    assert "default='full'" in (ROOT/'src/phase5b/wallet.py').read_text()
    git('-c','core.whitespace=cr-at-eol','diff','--check');git('fsck','--full')
    from datetime import datetime,timezone
    report=dict(result='PASS_CONNECTIVITY_PRESERVATION_AND_PUBLICATION',observed_at_utc=datetime.now(timezone.utc).isoformat(),starting_head=BASE,frozen_evidence_preserved=len(pre['frozen']),unchanged_tracked_files=unchanged,known_wallets=len(wallets),known_secret_values=len(known),known_secret_matches=0,secret_scope='New task disposable keys/capabilities only; not general secret absence or runtime erasure proof. No original human stores accessed.',new_disposable_bytes=size,archive_bytes=package.stat().st_size,archive_sha256=sha(package.read_bytes()),source_files=len(m['files']),original_package_preserved=True,original_native_binaries_preserved=True,consensus_crypto_monetary_changes=False,full_sync_default=True,owned_processes_remaining=0,phase5='INCOMPLETE_WITH_BLOCKERS',phase6a='INCOMPLETE_WITH_BLOCKERS',public_onion=False,physical_host='NOT_TESTED',git_fsck='PASS',publication_sha256={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in changed if p.is_file()})
    target.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps({k:report[k] for k in ('result','frozen_evidence_preserved','new_disposable_bytes','archive_sha256')}))
if __name__=='__main__':main()
