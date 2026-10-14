"""N2 preservation/source-package audit; only new disposable private fixtures read."""
from pathlib import Path
import hashlib,json,os,re,sqlite3,subprocess,sys,zipfile
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'deploy/n2/common'),str(ROOT/'services/privacy-network'),str(ROOT/'scripts/devnet-gui')]
from common import c,f,load_json,NATIVE
from bundle import inspect,sha
BASE='db3f4e1e6bf9d25001859423365b508a9a814dda'
OUT=ROOT/'docs/evidence/privacy-network-n2'
EDIT={'STATUS.md','docs/design/ROADMAP.md','docs/strategy/DECISION_LOG.md','scripts/devnet-gui/backend.py','scripts/devnet-gui/launcher_host.py'}
PREFIX=('deploy/n2/','docs/privacy-network/n2/','docs/evidence/privacy-network-n2/')
G=['git',f'--git-dir={ROOT/".phase0-git"}',f'--work-tree={ROOT}']
def git(*args):return subprocess.check_output(G+list(args),stderr=subprocess.PIPE)
def main():
    c.harden();target=OUT/'audit.json';assert not target.exists();assert git('rev-parse','HEAD').decode().strip()==BASE
    pre=json.loads((OUT/'preflight.json').read_bytes())
    for n,h in pre['frozen_evidence_sha256'].items():assert sha((ROOT/n).read_bytes())==h,n
    unchanged=0
    for entry in git('ls-tree','-rz',BASE).split(b'\0'):
        if not entry:continue
        meta,n=entry.split(b'\t');name=n.decode();old=git('cat-file','blob',meta.split()[2].decode());now=(ROOT/name).read_bytes()
        if name in EDIT:
            if name.endswith('.md'):
                a=old.replace(b'\r\n',b'\n');b=now.replace(b'\r\n',b'\n')
                assert b.startswith(a.rstrip()) if name.endswith('DECISION_LOG.md') else b.endswith(a)
            continue
        assert now==old if name.startswith('docs/evidence/') else now.replace(b'\r\n',b'\n')==old.replace(b'\r\n',b'\n'),name
        unchanged+=1
    changed=[]
    for line in git('status','--porcelain','--untracked-files=all').decode().splitlines():
        name=line[3:].strip('"');assert name in EDIT or name.startswith(PREFIX),name;changed.append(ROOT/name)
    package=ROOT/'build/n2-deployment/PrivacyNetwork-N2-source.zip';manifest=inspect(package)
    fixture=NATIVE/'build/privacycoin-n2-preparation';roots={fixture};known=set();wallets=set();size=0;symlinks=0
    for p in OUT.rglob('*.json'):
        r=json.loads(p.read_text(encoding='utf-8-sig'));path=r.get('private_fixture')
        if path:
            path=Path(path)
            if not path.is_relative_to(fixture):
                assert any(path.is_relative_to(NATIVE/'build'/x) and path.name not in ('privacy-network-v01','privacy-network-repair','privacy-network-n1') for x in ('privacy-network-v01','privacy-network-repair','privacy-network-n1'))
                roots.add(path)
    def add(x):
        if isinstance(x,str):known.add(x.encode())
        elif isinstance(x,bytes) and len(x)>=16:known.add(x)
    def wallet(w):
        wallets.add(f.wallet_id(w))
        for k in ('seed','view'):
            if k in w:add(bytes.fromhex(w[k]))
        if 'seed' in w:
            for value in f.crypto('derive',w['seed'])[:2]:add(bytes.fromhex(value))
    for root in roots:
        for p in root.rglob('*'):
            if p.is_symlink():symlinks+=1;continue
            if not p.is_file():continue
            size+=p.stat().st_size
            if p.name=='control' and p.parent.name.startswith('provider'):
                record=load_json(p);add(record['password']);add(record['admin'])
                db=p.parent/'state.sqlite'
                if db.is_symlink():continue
                with sqlite3.connect('file:'+str(db)+'?mode=ro',uri=True) as connection:
                    for row in connection.execute('SELECT wallet FROM quotes'):wallet(f.open_sealed(row[0],record['password'].encode(),'resource-invoice-wallet'))
            elif p.name=='runtime-config':
                record=load_json(p);add(record['password']);wp=p.parent/'alice-wallets/DisposableAlice.wallet'
                if wp.exists():wallet(c.load(wp,record['password'].encode()))
            elif p.suffix=='.intent':
                record=load_json(p)['quote'];add(record['owner']);add(record['retriever'])
            elif p.suffix=='.upload':
                record=load_json(p)['bundle'];add(record['retriever']);add(bytes.fromhex(record['key']))
            elif p.name in ('control_auth_cookie','hs_ed25519_secret_key','authority_identity_key','authority_signing_key','secret_id_key','ed25519_master_id_secret_key'):
                s=p.stat();assert s.st_uid==os.getuid() and s.st_mode&0o077==0 and s.st_nlink==1;add(p.read_bytes())
    archives=sum(p.stat().st_size for p in (ROOT/'build/n2-deployment').glob('*') if p.is_file())
    assert size+archives<2*1024**3
    def scan(raw):
        assert not re.search(rb'(?m)^-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----',raw)
        for value in known:assert value not in raw and value.hex().encode() not in raw,'Known disposable secret match withheld'
    compiled=links=0
    for p in changed:
        if not p.is_file() or p==target:continue
        scan(p.read_bytes())
        if p.suffix=='.py':compile(p.read_bytes(),str(p),'exec');compiled+=1
        if p.suffix=='.md':
            for link in re.findall(r'\]\(([^)]+)\)',p.read_text(encoding='utf-8')):
                if '://' in link or link.startswith('#'):continue
                dest=(p.parent/link.split('#')[0]).resolve();assert dest.exists() or dest==target,(str(p),link);links+=1
    with zipfile.ZipFile(package) as z:
        for name in z.namelist():
            assert Path(name).suffix not in ('.wallet','.wallet-backup','.sqlite','.seed','.key','.keys','.password','.retrieval','.upload','.intent','.exe','.dll','.deb')
            scan(z.read(name))
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():continue
        try:args=(p/'cmdline').read_bytes().split(b'\0')
        except OSError:continue
        assert not any(x.startswith(str(root).encode()) for root in roots for x in args),'Owned fixture process remains'
    old=json.loads((ROOT/'docs/evidence/privacy-network-n1-repair/audit.json').read_bytes())
    actual={p.name:sha(p.read_bytes()) for p in (NATIVE/'build/monero-linux/phase4').glob('privacycoin-hardened-*')};assert actual==old['binary_sha256']
    policy=json.loads((ROOT/'docs/evidence/overnight-v1/audit.json').read_bytes());assert {n:sha((ROOT/'.git'/n).read_bytes()) for n in ('HEAD','config')}==policy['ordinary_git_control_sha256']
    assert git('rev-parse','strategic-pause-2026-10-09^{}').decode().strip()=='4d8a3c9e7d6258a9408698c6b1ea5de3b321e0d6'
    assert "default='full'" in (ROOT/'src/phase5b/wallet.py').read_text()
    git('-c','core.whitespace=cr-at-eol','diff','--check');git('fsck','--full')
    from datetime import datetime,timezone
    report=dict(result='PASS_N2_PRESERVATION_AND_SOURCE_PUBLICATION',observed_at_utc=datetime.now(timezone.utc).isoformat(),starting_commit=BASE,frozen_evidence_preserved=len(pre['frozen_evidence_sha256']),unchanged_tracked_files=unchanged,archive_sha256=sha(package.read_bytes()),archive_bytes=package.stat().st_size,archive_source_files=len(manifest['files']),new_disposable_bytes=size,all_new_data_including_candidate_archives_bytes=size+archives,known_disposable_wallets=len(wallets),known_secret_values=len(known),known_secret_matches=0,secret_audit_scope='Only newly retained disposable fixture secrets and actual PEM headers. No original user store read/copied; not arbitrary secret detection or erasure proof.',fixture_symlinks_skipped=symlinks,python_files_compiled=compiled,local_links_checked=links,owned_services_remaining=0,original_native_binary_sha256=actual,ordinary_git_unchanged=True,strategic_pause_preserved=True,full_sync_default=True,consensus_crypto_monetary_changes=False,phase5='INCOMPLETE_WITH_BLOCKERS',phase6a='INCOMPLETE_WITH_BLOCKERS',route_c='PAUSED',mainnet='NOT AUTHORIZED',public_onion_activation=False,physical_host_acceptance='PENDING',git_fsck='PASS',publication_sha256={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in changed if p.is_file() and p!=target})
    target.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps({k:report[k] for k in ('result','frozen_evidence_preserved','archive_sha256','all_new_data_including_candidate_archives_bytes')}))
if __name__=='__main__':main()
