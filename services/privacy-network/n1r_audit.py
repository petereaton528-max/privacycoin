"""N1-R preservation/publication audit. Never reads original private user stores."""
from common import *
from launcher_host import requirements
from tor_runtime import TOR
import subprocess,re,datetime,sqlite3
BASE='7b23fe66139add6a375ad1ee25104faa3c7cb7e2'
EDIT={'STATUS.md','docs/design/ROADMAP.md','docs/strategy/DECISION_LOG.md','docs/privacy-network/n1/ASSESSMENT.md','services/privacy-network/n1_runtime.py','services/privacy-network/n1_tests.py','services/privacy-network/onion_bridge.py','services/privacy-network/runtime.py','services/privacy-network/tor_runtime.py','services/privacy-network/tor_transport.py'}
PREFIX=('services/privacy-network/n1r_','docs/privacy-network/n1-repair/','docs/evidence/privacy-network-n1-repair/')
NEW={'services/privacy-network/n1_diagnostics.py'}
OUT=ROOT/'docs/evidence/privacy-network-n1-repair';G=['git',f'--git-dir={ROOT/".phase0-git"}',f'--work-tree={ROOT}']

def git(*args):return subprocess.check_output(G+list(args),stderr=subprocess.PIPE)
def blob(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()

def main():
    c.harden();assert git('rev-parse','HEAD').decode().strip()==BASE
    target=OUT/'audit.json';assert not target.exists();tracked=frozen=unchanged=0
    preflight=json.loads((OUT/'preflight.json').read_bytes())
    assert digest(TOR.read_bytes())==preflight['tor_sha256']
    for name,expected in preflight['frozen_evidence_sha256'].items():assert digest((ROOT/name).read_bytes())==expected,name
    for item in git('ls-tree','-rz',BASE).split(b'\0'):
        if not item:continue
        meta,name=item.split(b'\t');name=name.decode();expected=meta.split()[2].decode();raw=(ROOT/name).read_bytes();tracked+=1
        if name in EDIT:
            old=git('cat-file','blob',expected).replace(b'\r\n',b'\n');current=raw.replace(b'\r\n',b'\n')
            if name=='docs/strategy/DECISION_LOG.md':assert current.startswith(old.rstrip())
            elif name.endswith('.md'):assert current.endswith(old)
            continue
        assert blob(raw if name.startswith('docs/evidence/') else raw.replace(b'\r\n',b'\n'))==expected,name
        unchanged+=1;frozen+=name.startswith('docs/evidence/')
    manifest=json.loads((ROOT/'docs/checkpoints/PRESERVATION_MANIFEST_2026-10-09.json').read_bytes())['files'];archive=0
    for name,item in manifest.items():
        if name.startswith('docs/evidence/'):assert digest((ROOT/name).read_bytes())==item['worktree_sha256'],name;archive+=1
    assert git('rev-parse','strategic-pause-2026-10-09^{}').decode().strip()=='4d8a3c9e7d6258a9408698c6b1ea5de3b321e0d6'
    paths=set()
    for line in git('status','--porcelain','--untracked-files=all').decode().splitlines():
        name=line[3:].strip('"');assert name in EDIT|NEW or name.startswith(PREFIX),name;paths.add(ROOT/name)
    paths.discard(target)
    # All secrets inspected below belong ONLY to new campaign-owned fixtures.
    fixtures=NATIVE/'build/privacy-network-n1-repair';known=set();total=0;unsafe=0;wallets=set();roots={fixtures}
    for evidence in OUT.rglob('*.json'):
        report=json.loads(evidence.read_bytes());value=report.get('private_fixture')
        if value:
            candidate=Path(value)
            assert any(candidate.is_relative_to(NATIVE/'build'/name) for name in ('privacy-network-n1-repair','privacy-network-v01','privacy-network-repair','privacy-network-n1'))
            if not candidate.is_relative_to(fixtures):
                assert candidate not in (NATIVE/'build/privacy-network-n1',NATIVE/'build/privacy-network-v01',NATIVE/'build/privacy-network-repair');roots.add(candidate)
    def add(value):
        if isinstance(value,str):known.add(value.encode())
        elif isinstance(value,bytes) and len(value)>=16:known.add(value)
    def wallet(value):
        wallets.add(f.wallet_id(value))
        for k in ('seed','view'):
            if k in value:add(bytes.fromhex(value[k]))
        if 'seed' in value:
            for v in f.crypto('derive',value['seed'])[:2]:add(bytes.fromhex(v))
    for path in (p for root in roots for p in root.rglob('*')):
        if path.is_symlink():unsafe+=1;continue
        if not path.is_file():continue
        total+=path.stat().st_size
        if path.name=='control' and path.parent.name.startswith('provider-'):
            control=load_json(path);add(control['password']);add(control['admin'])
            database=path.parent/'state.sqlite'
            if database.is_symlink():unsafe+=1;continue
            with sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True) as db:
                for row in db.execute('SELECT wallet FROM quotes'):wallet(f.open_sealed(row[0],control['password'].encode(),'resource-invoice-wallet'))
        if path.name=='runtime-config':
            config=load_json(path);add(config['password'])
            candidate=path.parent/'alice-wallets/DisposableAlice.wallet'
            if candidate.exists():wallet(c.load(candidate,config['password'].encode()))
        if path.suffix=='.intent':
            q=load_json(path)['quote'];add(q['owner']);add(q['retriever'])
        if path.suffix=='.upload':
            b=load_json(path)['bundle'];add(b['retriever']);add(bytes.fromhex(b['key']))
        if path.name in ('control_auth_cookie','hs_ed25519_secret_key','authority_identity_key','authority_signing_key','secret_id_key','ed25519_master_id_secret_key'):
            mode=path.stat();assert mode.st_uid==os.getuid() and mode.st_mode&0o077==0 and mode.st_nlink==1
            add(path.read_bytes())
    assert total<3*1024**3
    compiled=links=0
    for p in paths:
        if not p.is_file():continue
        raw=p.read_bytes();assert p.suffix not in ('.wallet','.seed','.key','.sqlite','.upload','.intent','.retrieval','.deb')
        assert not re.search(rb'-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----',raw)
        for secret in known:assert secret not in raw and secret.hex().encode() not in raw,'Known fixture secret match withheld'
        if p.suffix=='.py':compile(raw,str(p),'exec');compiled+=1
        if p.suffix=='.md':
            for link in re.findall(r'\]\(([^)]+)\)',raw.decode('utf-8')):
                if '://' in link or link.startswith('#'):continue
                dest=(p.parent/link.split('#')[0]).resolve();assert dest.exists() or dest==target,(p.name,link);links+=1
    prior=json.loads((ROOT/'docs/evidence/privacy-network-v01/audit.json').read_bytes());requirements()
    binaries={p.name:digest(p.read_bytes()) for p in (NATIVE/'build/monero-linux/phase4').glob('privacycoin-hardened-*')};assert binaries==prior['binary_sha256']
    policy=json.loads((ROOT/'docs/evidence/overnight-v1/audit.json').read_bytes());assert {p:digest((ROOT/'.git'/p).read_bytes()) for p in ('HEAD','config')}==policy['ordinary_git_control_sha256']
    assert "default='full'" in (ROOT/'src/phase5b/wallet.py').read_text()
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():continue
        try:args=(p/'cmdline').read_bytes().split(b'\0')
        except OSError:continue
        if not args:continue
        assert not any(x.startswith(str(root).encode()) for root in roots for x in args),'Campaign service remains'
    git('-c','core.whitespace=cr-at-eol','diff','--check');git('fsck','--full')
    report=dict(result='PASS_N1R_PRESERVATION_PUBLICATION',starting_commit=BASE,observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),authoritative_git='.phase0-git',worktree='D:/grok Projects/Privacy_Coin',starting_tracked_files=tracked,unchanged_tracked_files=unchanged,frozen_evidence_files_preserved=frozen,archive_frozen_evidence_preserved=archive,ordinary_git_unchanged=True,pause_tag_preserved=True,allowed_existing_changes=sorted(EDIT),publication_sha256={p.relative_to(ROOT).as_posix():digest(p.read_bytes()) for p in sorted(paths) if p.is_file()},python_files_compiled=compiled,local_links_checked=links,known_disposable_wallets=len(wallets),known_secret_encodings=len(known),secret_matches=0,secret_audit_scope='Only newly owned N1-R fixture secrets plus private-key markers. Not arbitrary secret detection or memory-erasure proof. No original private store contents read or copied.',original_private_store_byte_audit='NOT PERFORMED: original stores deliberately not accessed; source/test isolation reviewed instead',new_private_fixture_bytes=total,unsafe_fixture_symlinks_skipped=unsafe,binary_sha256=binaries,consensus_crypto_monetary_wallet_signing_changes=False,full_sync_default=True,phase5='INCOMPLETE_WITH_BLOCKERS',phase6a='INCOMPLETE_WITH_BLOCKERS',route_c='PAUSED',r1='KILL',independent_review='PENDING',five_humans='PENDING',mainnet='NOT AUTHORIZED',public_onion_activation=False,cross_physical_host_acceptance='PENDING',owned_services_remaining=0,git_fsck='PASS; no cleanup')
    target.write_bytes(json.dumps(report,indent=2,sort_keys=True).encode()+b'\n');print(json.dumps({k:report[k] for k in ('result','frozen_evidence_files_preserved','python_files_compiled','new_private_fixture_bytes')}))
if __name__=='__main__':main()
