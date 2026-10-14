"""Read-only preservation/publication audit; private reads ONLY new test stores."""
from common import *
from launcher_host import requirements
import datetime,hashlib,re,subprocess,sqlite3,platform,stat
BASE='4d8a3c9e7d6258a9408698c6b1ea5de3b321e0d6'
EDIT={'STATUS.md','docs/design/ROADMAP.md','docs/strategy/DECISION_LOG.md'}
PREFIX=('services/privacy-network/','docs/privacy-network/','docs/evidence/privacy-network-v01/')
OUT=ROOT/'docs/evidence/privacy-network-v01/audit.json'
G=['git',f'--git-dir={ROOT/".phase0-git"}',f'--work-tree={ROOT}']
def git(*args):return subprocess.check_output(G+list(args),stderr=subprocess.PIPE)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def blob(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def main():
    c.harden();assert not OUT.exists();assert git('rev-parse','HEAD').decode().strip()==BASE
    assert git('rev-parse','strategic-pause-2026-10-09^{}').decode().strip()==BASE
    inventory=json.loads((ROOT/'docs/checkpoints/PRESERVATION_MANIFEST_2026-10-09.json').read_bytes())['files']
    frozen=0;unchanged=0;count=0
    for item in git('ls-tree','-rz',BASE).split(b'\0'):
        if not item:continue
        meta,name=item.split(b'\t');name=name.decode();raw=(ROOT/name).read_bytes();norm=raw.replace(b'\r\n',b'\n');expected=meta.split()[2].decode();count+=1
        if name in EDIT:
            old=git('cat-file','blob',expected).replace(b'\r\n',b'\n')
            if name=='docs/strategy/DECISION_LOG.md':assert norm.startswith(old.rstrip()),name
            else:assert norm.endswith(old.split(b'\n\n',1)[1]),name
            continue
        assert blob(raw if name.startswith('docs/evidence/') else norm)==expected,name;unchanged+=1
        if name in inventory:assert sha(raw)==inventory[name]['worktree_sha256'],name
        if name.startswith('docs/evidence/'):frozen+=1
    assert frozen==1036
    checkpoints=set(re.findall(r'`([a-f0-9]{40})`',(ROOT/'docs/checkpoints/FINAL_ENGINEERING_SUMMARY.md').read_text()))
    for commit in checkpoints:git('cat-file','-e',commit+'^{commit}')
    files={ROOT/p for p in EDIT};files.add(ROOT/'Open-Privacy-Network.cmd')
    for prefix in PREFIX:files.update(p for p in (ROOT/prefix).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    files.discard(OUT)
    for line in git('status','--porcelain','--untracked-files=all').decode().splitlines():
        name=line[3:].strip('"');assert name in EDIT or name=='Open-Privacy-Network.cmd' or name.startswith(PREFIX),name
    known=set();wallet_ids=set();roots=[NATIVE/'build/privacy-network-v01',Path.home()/'.local/share/privacycoin-network-v01',Path('/tmp/pc-pn-first-check')];fixture_bytes=0;unsafe_fixtures_skipped=0
    for root in roots:
        if not root.exists():continue
        for path in root.rglob('*'):
            if path.is_symlink():continue
            if path.is_file():fixture_bytes+=path.stat().st_size
        for path in root.rglob('runtime-config'):known.add(load_json(path)['password'].encode())
        for path in root.rglob('control'):
            control=load_json(path);known.update(control[k].encode() for k in ('admin','password'))
            # Negative tests intentionally leave a symlink to another fixture's DB.
            # Never follow it or try that store's password against unrelated rows.
            if (path.parent/'state.sqlite').is_symlink():unsafe_fixtures_skipped+=1;continue
            db=sqlite3.connect('file:'+str(path.parent/'state.sqlite')+'?mode=ro',uri=True)
            try:
                for row in db.execute('SELECT wallet FROM quotes'):
                    wallet=f.open_sealed(row[0],control['password'].encode(),'resource-invoice-wallet');wallet_ids.add(f.wallet_id(wallet));known.update(bytes.fromhex(wallet[k]) for k in ('seed','view') if k in wallet)
                    if 'seed' in wallet:known.update(bytes.fromhex(x) for x in f.crypto('derive',wallet['seed'])[:2])
            finally:db.close()
        for path in root.rglob('*.intent'):
            q=load_json(path)['quote'];known.update(q[k].encode() for k in ('owner','retriever'))
        for path in root.rglob('*.upload'):
            bundle=load_json(path)['bundle'];known.add(bundle['key'].encode());known.add(bytes.fromhex(bundle['key']));known.add(bundle['retriever'].encode())
    assert fixture_bytes<3*1024**3
    compiled=0;links=0
    for path in files:
        raw=path.read_bytes()
        assert path.suffix not in ('.wallet','.password','.key','.seed','.sqlite','.retrieval','.upload','.intent'),path.name
        assert not re.search(rb'-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----',raw)
        for secret in known:assert secret not in raw and secret.hex().encode() not in raw,'Secret match withheld'
        if path.suffix=='.py':compile(raw,str(path),'exec');compiled+=1
        if path.suffix=='.md':
            for link in re.findall(r'\]\(([^)]+)\)',raw.decode('utf-8')):
                if '://' in link or link.startswith('#'):continue
                target=(path.parent/link.split('#')[0]).resolve();assert target==OUT or target.exists(),(path.name,link);links+=1
    prior=json.loads((ROOT/'docs/evidence/overnight-v1/audit.json').read_bytes())
    requirements()
    binaries={p.name:sha(p.read_bytes()) for p in (NATIVE/'build/monero-linux/phase4').glob('privacycoin-hardened-*')};assert binaries==prior['binary_sha256']
    assert {p:sha((ROOT/p).read_bytes()) for p in ('.gitignore','.gitattributes')}==prior['git_policy_sha256']
    assert {p:sha((ROOT/'.git'/p).read_bytes()) for p in ('HEAD','config')}==prior['ordinary_git_control_sha256']
    assert "default='full'" in (ROOT/'src/phase5b/wallet.py').read_text()
    # Original stores: METADATA ONLY. No content reads, hashing, decryption/copy.
    locations=json.loads((ROOT/'docs/checkpoints/PRIVATE_DATA_LOCATIONS_2026-10-09.json').read_bytes())['locations']
    for old in locations:
        p=Path(old['path']);assert p.exists()==old['exists'] and p.is_symlink()==old['symlink']
        if p.exists():
            assert oct(stat.S_IMODE(p.stat().st_mode))==old['directory_mode']
            entries=list(p.iterdir());assert sum(x.is_file() for x in entries)==old['immediate_files'] and sum(x.is_dir() for x in entries)==old['immediate_directories']
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():continue
        try:args=(p/'cmdline').read_bytes().split(b'\0')
        except OSError:continue
        if not args:continue
        assert not any(x==str(ROOT/'services/privacy-network/provider.py').encode() or x==str(ROOT/'services/privacy-network/demo.py').encode() for x in args),'Owned service remains'
        if b'privacycoin-hardened-devnet' in args[0]:assert not any(x.startswith(tuple(str(r).encode() for r in roots)) for x in args),'Owned node remains'
    git('-c','core.whitespace=cr-at-eol','diff','--check');git('fsck','--full')
    now=datetime.datetime.now(datetime.timezone.utc);elapsed=(now-datetime.datetime(2026,10,9,3,34,tzinfo=datetime.timezone.utc)).total_seconds();assert 0<=elapsed<6*3600
    report=dict(result='PASS_SCOPE_HISTORY_PUBLICATION',starting_commit=BASE,observed_at_utc=now.isoformat(),campaign_elapsed_seconds=elapsed,maximum_seconds=21600,authoritative_git='.phase0-git',worktree='D:/grok Projects/Privacy_Coin',starting_tracked_files=count,unchanged_tracked_files=unchanged,frozen_evidence_files_preserved=frozen,checkpoint_objects_verified=len(checkpoints)+1,pause_tag_preserved=True,historical_document_bodies_preserved=True,allowed_existing_changes=sorted(EDIT),publication_sha256={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in sorted(files)},python_files_compiled=compiled,local_links_checked=links,binary_sha256=binaries,ordinary_git_unchanged=True,git_fsck='PASS; no cleanup',secret_audit=dict(matches=0,new_disposable_invoice_wallets=len(wallet_ids),known_secret_encodings=len(known),scope='Only new campaign fixtures and new separate pilot store. Raw/hex known private encodings + PEM markers. Not arbitrary-secret/forensic proof. Existing original wallets never decrypted.'),original_private_locations_metadata_unchanged=len(locations),original_private_contents='Not read/exported/copied; metadata comparison does not prove byte integrity against external changes',new_private_data_bytes=fixture_bytes,owned_services_remaining=0,environment=dict(platform=platform.platform(),python=platform.python_version(),cpu='Intel i5-11300H @ 3.10GHz',distribution='Ubuntu-24.04 WSL2',runtime_cpu_affinity_limit=2),active_consensus_crypto_monetary_wallet_authority_changes=False,full_sync_default=True,live_tor=False,public_service=False,phase5='INCOMPLETE_WITH_BLOCKERS',phase6a='INCOMPLETE_WITH_BLOCKERS',route_c='PAUSED',r1='KILL',five_humans='PENDING',independent_review='PENDING',mainnet='NOT AUTHORIZED')
    report['audit_harness_note']=dict(unsafe_fixture_symlinks_skipped=unsafe_fixtures_skipped,reason='Initial audit tried a deliberately unsafe symlink fixture with its unrelated control password and failed decryption. Audit now skips links before DB access. Product had already rejected these fixtures; no acceptance gate changed.')
    OUT.write_bytes(json.dumps(report,indent=2,sort_keys=True).encode()+b'\n');print(json.dumps({k:report[k] for k in ('result','frozen_evidence_files_preserved','unchanged_tracked_files','python_files_compiled','local_links_checked','new_private_data_bytes','campaign_elapsed_seconds')}))
if __name__=='__main__':main()
