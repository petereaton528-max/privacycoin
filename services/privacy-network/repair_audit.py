"""Bounded repair preservation audit; never opens original node/provider for write."""
from common import *
from launcher_host import requirements
import subprocess,re,sqlite3,datetime
BASE='24d223e17dbf08aed10e35082d17ecb8866e8558'
EDIT={'STATUS.md','docs/design/ROADMAP.md','docs/strategy/DECISION_LOG.md','services/privacy-network/provider.py','services/privacy-network/client.py','services/privacy-network/demo.py','docs/privacy-network/PAYMENT_AND_ENTITLEMENT.md','docs/privacy-network/RUN_AND_DEMO.md'}
NEW={'docs/privacy-network/EXPIRY_REPAIR.md','docs/privacy-network/REPAIR_RESULTS.md','docs/evidence/manual-acceptance/2026-10-09/PRIVACY_NETWORK_FIRST_FAILURE.md'}
PREFIX=('docs/evidence/privacy-network-repair/','services/privacy-network/repair_')
OUT=ROOT/'docs/evidence/privacy-network-repair';G=['git',f'--git-dir={ROOT/".phase0-git"}',f'--work-tree={ROOT}']
def git(*args):return subprocess.check_output(G+list(args),stderr=subprocess.PIPE)
def blob(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def main():
    c.harden();target=OUT/'audit.json';assert not target.exists();assert git('rev-parse','HEAD').decode().strip()==BASE
    frozen=0;unchanged=0;tracked=0
    for item in git('ls-tree','-rz',BASE).split(b'\0'):
        if not item:continue
        meta,name=item.split(b'\t');name=name.decode();raw=(ROOT/name).read_bytes();norm=raw.replace(b'\r\n',b'\n');expected=meta.split()[2].decode();tracked+=1
        if name in EDIT:
            if name.endswith('.md'):
                old=git('cat-file','blob',expected).replace(b'\r\n',b'\n')
                if name=='docs/strategy/DECISION_LOG.md':assert norm.startswith(old.rstrip())
                else:assert norm.endswith(old.split(b'\n\n',1)[1])
            continue
        assert blob(raw if name.startswith('docs/evidence/') else norm)==expected,name;unchanged+=1
        if name.startswith('docs/evidence/'):frozen+=1
    manifest=json.loads((ROOT/'docs/checkpoints/PRESERVATION_MANIFEST_2026-10-09.json').read_bytes())['files']
    old_frozen=[name for name in manifest if name.startswith('docs/evidence/')]
    for name in old_frozen:assert digest((ROOT/name).read_bytes())==manifest[name]['worktree_sha256'],name
    assert git('rev-parse','strategic-pause-2026-10-09^{}').decode().strip()=='4d8a3c9e7d6258a9408698c6b1ea5de3b321e0d6'
    files={ROOT/p for p in EDIT|NEW}
    files.update(p for p in (ROOT/'services/privacy-network').glob('repair_*.py'))
    files.update(p for p in OUT.rglob('*') if p.is_file());files.discard(target)
    for line in git('status','--porcelain','--untracked-files=all').decode().splitlines():
        name=line[3:].strip('"');assert name in EDIT|NEW or name.startswith(PREFIX),name
    # Exact original manual store bytes must still match Phase A, not just metadata.
    original=Path.home()/'.local/share/privacycoin-network-v01'
    inventory={str(p.relative_to(original)):digest(p.read_bytes()) for p in original.rglob('*') if p.is_file() and not p.is_symlink()}
    forensic=json.loads((OUT/'original-forensics.json').read_bytes());assert digest(f.canonical(inventory))==forensic['original_store_fingerprint'] and len(inventory)==18
    # Only NEW explicitly identified campaign fixture roots, never other user wallets.
    roots={NATIVE/'build/privacy-network-repair'}
    for p in OUT.rglob('*.json'):
        r=json.loads(p.read_bytes());name=r.get('private_fixture')
        if name:
            path=Path(name);assert path.is_relative_to(NATIVE/'build/privacy-network-v01') or path.is_relative_to(NATIVE/'build/privacy-network-repair');roots.add(path)
    known=set();ids=set();total=0;unsafe=0
    def wallet_secrets(wallet):
        ids.add(f.wallet_id(wallet));known.update(bytes.fromhex(wallet[k]) for k in ('seed','view') if k in wallet)
        if 'seed' in wallet:known.update(bytes.fromhex(v) for v in f.crypto('derive',wallet['seed'])[:2])
    # Avoid counting nested roots twice.
    roots={p for p in roots if not any(p!=q and p.is_relative_to(q) for q in roots)}
    for root in roots:
        for p in root.rglob('*'):
            if p.is_file() and not p.is_symlink():total+=p.stat().st_size
        for p in root.rglob('runtime-config'):
            password=load_json(p)['password'].encode();known.add(password)
            for wallet in (p.parent/'alice-wallets').glob('*.wallet'):wallet_secrets(c.load(wallet,password))
        for p in root.rglob('control'):
            control=load_json(p);known.update(control[k].encode() for k in ('admin','password'))
            if (p.parent/'state.sqlite').is_symlink():unsafe+=1;continue
            db=sqlite3.connect('file:'+str(p.parent/'state.sqlite')+'?mode=ro',uri=True)
            try:
                for row in db.execute('SELECT wallet FROM quotes'):wallet_secrets(f.open_sealed(row[0],control['password'].encode(),'resource-invoice-wallet'))
            finally:db.close()
        for p in root.rglob('*.intent'):
            q=load_json(p)['quote'];known.update(q[k].encode() for k in ('owner','retriever'))
        for p in root.rglob('*.upload'):
            b=load_json(p)['bundle'];known.update([b['retriever'].encode(),b['key'].encode(),bytes.fromhex(b['key'])])
    assert total<3*1024**3
    compiled=0;links=0
    for p in files:
        raw=p.read_bytes();assert p.suffix not in ('.wallet','.password','.seed','.key','.sqlite','.mdb','.upload','.intent','.retrieval')
        assert not re.search(rb'-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----',raw)
        for secret in known:assert secret not in raw and secret.hex().encode() not in raw,'Secret match withheld'
        if p.suffix=='.py':compile(raw,str(p),'exec');compiled+=1
        if p.suffix=='.md':
            for link in re.findall(r'\]\(([^)]+)\)',raw.decode('utf-8')):
                if '://' in link or link.startswith('#'):continue
                dest=(p.parent/link.split('#')[0]).resolve();assert dest==target or dest.exists(),(p.name,link);links+=1
    prior=json.loads((ROOT/'docs/evidence/privacy-network-v01/audit.json').read_bytes());requirements()
    binaries={p.name:digest(p.read_bytes()) for p in (NATIVE/'build/monero-linux/phase4').glob('privacycoin-hardened-*')};assert binaries==prior['binary_sha256']
    policy=json.loads((ROOT/'docs/evidence/overnight-v1/audit.json').read_bytes());assert {p:digest((ROOT/'.git'/p).read_bytes()) for p in ('HEAD','config')}==policy['ordinary_git_control_sha256']
    assert "default='full'" in (ROOT/'src/phase5b/wallet.py').read_text()
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():continue
        try:args=(p/'cmdline').read_bytes().split(b'\0')
        except OSError:continue
        if not args:continue
        assert str(ROOT/'services/privacy-network/provider.py').encode() not in args,'Owned provider remains'
        if b'privacycoin-hardened-devnet' in args[0]:assert not any(x.startswith(str(q).encode()) for x in args for q in roots),'Owned node remains'
    git('-c','core.whitespace=cr-at-eol','diff','--check');git('fsck','--full')
    report=dict(result='PASS_REPAIR_SCOPE_PRESERVATION_PUBLICATION',starting_commit=BASE,observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),authoritative_git='.phase0-git',worktree='D:/grok Projects/Privacy_Coin',starting_tracked_files=tracked,unchanged_tracked_files=unchanged,frozen_evidence_files_preserved=frozen,original_archive_frozen_evidence_preserved=len(old_frozen),original_manual_store_files_byte_unchanged=len(inventory),original_store_fingerprint=forensic['original_store_fingerprint'],original_store_migrated=False,original_payment_repeated=False,original_human_acceptance='FAILED',original_recovery='PAID_NO_ENTITLEMENT / LEGACY_UNPROVEN; operator resolution pending',ordinary_git_unchanged=True,pause_tag_preserved=True,allowed_existing_changes=sorted(EDIT),publication_sha256={p.relative_to(ROOT).as_posix():digest(p.read_bytes()) for p in sorted(files)},python_files_compiled=compiled,local_links_checked=links,known_disposable_wallets=len(ids),known_secret_encodings=len(known),secret_matches=0,secret_audit_scope='New isolated campaign wallet seed/view/spend encodings, passwords, file keys and capabilities + PEM markers. Not arbitrary-secret or memory-erasure proof. Original plaintext keys were ephemeral in read-only forensic script, not archived.',unsafe_fixture_symlinks_skipped=unsafe,new_private_fixture_bytes=total,binary_sha256=binaries,consensus_crypto_monetary_wallet_signing_changes=False,full_sync_default=True,phase5='INCOMPLETE_WITH_BLOCKERS',phase6a='INCOMPLETE_WITH_BLOCKERS',route_c='PAUSED',r1='KILL',independent_review='PENDING',five_humans='PENDING',mainnet='NOT AUTHORIZED',owned_services_remaining=0,git_fsck='PASS; no cleanup')
    target.write_bytes(json.dumps(report,indent=2,sort_keys=True).encode()+b'\n');print(json.dumps({k:report[k] for k in ('result','frozen_evidence_files_preserved','original_manual_store_files_byte_unchanged','python_files_compiled','new_private_fixture_bytes')}))
if __name__=='__main__':main()
