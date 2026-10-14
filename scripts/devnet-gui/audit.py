"""Authoritative history, scope, publication and known-disposable-secret audit."""
from pathlib import Path
import datetime, hashlib, json, re, subprocess
from backend import SOURCE as ROOT,NATIVE,c

BASE='70202cbced73ab748f792c77137aa993655dd5c7'
OUT=ROOT/'docs/evidence/devnet-gui-v1/audit.json'
G=['git',f'--git-dir={ROOT/".phase0-git"}',f'--work-tree={ROOT}']
EDIT={'STATUS.md','docs/strategy/DECISION_LOG.md','docs/strategy/ADR-PRIVATE-MACHINE-PAYMENTS.md','docs/strategy/ROUTE_C/STATUS.md','docs/design/ROADMAP.md'}
PREFIXES=('scripts/devnet-gui/','docs/evidence/devnet-gui-v1/','docs/design/DEVNET_GUI','docs/protocol/DEVNET_GUI')
def git(*args):return subprocess.check_output(G+list(args),stderr=subprocess.PIPE)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def blob(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def main():
    assert not OUT.exists();git('merge-base','--is-ancestor',BASE,'HEAD')
    frozen={};code={};unchanged={}
    for entry in git('ls-tree','-rz',BASE).split(b'\0'):
        if not entry:continue
        meta,rel=entry.split(b'\t');path=rel.decode();raw=(ROOT/path).read_bytes();norm=raw.replace(b'\r\n',b'\n');expected=meta.split()[2].decode()
        if path in EDIT:
            old=git('cat-file','blob',expected)
            if path=='STATUS.md':assert norm.endswith(old.split(b'\n\n',1)[1])
            elif path.endswith('/STATUS.md'):assert norm.endswith(old)
            else:assert norm.startswith(old)
            continue
        checked=raw if path.startswith('docs/evidence/') else norm
        assert blob(checked)==expected,path
        unchanged[path]=sha(checked)
        if path.startswith('docs/evidence/'):frozen[path]=sha(raw)
        if path.startswith(('src/','tests/','scripts/')):code[path]=sha(checked)
    for line in git('status','--porcelain','--untracked-files=all').decode().splitlines():
        path=line[3:].strip('"');assert path in EDIT or path.startswith(PREFIXES),path
    publish={ROOT/p for p in EDIT}
    for prefix in PREFIXES[:2]:publish.update(p for p in (ROOT/prefix).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    publish.update((ROOT/'docs/design').glob('DEVNET_GUI*.md'));publish.update((ROOT/'docs/protocol').glob('DEVNET_GUI*.md'));publish.discard(OUT)
    for p in (ROOT/'scripts/devnet-gui').glob('*.py'):compile(p.read_bytes(),str(p),'exec')
    backend=json.loads((OUT.parent/'accepted/backend.json').read_text());gui=json.loads((OUT.parent/'gui.json').read_text());reg=json.loads((OUT.parent/'regressions/summary.json').read_text())
    assert backend['result']=='PASS_DECLARED_BACKEND_CASES' and gui['result']=='PASS_AUTOMATED_NATIVE_TK_WSL_CASES' and reg['result']=='PASS'
    assert len(gui['transaction_workflow_trials_ms'])==7 and len(gui['launch_trials'])==7
    known=[]
    fixture=NATIVE/'build/phase6a-local';password=c.read_private(fixture/'fixture.password');known.append(password)
    for name in 'ABC':
        wallet=c.load(fixture/(name+'.wallet'),password)
        known.extend(bytes.fromhex(wallet[k]) for k in ('seed','view'))
        known.extend(bytes.fromhex(x) for x in c.f.crypto('derive',wallet['seed'])[:2])
    links=0
    for p in publish:
        raw=p.read_bytes()
        assert not re.search(rb'-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----',raw)
        for secret in known:assert secret not in raw and secret.hex().encode() not in raw,'Secret match withheld'
        assert p.suffix not in {'.wallet','.seed','.key','.keys','.password','.capability','.backup','.gui-state'}
        if p.suffix=='.md':
            for link in re.findall(r'\]\(([^)]+)\)',raw.decode('utf-8')):
                if '://' in link or link.startswith('#'):continue
                target=(p.parent/link.split('#')[0]).resolve();assert target==OUT or target.exists(),(p.name,link);links+=1
    prior=json.loads((ROOT/'docs/evidence/route-c-r1/audit.json').read_text())
    binaries={p.name:sha(p.read_bytes()) for p in (NATIVE/'build/monero-linux/phase4').glob('privacycoin-hardened-*')}
    assert binaries==prior['binary_sha256']
    policy={p:sha((ROOT/p).read_bytes()) for p in ('.gitignore','.gitattributes')}
    ordinary={p:sha((ROOT/'.git'/p).read_bytes()) for p in ('HEAD','config') if (ROOT/'.git'/p).is_file()}
    assert policy==prior['git_policy_sha256'] and ordinary==prior['ordinary_git_control_sha256']
    assert "default='full'" in (ROOT/'src/phase5b/wallet.py').read_text()
    subprocess.run(G+['fsck','--full'],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    report=dict(result='PASS_BOUNDED_GUI_SCOPE_HISTORY_PUBLICATION',input_checkpoint=BASE,observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),authoritative_git='.phase0-git',authoritative_worktree='D:/grok Projects/Privacy_Coin',frozen_evidence_files=len(frozen),unchanged_source_test_script_files=len(code),unchanged_tracked_files=len(unchanged),frozen_evidence_sha256=frozen,unchanged_code_sha256=code,publication_sha256={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in sorted(publish)},local_links_checked=links,python_compile='PASS',git_fsck='PASS; dangling objects retained',binary_sha256=binaries,git_policy_sha256=policy,ordinary_git_control_sha256=ordinary,secret_audit=dict(matches=0,retained_disposable_encodings_checked=2*len(known),scope='Known retained Phase6A raw/hex secrets plus publication patterns; new ephemeral secrets checked inside live harnesses before destruction. No arbitrary-secret proof or memory erasure claim.'),active_source_consensus_crypto_changed=False,full_sync_default=True,experimental_default_enabled=False,http_listener=False,phase5='INCOMPLETE_WITH_BLOCKERS',phase6a='INCOMPLETE_WITH_BLOCKERS',route_c='PAUSED',r1='KILL',r2='NOT_STARTED',phase6b='NOT_STARTED',phase7='NOT_STARTED',independent_review='PENDING',manual_gui_uat='PENDING')
    OUT.write_bytes(json.dumps(report,indent=2).encode()+b'\n')
    print(json.dumps({k:report[k] for k in ('result','frozen_evidence_files','unchanged_source_test_script_files','local_links_checked')}))
if __name__=='__main__':main()
