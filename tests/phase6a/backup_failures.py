"""Actual interrupted backup publication and restoration failure boundaries."""
from pathlib import Path
import importlib.util,json,os,sys,tempfile,subprocess
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('backup_safety',ROOT/'tests/phase6a/gates.py');g=importlib.util.module_from_spec(spec);sys.modules['backup_safety']=g;spec.loader.exec_module(g)
c=g.c;f=g.f;OUT=g.OUT
def main():
    assert not (OUT/'backup-failures.json').exists();checks=[]
    with tempfile.TemporaryDirectory(prefix='privacycoin-6a-backup-') as d:
        base=Path(d);base.chmod(0o700);password=os.urandom(32).hex().encode();pf=base/'password';c.write_private(pf,password)
        wallet=f.full();wf=base/'wallet';c.save(wf,wallet,password)
        backup=f.seal(f.recovery(wallet),password,'recovery')
        for stage in ('during_write','before_publish','after_publish'):
            target=base/(stage+'.wallet-backup')
            prog=f"import sys;sys.path.insert(0,{str(ROOT/'src/phase6a')!r});import wallet as c,os,signal;pw=c.read_private({str(pf)!r});w=c.load({str(wf)!r},pw);raw=c.f.seal(c.f.recovery(w),pw,'recovery');c.write_private({str(target)!r},raw,fault=lambda s:os.kill(os.getpid(),signal.SIGKILL) if s=={stage!r} else None)"
            p=g.child(prog);assert p.returncode==-9;checks.append('actual backup SIGKILL '+stage)
            if target.exists():assert f.restore(f.open_sealed(c.read_private(target),password,'recovery'))==wallet
            checks.append('backup absent or complete '+stage)
        destination=base/'destination';c.save(destination,wallet,password);before=destination.read_bytes()
        for key,value in [('version',0),('version',2),('network','wrong'),('schemes',[1,2,1])]:
            recovery=f.recovery(wallet);recovery[key]=value;raw=f.seal(recovery,password,'recovery')
            try:f.restore(f.open_sealed(raw,password,'recovery'))
            except ValueError:checks.append('authenticated unsupported recovery '+key+' '+str(value))
            else:raise AssertionError('unsupported recovery accepted')
            assert destination.read_bytes()==before
        with patch.object(c.os,'fsync',side_effect=OSError('disk injected')):
            try:c.save(base/'disk-error-restore',f.restore(f.open_sealed(backup,password,'recovery')),password)
            except OSError:checks.append('restore disk failure rejected')
            else:raise AssertionError('disk error ignored')
        assert not (base/'disk-error-restore').exists();checks.append('failed restore never publishes incomplete wallet')
        # Concurrent access is serialized before reading/decrypting wallet state.
        with c.lock(wf):
            p=g.child(f"import sys;sys.path.insert(0,{str(ROOT/'src/phase6a')!r});import wallet as c;\nwith c.lock({str(wf)!r}):pass")
            assert p.returncode!=0;checks.append('concurrent process lock rejected')
        raw=f.canonical(dict(result='PASS',checks=checks,check_count=len(checks),supported_versions=[1],old_versions='No earlier supported version exists; v0 is rejected, not migrated'))
        for value in (password,bytes.fromhex(wallet['seed']),bytes.fromhex(wallet['view'])):assert value not in raw and value.hex().encode() not in raw
        (OUT/'backup-failures.json').write_bytes(raw+b'\n')
        print('PASS backup/failure supplement',len(checks))
if __name__=='__main__':main()
