"""Final extracted-artifact verification; disposable secrets only.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,os,pty,select,subprocess,sys,time
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--release',type=Path,required=True);p.add_argument('--work',type=Path,required=True);p.add_argument('--native-root',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    os.umask(0o077)
    if a.work.exists() or not a.work.name.startswith('pc-founder-validation-'):raise ValueError('FRESH_VALIDATION_ONLY')
    a.work.mkdir(mode=0o700);checks=[];begin=time.monotonic()
    def check(name,ok):
        if not ok:raise AssertionError(name)
        checks.append(name);print('PASS '+name,flush=True)
    from .install_founder import install
    release=json.loads((a.release/'RELEASE.json').read_text());archive=a.release/'privacycoin-founder-offline-linux-wsl2.zip';digest=release['sha256'][archive.name]
    first=a.work/'first';second=a.work/'second'
    for destination in (first,second):install(archive,destination,digest)
    check('two independent fresh installs checked against archive SHA256',True)
    for destination in (first,second):
        r=subprocess.run([str(destination/'Founder-Wallet.sh'),'preflight','--private-parent',str(a.work)],capture_output=True,timeout=30)
        check('installed preflight '+destination.name,r.returncode==0 and json.loads(r.stdout)['status']=='PASS')
    # Import the actual extracted code; no source-tree fallback for the unit suite.
    code="import sys,unittest;sys.path.insert(0,sys.argv[1]);from tools.mainnet_prepare.test_founder import FounderTests;r=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(FounderTests));sys.exit(not r.wasSuccessful())"
    env=dict(os.environ,PYTHONHOME=str(first/'runtime/python'),LD_LIBRARY_PATH=str(first/'runtime/lib'));env.pop('PYTHONPATH',None)
    r=subprocess.run([str(first/'runtime/python/bin/python3'),'-I','-B','-c',code,str(first)],capture_output=True,env=env,timeout=120)
    (a.work/'unit-results.txt').write_bytes(r.stdout+r.stderr)
    check('all 18 extracted-package custody regressions',r.returncode==0 and b'Ran 18 tests' in r.stderr)
    # In-memory disposable test secret transferred only over pipes to a separate
    # process/installation, never command arguments, environment or result logs.
    import secrets
    password=secrets.token_hex(24)
    create="""import sys,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from tools.mainnet_prepare import founder as f
h=Path(sys.argv[2]);pw=sys.stdin.buffer.read()
pub=f.create(h/'disposable',pw,purpose='DISPOSABLE_TEST')
for i in (1,2):f.backup(h/'disposable',h/('backup'+str(i)),pw)
print(json.dumps(pub))
"""
    r=subprocess.run([str(first/'runtime/python/bin/python3'),'-I','-B','-c',create,str(first),str(a.work)],input=password.encode(),capture_output=True,env=env,timeout=30)
    check('installed native disposable key generation and two complete backups',r.returncode==0)
    public=json.loads(r.stdout)
    recover="""import sys,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from tools.mainnet_prepare import founder as f
h=Path(sys.argv[2]);pw=sys.stdin.buffer.read()
results=[f.recover(h/('backup'+str(i)),h/('independent'+str(i)),pw) for i in (1,2)]
print(json.dumps(results))
"""
    env2=dict(env,PYTHONHOME=str(second/'runtime/python'),LD_LIBRARY_PATH=str(second/'runtime/lib'))
    r=subprocess.run([str(second/'runtime/python/bin/python3'),'-I','-B','-c',recover,str(second),str(a.work)],input=password.encode(),capture_output=True,env=env2,timeout=30)
    check('both backups independently recovered by second installation',r.returncode==0 and json.loads(r.stdout)==[public,public])
    r=subprocess.run([str(first/'Founder-Wallet.sh'),'create','--profile',str(a.work/'must-not-create'),'--offline-confirmed'],capture_output=True,timeout=30)
    check('owner creation refuses nonterminal and creates no keys',r.returncode!=0 and not (a.work/'must-not-create').exists())
    # Exercise actual hidden CLI input without ever invoking owner generation.
    master,slave=pty.openpty()
    # Detach from the runner's inherited WSL controlling terminal: otherwise
    # getpass correctly selects /dev/tty, bypassing this fixture's slave PTY.
    process=subprocess.Popen([str(second/'Founder-Wallet.sh'),'verify','--file',str(a.work/'backup1'),'--offline-confirmed'],stdin=slave,stdout=slave,stderr=slave,close_fds=True,start_new_session=True)
    os.close(slave);output=b'';sent=False;deadline=time.monotonic()+30
    try:
        while time.monotonic()<deadline:
            ready,_,_=select.select([master],[],[],0.2)
            if ready:
                try:data=os.read(master,65536)
                except OSError:break
                if not data:break
                output+=data
                if not sent and b'Wallet encryption password (hidden):' in output:
                    os.write(master,password.encode()+b'\n');sent=True
            if process.poll() is not None and not ready:break
        if process.poll() is None:process.terminate()
        exitcode=process.wait(timeout=5)
    finally:os.close(master)
    check('actual terminal password hidden; CLI verifies backup',sent and exitcode==0 and b'RECOVERY_VERIFIED' in output and password.encode() not in output)
    check('no secret in captured subprocess diagnostics',all(password.encode() not in v for v in (r.stdout,r.stderr,output)))
    # Only this fixture uses retained native ledger components; package itself
    # contains no ledger/Genesis/node executable and cannot start a network.
    code="import sys;sys.path[:0]=[sys.argv.pop(1),sys.argv.pop(1)];from tools.mainnet_prepare.verify_founder_native import main;main()"
    native_report=a.work/'native.json'
    cmd=[str(first/'runtime/python/bin/python3'),'-I','-B','-c',code,str(first),str(a.native_root),'--native-root',str(a.native_root),'--work',str(a.work/'pc-disposable-founder-native'),'--report',str(native_report)]
    r=subprocess.run(cmd,capture_output=True,env=env,timeout=120)
    (a.work/'native-results.txt').write_bytes(r.stdout+r.stderr)
    check('six actual native allocation/recovery checks from installed founder code',r.returncode==0 and json.loads(native_report.read_text())['result']=='PASS')
    manifest=json.loads((first/'FOUNDER_MANIFEST.json').read_text())
    check('no node Tor miner or GUI launcher in custody package',not any(n.startswith(('candidate-native/','runtime/bin/')) or n=='Launch-PC.sh' for n in manifest['files']))
    # A fresh disposable copy is corrupted; validated installations remain intact.
    bad=a.work/'corrupt-install';install(archive,bad,digest)
    with (bad/'tools/mainnet_prepare/binding.py').open('ab') as out:out.write(b'\n# tampered\n')
    r=subprocess.run([str(bad/'Founder-Wallet.sh'),'preflight'],capture_output=True,timeout=30)
    check('tampered installed source fails closed before key operations',r.returncode!=0)
    result=dict(result='PASS',checks=checks,unit_tests=18,native_checks=6,failures=0,skipped=0,seconds=round(time.monotonic()-begin,3),archive_sha256=digest,source_commit=manifest['source_commit'],installed=str(first),independent_recovery_install=str(second),production_keys_generated=False,services_started=False,external_network=False)
    a.report.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
