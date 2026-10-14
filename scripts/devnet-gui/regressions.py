"""Rerun unchanged relevant suites into a NEW namespace; historical evidence untouched."""
from pathlib import Path
import hashlib, json, subprocess, tempfile, time
from backend import native,NATIVE,SOURCE
OUT=SOURCE/'docs/evidence/devnet-gui-v1/regressions'

def main():
    OUT.mkdir(parents=True,exist_ok=True);assert not (OUT/'summary.json').exists();results={}
    for name,relative,args in [('consensus','phase1/privacycoin-devnet',['--self-test']),('randomx','external/randomx/randomx-tests',[]),('mining','phase0/phase0_vectors',[])]:
        exe=NATIVE/'build/monero-linux'/relative;t=time.perf_counter()
        p=subprocess.run([str(exe),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=300)
        result=dict(exit_code=p.returncode,seconds=time.perf_counter()-t,executable_sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),stdout=p.stdout.decode(errors='replace'),stderr=p.stderr.decode(errors='replace'))
        (OUT/(name+'.json')).write_text(json.dumps(result,indent=2)+'\n');assert p.returncode==0;results[name]='PASS';print('PASS '+name,flush=True)
    for name,rel in [('wallet','tests/phase6a/gates.py'),('private-transaction','tests/phase4/gates.py'),('persistence','tests/phase4/crash.py'),('mutations','tests/phase4/mutations.py')]:
        module=native('gui_regression_'+name.replace('-','_'),rel)
        destination=OUT/name;destination.mkdir(parents=True,exist_ok=True);module.OUT=destination
        if hasattr(module,'h'):module.h.OUT=destination
        try:module.main();results[name]='PASS'
        finally:
            utilities=module.h.g if hasattr(module,'h') else module.g
            for node in utilities.nodes:
                try:node.stop(crash=True)
                except Exception:pass
        print('PASS unchanged suite '+name,flush=True)
    (OUT/'summary.json').write_text(json.dumps(dict(result='PASS',suites=results,scope='Unmodified wallet/Phase4 private transaction, persistence/mutation suites and consensus/RandomX/mining executables. No frozen evidence overwritten; Phase5 experiments not repeated.'),indent=2)+'\n')

if __name__=='__main__':main()
