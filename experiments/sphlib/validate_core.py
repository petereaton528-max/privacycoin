"""Bounded isolated real-core checks after the clean sphlib build.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,importlib.util,json,os,shlex,subprocess,time,sys,shutil
from pathlib import Path
from stage import replacements
ROOT=Path(__file__).resolve().parents[2]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser();p.add_argument('--base',type=Path,required=True);a=p.parse_args()
    os.umask(0o077);base=a.base;build=base/'build-clean'
    if (base/'core-validation.json').exists():raise ValueError('NEW_VALIDATION_RECORD_REQUIRED')
    assert (build/'build.json').exists(), 'COMPLETE_CLEAN_BUILD_REQUIRED'
    rows=json.loads((base/'core-progress.json').read_text()) if (base/'core-progress.json').exists() else []
    def run(name,cmd,timeout=300,cwd=ROOT):
        if any(r['name']==name and r['exit']==0 for r in rows):return
        start=time.monotonic()
        attempt=sum(r['name']==name for r in rows)
        logfile=base/(name+('-retry'+str(attempt) if attempt else '')+'.txt')
        while logfile.exists():
            attempt+=1;logfile=base/(name+'-retry'+str(attempt)+'.txt')
        with logfile.open('xb') as log:
            proc=subprocess.run(list(map(str,cmd)),cwd=cwd,stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
        row=dict(name=name,command=list(map(str,cmd)),cwd=str(cwd),exit=proc.returncode,seconds=round(time.monotonic()-start,3),log=str(logfile),log_sha256=sha(logfile))
        rows.append(row);print(name,proc.returncode,flush=True)
        (base/'core-progress.json').write_text(json.dumps(rows,indent=2)+'\n')
        if proc.returncode:raise ValueError(name+'_FAILED_LOG_RETAINED')
    # First clean build was already running when UBSan found the alignment issue.
    # Preserve that receipt, then update ONLY the isolated upstream adaptations.
    for n,b in replacements().items():
        target=base/'upstream'/n
        if target.read_bytes()!=b:target.write_bytes(b)
    run('final-crypto-rebuild',['cmake','--build',build,'--target','privacycoin-hardened-devnet','privacycoin-hardened-crypto','privacycoin-wallet-crypto','pc-public-tools','phase0_vectors','-j2'],900)
    for phase in ('phase2','phase4'):
        dest=ROOT/'build/monero-linux'/phase;dest.parent.mkdir(parents=True,exist_ok=True)
        if dest.exists() or dest.is_symlink():assert dest.is_symlink() and dest.resolve()==(build/phase).resolve()
        else:dest.symlink_to(build/phase,target_is_directory=True)
    path=ROOT/'build/v1-native-manifest.json'
    paths=['phase4/privacycoin-hardened-devnet','phase4/privacycoin-hardened-crypto','phase2/privacycoin-wallet-crypto']
    sources=[p for p in (ROOT/'src').rglob('*') if p.is_file() and '__pycache__' not in p.parts]
    sources += [ROOT/'tests/phase4/CMakeLists.txt',ROOT/'scripts/devnet-gui/launcher_host.py',ROOT/'apps/network_v1/native/public_tools.cpp']
    path.write_text(json.dumps(dict(version=1,kind='V1_LOCAL_SOURCE_BUILD',source_sha256={p.relative_to(ROOT).as_posix():sha(p) for p in sources},binary_sha256={Path(n).name:sha(build/n) for n in paths}),indent=2)+'\n');path.chmod(0o600)
    run('consensus-vectors',[build/'phase0/phase0_vectors'])
    run('genesis',[build/'phase0/phase0_vectors','--genesis'])
    actual=json.loads((base/'genesis.txt').read_text());expected=json.loads((ROOT/'tests/phase0/genesis.json').read_text())
    assert actual==expected,'HISTORICAL_GENESIS_MISMATCH'
    # Reuse unchanged compiled upstream test objects and libraries, replacing
    # cncrypto with the freshly built archive. Never modify the cache.
    cache=Path('/home/privacydev/privacycoin-dev/Privacy_Coin/build/monero-linux')
    link=shlex.split((cache/'tests/unit_tests/CMakeFiles/unit_tests.dir/link.txt').read_text())
    out=base/'unit_tests-sphlib'
    args=[];next_output=False
    for word in link:
        if next_output:args.append(str(out));next_output=False;continue
        if word=='-o':args.append(word);next_output=True;continue
        if word.endswith('src/crypto/libcncrypto.a') or word=='../../src/crypto/libcncrypto.a':word=str(build/'src/crypto/libcncrypto.a')
        elif not word.startswith(('-','/')):word=str((cache/'tests/unit_tests'/word).resolve())
        args.append(word)
    assert str(build/'src/crypto/libcncrypto.a') in args
    run('link-upstream-regression',args,180,cwd=cache/'tests/unit_tests')
    run('upstream-regression',[out,'--gtest_filter=Crypto.*:keccak.*:keccak_hmac.*:bulletproofs.*:bulletproof.*:bulletproofs_plus.*:ringct.*:tx_proof.*:block_reward*.*:difficulty.*:Serialization.*:JsonSerialization.*:JsonRpcSerialization.*:WalletSubaddress.*:BlockchainDBTest/*.*:account.*:chacha8.*:verRctNonSemanticsSimple.*'],300,cwd=cache/'tests/unit_tests')
    # DrvFS is not private POSIX storage. Install an independent application
    # copy into native 0700/0600 directories instead of weakening the guards.
    app=base/'private-app'
    if not app.exists():
        sys.path.insert(0,str(ROOT));from apps.network_v1.release import source_files
        app.mkdir(mode=0o700)
        for n,b in source_files().items():
            target=app/n;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(b);target.chmod(0o600)
        for n in paths:
            target=app/'build/monero-linux'/n;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(build/n,target);target.chmod(0o700)
        shutil.copyfile(path,app/'build/v1-native-manifest.json');(app/'build/v1-native-manifest.json').chmod(0o600)
    attempt=sum(r['name']=='real-core-integration' for r in rows)
    integration_report=base/('integration-attempt'+str(attempt)+'.json')
    run('real-core-integration',['python3','-m','apps.network_v1.tests.integration',
        '--fixture-root','/home/privacydev/pc-v1-fixtures-sphlib-'+str(os.getpid()),
        '--helper',build/'v1/pc-public-tools','--report',integration_report,
        '--native-root',app,'--authorize-disposable-test-mining-payment'],600,cwd=app)
    record=dict(result='PASS',commands=rows,genesis_exactly_unchanged=True,
        binary_sha256={n:sha(build/n) for n in paths+['v1/pc-public-tools']},
        replacement_sha256={n:hashlib.sha256(b).hexdigest() for n,b in replacements().items()},
        clean_build=True,upstream_unit_test_objects_reused=True,integration_report=str(integration_report),
        unit_test_crypto_archive_sha256=sha(build/'src/crypto/libcncrypto.a'),
        isolated_single_host=True,n2_access=False,physical_host_validation=False)
    (base/'core-validation.json').write_text(json.dumps(record,indent=2)+'\n')
    print('ISOLATED_CORE_VALIDATION_PASS',flush=True)
if __name__=='__main__':main()
