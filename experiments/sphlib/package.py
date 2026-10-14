"""New local source/Linux/WSL2 artifacts; preserve all historical archives.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,os,shutil,sys,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from apps.network_v1.release import archive,verify,source_files,upstream_files,provenance
from apps.network_v1.licensing import inspect,inspect_set
if __package__:
    from .stage import EXPECTED,replacements
else:
    from stage import EXPECTED,replacements
sha=lambda b:hashlib.sha256(b).hexdigest()

def native_binding(path,binaries):
    native=json.loads(path.read_bytes())
    for rel,digest in binaries.items():
        if not rel.startswith('v1/') and native['binary_sha256'][Path(rel).name]!=digest:
            raise ValueError('ISOLATED_NATIVE_BINDING_MISMATCH')
    return (json.dumps(native,indent=2)+'\n').encode()

def main():
    p=argparse.ArgumentParser();p.add_argument('--base',type=Path,required=True)
    p.add_argument('--old-directory',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--native-manifest',type=Path,help='Verified isolated-build binding; avoids replacing an existing developer manifest')
    p.add_argument('--packaging-revision',default='sphlib.1');a=p.parse_args()
    if not a.packaging_revision or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-' for c in a.packaging_revision):
        raise ValueError('PACKAGING_REVISION')
    os.umask(0o077);a.out.mkdir(parents=True,exist_ok=False)
    core=json.loads((a.base/'core-validation.json').read_text());assert core['result']=='PASS'
    source=source_files();revision=provenance(source);assert not revision['worktree_overlay'],revision['worktree_overlay']
    source['SOURCE_REVISION.json']=(json.dumps(revision,indent=2)+'\n').encode()
    source.update(upstream_files(a.base/'upstream'))
    forbidden=set(EXPECTED.values())
    assert not any(sha(b) in forbidden for b in source.values())
    artifacts={};checks={}
    def pack(name,files,kind,executable=()):
        artifacts[name]=archive(a.out/name,files,kind,executable)
        checks[name]=inspect(a.out/name);assert checks[name]['redistribution_ready'],checks[name]['unresolved']
        assert checks[name]['public_release_authorized'] is False
    full='privacycoin-rc5-sphlib-source.zip';pack(full,source,'source')
    gnu='privacycoin-rc5-gnu-corresponding-source-inspection.zip'
    shutil.copyfile(a.old_directory/gnu,a.out/gnu);verify(a.out/gnu);artifacts[gnu]=sha((a.out/gnu).read_bytes())
    binarymapping={'build/network-v1/pc-public-tools':'v1/pc-public-tools',
        **{'build/monero-linux/'+n:n for n in core['binary_sha256'] if not n.startswith('v1/')}}
    pairs={}
    for kind,old,name in [('linux-x86_64','privacycoin-rc5-linux-crypto-rights-inspection.zip','privacycoin-rc5-linux-sphlib.zip'),
                          ('windows-wsl2-x86_64','privacycoin-rc5-wsl2-crypto-rights-inspection.zip','privacycoin-rc5-wsl2-sphlib.zip')]:
        manifest=verify(a.old_directory/old)
        with zipfile.ZipFile(a.old_directory/old) as z:
            files={n:z.read(n) for n in manifest['files'] if n!='LICENSE_COMPLIANCE.json'}
        old_runtime={n:sha(b) for n,b in files.items() if n.startswith('runtime/')}
        files.update({n:b for n,b in source.items() if not n.startswith('.upstream/')})
        for target,rel in binarymapping.items():
            raw=(a.base/'build-clean'/rel).read_bytes();assert sha(raw)==core['binary_sha256'][rel];files[target]=raw
        files['build/v1-native-manifest.json']=native_binding(a.native_manifest or ROOT/'build/v1-native-manifest.json',core['binary_sha256'])
        files['BUILD.json']=(json.dumps(dict(source_commit=revision['source_commit'],
            clean_build_receipt=json.loads((a.base/'build-clean/build.json').read_text()),
            final_build_and_validation=core,
            method='Isolated build from reviewed source; final validation hashes govern',
            independent_bit_reproducibility_claimed=False),indent=2)+'\n').encode()
        refs=json.loads(files['CORRESPONDING_SOURCE.json']);refs.update(archives={full:artifacts[full],gnu:artifacts[gnu]},source_commit=revision['source_commit'])
        files['CORRESPONDING_SOURCE.json']=(json.dumps(refs,indent=2)+'\n').encode()
        files['DISTRIBUTION-PROVENANCE.json']=(json.dumps(dict(source_commit=revision['source_commit'],version='1.0.0-testnet-candidate.5',packaging_revision=a.packaging_revision,
            clean_rebuilt_crypto=True,source_and_linux_only=True,native_windows_substituted=False,public_release_authorized=False),indent=2)+'\n').encode()
        assert all(sha(files[n])==h for n,h in old_runtime.items())
        pack(name,files,kind,manifest['executable'])
        pairs[name]=inspect_set(a.out/name,a.out)
    record=dict(result='PASS_NEW_SOURCE_LINUX_WSL2_LOCAL_COMPLIANCE',source_commit=revision['source_commit'],source_overlay=False,
        version='1.0.0-testnet-candidate.5',packaging_revision=a.packaging_revision,artifacts=artifacts,checks=checks,source_pairs=pairs,
        inherited_implementations_absent=True,linux_runtimes_unchanged=True,windows_native_artifacts_rebuilt=False,public_release_authorized=False)
    (a.out/'SHA256SUMS').write_text(''.join(h+'  '+n+'\n' for n,h in artifacts.items()))
    (a.out/'RELEASE.json').write_text(json.dumps(record,indent=2)+'\n')
    print(record['result'],len(artifacts),flush=True)
if __name__=='__main__':main()
