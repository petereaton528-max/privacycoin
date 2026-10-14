"""Create a NEW private upstream tree for the isolated compatibility build.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse, hashlib, json, os, zipfile
from pathlib import Path, PurePosixPath
HERE=Path(__file__).resolve().parent
EXPECTED={'jh.c':'df9ff5fa646179e984baf03fbf4be9914893e6900b9f7223d7a115c952df72d3',
 'jh.h':'ca4f3570ce36a46bdc24e749ad1d60f9216ee708076d61fd9f1a1ed336626178',
 'keccak.c':'1fbfb9d4c857dab9f80ad2b6019e146ae64e8d1856ffdc5d03f66275c47ae5ca',
 'keccak.h':'dde2bdb591a893b8ca5890b7e3d5be906812d4b3977e9006b5434e1cf35d3be7'}
sha=lambda b:hashlib.sha256(b).hexdigest()

def replacements():
    files={}
    for p in (HERE/'adapters').iterdir():
        if p.is_file():
            raw=p.read_bytes().replace(b'../vendor/',b'pc_sphlib/')
            files['src/crypto/'+p.name]=raw
    for p in (HERE/'vendor').iterdir():
        if p.is_file():files['src/crypto/pc_sphlib/'+p.name]=p.read_bytes()
    return files

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--archive',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True);a=parser.parse_args()
    os.umask(0o077);a.out.mkdir(parents=True,exist_ok=False)
    with zipfile.ZipFile(a.archive) as z:
        contents={n.removeprefix('.upstream/monero/'):z.read(n) for n in z.namelist() if n.startswith('.upstream/monero/') and not n.endswith('/')}
    for name,h in EXPECTED.items():assert sha(contents['src/crypto/'+name]) in (h,sha(replacements()['src/crypto/'+name]))
    baseline={n:sha(b) for n,b in contents.items()}
    contents.update(replacements())
    for name,data in contents.items():
        p=PurePosixPath(name)
        if p.is_absolute() or '..' in p.parts or '\\' in name:raise ValueError('ARCHIVE_PATH')
        dest=a.out/p;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data)
    record=dict(source_archive_sha256=sha(a.archive.read_bytes()),original_four_sha256=EXPECTED,
                replacements_sha256={n:sha(b) for n,b in replacements().items()},
                unchanged_upstream_files=sum(sha(b)==baseline.get(n) for n,b in contents.items()),
                original_checkout_modified=False,public_release_authorized=False)
    (a.out.parent/'staging.json').write_text(json.dumps(record,indent=2)+'\n')
    print('NEW_ISOLATED_UPSTREAM_STAGED',len(contents))
if __name__=='__main__':main()
