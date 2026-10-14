"""Explicit offline build of new adapter using existing pinned build libraries.

Does not modify the cache or rebuild existing node/Provider. Not a clean rebuild.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--cache-source', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    root = Path(__file__).resolve().parents[2]
    cache = a.cache_source / 'build/monero-linux'
    if a.out.exists() or a.out.is_symlink():
        raise ValueError('NEW_BUILD_DESTINATION_REQUIRED')
    a.out.mkdir(mode=0o700, parents=True)
    line = shlex.split((cache/'CMakeFiles/privacycoin-wallet-crypto.dir/link.txt').read_text())
    pivot = line.index('-o')
    libraries = [str(cache/x) if not x.startswith(('-', '/')) else x for x in line[pivot+2:]]
    source = root/'apps/network_v1/native/public_tools.cpp'
    target = a.out/'pc-public-tools'
    args = [line[0], '-std=c++17', '-O2', '-pthread', '-fstack-protector-strong',
            '-I'+str(a.cache_source/'.upstream/monero/src'),
            '-I'+str(a.cache_source/'.upstream/monero/external/randomx/src'),
            '-I'+str(root/'src'), '-Wl,--wrap=__cxa_throw', '-Wl,-u,__wrap___cxa_throw',
            '-Wl,-z,relro,-z,now,-z,noexecstack', str(source), '-o', str(target), *libraries]
    for rel in ('external/rapidjson/include', 'external/easylogging++', 'contrib/epee/include',
                'external', 'external/supercop/include'):
        args.insert(1, '-I'+str(a.cache_source/'.upstream/monero'/rel))
    args.insert(1, '-I'+str(cache/'generated_include'))
    with (a.out/'build.log').open('xb') as log:
        result = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT, timeout=180)
    if result.returncode:
        raise ValueError('BUILD_FAILED_INSPECT_LOCAL_LOG')
    sha = lambda x: hashlib.sha256(x.read_bytes()).hexdigest()
    manifest = dict(kind='CACHE_LINKED_LINUX_ADAPTER_NOT_CLEAN_REBUILD', command=args,
                    source_sha256=sha(source), binary_sha256=sha(target),
                    cache_libraries_sha256={str(Path(x).relative_to(cache)):sha(Path(x)) for x in libraries if x.startswith(str(cache)) and Path(x).is_file()})
    (a.out/'build.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print('V1_ADAPTER_BUILD_PASS_NOT_REPRODUCIBILITY_CERTIFICATION')


if __name__ == '__main__':
    main()
