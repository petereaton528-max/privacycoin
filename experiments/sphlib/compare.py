"""Offline differential experiment; never alters reference source or databases.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse, ctypes as C, hashlib, json, os, random, subprocess, time, re, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
SHIM = '''#include "keccak.h"
size_t test_context_size(void) { return sizeof(KECCAK_CTX); }
void test_stream(const unsigned char *p, size_t n, size_t chunk, unsigned char *out) {
 KECCAK_CTX ctx; keccak_init(&ctx);
 for(size_t i=0;i<n;) {size_t k=n-i<chunk?n-i:chunk;keccak_update(&ctx,p+i,k);i+=k;}
 keccak_finish(&ctx,0); keccak_finish(&ctx,out); keccak_finish(&ctx,out);
}
'''

def main():
    p=argparse.ArgumentParser();p.add_argument('--reference',type=Path,required=True)
    p.add_argument('--jh-kat',type=Path,help='Previously verified author submission ZIP; used locally, never distributed')
    p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    os.umask(0o077);a.out.mkdir(parents=True,exist_ok=False)
    upstream=a.reference.resolve();crypto=upstream/'src/crypto'
    (a.out/'shim.c').write_text(SHIM)
    commands=[]
    def build(name, sources, includes, flags=()):
        cmd=['cc','-std=gnu11','-O2','-fPIC','-shared',*flags,
             *['-I'+str(i) for i in includes],*map(str,sources),str(a.out/'shim.c'),'-o',str(a.out/(name+'.so'))]
        commands.append(cmd)
        proc=subprocess.run(cmd,timeout=90,capture_output=True)
        (a.out/(name+'-compile.txt')).write_bytes(proc.stdout+proc.stderr)
        if proc.returncode:raise RuntimeError(proc.stderr.decode())
        lib=C.CDLL(str(a.out/(name+'.so')))
        lib.jh_hash.argtypes=[C.c_int,C.c_void_p,C.c_ulonglong,C.c_void_p]
        lib.keccak.argtypes=[C.c_void_p,C.c_size_t,C.c_void_p,C.c_int]
        lib.keccakf.argtypes=[C.c_void_p,C.c_int]
        lib.test_stream.argtypes=[C.c_void_p,C.c_size_t,C.c_size_t,C.c_void_p]
        lib.keccak_init.argtypes=[C.c_void_p]
        lib.keccak_update.argtypes=[C.c_void_p,C.c_void_p,C.c_size_t]
        lib.keccak_finish.argtypes=[C.c_void_p,C.c_void_p]
        return lib
    reference=build('reference',[crypto/'jh.c',crypto/'keccak.c'],[crypto,upstream/'contrib/epee/include'])
    sources=[HERE/'adapters/jh.c',HERE/'adapters/keccak.c']
    includes=[HERE/'adapters',HERE/'vendor']
    candidates={
        'native64':build('candidate64',sources,includes),
        'jh32_portable':build('candidate32',sources,includes,['-DSPH_JH_64=0','-DSPH_UNALIGNED=0']),
        'ubsan':build('candidate_ubsan',sources,includes,['-fsanitize=undefined','-fno-sanitize-recover=all']),
    }
    counts={};failed_counts={};failures=[];aggregate=hashlib.sha256();start=time.monotonic()
    def check(group,expected,actual,case):
        counts[group]=counts.get(group,0)+1
        aggregate.update(expected);aggregate.update(actual)
        if actual!=expected:
            failed_counts[group]=failed_counts.get(group,0)+1
            if len(failures)<20:
                failures.append(dict(group=group,case=case,expected=expected.hex(),actual=actual.hex()))
    def digest(lib,data,bits=None,mdlen=32):
        # Misaligned input and output exercise byte access rather than host alignment.
        inp=C.create_string_buffer(b'x'+data+b'\0'*8);out=C.create_string_buffer(210)
        ip=C.byref(inp,1);op=C.byref(out,1)
        if bits is None:lib.keccak(ip,len(data),op,mdlen);n=mdlen
        else:
            n=(bits[0]+7)//8
            assert lib.jh_hash(bits[0],ip,bits[1],op)==0
        return out.raw[1:1+n]
    rng=random.Random(0x50435350)
    lengths=list(range(0,290))+[511,512,513,1023,1024,1025,4095,4096,4097,65535,1048576]
    for name,lib in candidates.items():
        for n in lengths:
            data=rng.randbytes(n)
            for bits in (224,256,384,512):
                check(name+'/jh_bytes',digest(reference,data,(bits,n*8)),digest(lib,data,(bits,n*8)),[bits,n])
            for size in (32,40,48,56,64,72,80,88,96,200):
                check(name+'/keccak',digest(reference,data,mdlen=size),digest(lib,data,mdlen=size),[size,n])
            for chunk in (1,7,64,135,136,137,1024) if n<4098 else (137,4096):
                results=[]
                for impl in (reference,lib):
                    out=C.create_string_buffer(32);impl.test_stream(data,n,chunk,out);results.append(out.raw)
                check(name+'/incremental',*results,[n,chunk])
        # Partial-bit interfaces, including discarded low bits. PC calls JH on bytes.
        for n in list(range(1,521))+[1023,1025,4095,4097]:
            data=rng.randbytes((n+7)//8)
            for bits in (224,256,384,512):
                check(name+'/jh_bits',digest(reference,data,(bits,n)),digest(lib,data,(bits,n)),[bits,n,data.hex()])
        check(name+'/context_ABI',reference.test_context_size().to_bytes(4,'little'),lib.test_context_size().to_bytes(4,'little'),'sizeof')
        for n in (0,1,135,136,137,1024,4097):
            data=rng.randbytes(n)
            for first,last in ((reference,lib),(lib,reference)):
                state=(C.c_uint64*43)();out=C.create_string_buffer(32)
                first.keccak_init(state)
                first.keccak_update(state,data[:n//2],n//2)
                last.keccak_update(state,data[n//2:],n-n//2)
                last.keccak_finish(state,out)
                check(name+'/cross_version_context',digest(reference,data),out.raw,n)
        for n in (0,1,63,64,135,136,137,1024):
            for size in (32,200):
                data=rng.randbytes(n);expected=digest(reference,data,mdlen=size)
                for impl in (reference,lib):
                    overlap=C.create_string_buffer(data+b'\0'*201)
                    impl.keccak(overlap,n,overlap,size)
                    check(name+'/overlap',expected,overlap.raw[:size],[n,size])
        for rounds in range(25):
            for trial in range(16):
                state=[rng.getrandbits(64) for _ in range(25)]
                left=(C.c_uint64*25)(*state);right=(C.c_uint64*25)(*state)
                reference.keccakf(left,rounds);lib.keccakf(right,rounds)
                check(name+'/permutation',bytes(left),bytes(right),[rounds,trial])
        for filename,kind in [('tests-fast.txt','keccak'),('tests-extra-jh.txt','jh')]:
            for i,line in enumerate((upstream/'tests/hash'/filename).read_text().splitlines()):
                expected,hexdata=line.split();data=b'' if hexdata=='x' else bytes.fromhex(hexdata)
                actual=digest(lib,data,(256,len(data)*8)) if kind=='jh' else digest(lib,data)
                check(name+'/upstream_KAT_'+kind,bytes.fromhex(expected),actual,i)
        kat=a.jh_kat or ROOT.parent/'Privacy_Coin_V1_20261011/out/network-v1-redistribution-holds1/jh-submission.zip'
        if not kat.exists():raise ValueError('PREVIOUSLY_VERIFIED_AUTHOR_KAT_ARCHIVE_REQUIRED')
        if hashlib.sha256(kat.read_bytes()).hexdigest()!='b06d58ec87243fa9b5919c82b05a9d10036280ad4ede71f06fa51efe6b0638c1':raise ValueError('AUTHOR_KAT_ARCHIVE_HASH')
        with zipfile.ZipFile(kat) as z:
            for bits in (224,256,384,512):
                vectors=re.findall(r'Len\s*=\s*(\d+)\s+Msg\s*=\s*([0-9A-Fa-f]+)\s+MD\s*=\s*([0-9A-Fa-f]+)',z.read(f'KAT_MCT/ShortMsgKAT_{bits}.txt').decode())
                assert len(vectors)==2048
                for length,message,md in vectors:
                    n=int(length);data=bytes.fromhex(message)
                    check(name+'/author_JH_KAT',bytes.fromhex(md),digest(lib,data,(bits,n)),[bits,n])
        out=C.create_string_buffer(64)
        for invalid in (-1,0,1,128,255,257,1024):
            check(name+'/invalid_jh',bytes([reference.jh_hash(invalid,b'',0,out)]),bytes([lib.jh_hash(invalid,b'',0,out)]),invalid)
    result=dict(result='PASS' if not failures else 'FAIL',platform=os.uname()._asdict() if hasattr(os.uname(),'_asdict') else str(os.uname()),
        commands=commands,counts=counts,total=sum(counts.values()),failed_counts=failed_counts,failures=failures,comparison_sha256=aggregate.hexdigest(),elapsed_seconds=time.monotonic()-start,
        source_sha256={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [crypto/'jh.c',crypto/'jh.h',crypto/'keccak.c',crypto/'keccak.h',*sources]},
        limitation='32-bit JH arithmetic on x86_64; not an executed 32-bit or big-endian operating system; no physical-host evidence')
    (a.out/'comparison.json').write_text(json.dumps(result,indent=2)+'\n')
    print(result['result'],result['total'],'comparisons',len(failures),'recorded mismatches',flush=True)
    if failures:print(json.dumps(failures[:4],indent=2))
    return bool(failures)

if __name__=='__main__':raise SystemExit(main())

