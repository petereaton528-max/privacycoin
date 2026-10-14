"""Build the narrow OpenSSL-API TLS helper; no policy changes or key generation."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--toolchain',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    if os.name!='nt' or not a.toolchain.is_absolute() or a.out.exists():raise ValueError('NEW_WINDOWS_BUILD_REQUIRED')
    root=Path(__file__).resolve().parents[2];source=root/'apps/network_v1/native/pc_tls_tools.c'
    compiler=a.toolchain/'bin/gcc.exe';library=a.toolchain/'lib/libcrypto.a'
    a.out.mkdir(parents=True);env=dict(os.environ,PATH=str(a.toolchain/'bin')+os.pathsep+os.environ['PATH'],SOURCE_DATE_EPOCH='1791676800',TZ='UTC',ZERO_AR_DATE='1')
    command=[str(compiler),'-O2','-Wall','-Wextra','-fstack-protector-strong','-D_FORTIFY_SOURCE=2','-static','-static-libgcc','-municode','-Wl,--no-insert-timestamp','-I'+str(a.toolchain/'include'),str(source),str(library),'-lws2_32','-lcrypt32','-lbcrypt','-ladvapi32','-o',str(a.out/'pc-tls-tools.exe')]
    with (a.out/'build.txt').open('xb') as log:result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=90)
    binary=a.out/'pc-tls-tools.exe';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    record=dict(command=command,returncode=result.returncode,source_sha256=sha(source),compiler_sha256=sha(compiler),libcrypto_sha256=sha(library),binary_sha256=sha(binary) if binary.is_file() else None,policy_changed=False,private_material_generated=False,source_scope='Fixed Ed25519 X509 generation and public certificate date parsing via existing OpenSSL APIs; not a general openssl executable')
    with (a.out/'BUILD.json').open('x') as f:json.dump(record,f,indent=2);f.write('\n')
    raise SystemExit(result.returncode)

if __name__=='__main__':main()
