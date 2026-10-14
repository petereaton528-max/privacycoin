"""Read-only Ubuntu dependency inspection; never installs, connects or opens wallets."""
from pathlib import Path
import ctypes.util,json,os,platform,shutil,subprocess,time
def main():
    start=time.monotonic();checks=[]
    def check(name,state,detail):checks.append(dict(requirement=name,state=state,detail=detail))
    check('architecture','PASS' if platform.machine()=='x86_64' else 'FAIL',platform.machine())
    release=Path('/etc/os-release').read_text()
    check('Ubuntu 24.04','PASS' if 'ID=ubuntu' in release and 'VERSION_ID="24.04"' in release else 'USER_ACTION_REQUIRED','Ubuntu 24.04 tested; other distributions not accepted by this package.')
    check('WSL2 kernel','PASS' if 'wsl2' in platform.release().lower() else 'UNKNOWN',platform.release())
    check('Linux user','PASS' if os.getuid()!=0 else 'FAIL','Non-root user required; desktop username may differ from laptop.')
    import sys
    check('Python runtime','PASS' if sys.version_info[:2]==(3,12) else 'FAIL',platform.python_version()+'; Python 3.12 tested/required for N2.')
    for name in ('python3','cmake','make','g++','gcc','pkg-config'):
        path=shutil.which(name);check(name,'PASS' if path else 'USER_ACTION_REQUIRED','Installed command' if path else 'Review dependency installation guide; nothing installed automatically.')
    for name in ('libsodium','openssl','libunbound','libzmq'):
        try:r=subprocess.run(['pkg-config','--modversion',name],capture_output=True,timeout=5);ok=r.returncode==0;detail=r.stdout.decode().strip() if ok else 'Development package absent or not visible to pkg-config.'
        except (OSError,subprocess.TimeoutExpired):ok=False;detail='Inspection unavailable.'
        check(name,'PASS' if ok else 'USER_ACTION_REQUIRED',detail)
    for name in ('lzma','zstd'):
        check('Optional Tor compression '+name,'PASS' if ctypes.util.find_library(name) else 'UNKNOWN','Shared-library discovery only; not a native-PC development-header requirement or Tor ABI certification.')
    check('Tor','USER_ACTION_REQUIRED','No Tor executed or started. Inspect authenticated runtime and run role.py prepare --tor /absolute/path only after provisioning approval.')
    check('Independent shared-chain link','USER_ACTION_REQUIRED','Node peers are loopback-only. Authenticated cross-host P2P forwarding is not prepared/accepted; no public RPC.')
    print(json.dumps(dict(state='READ_ONLY_LINUX_PREFLIGHT',checks=checks,seconds=time.monotonic()-start,changes='NONE'),indent=2))
if __name__=='__main__':main()
