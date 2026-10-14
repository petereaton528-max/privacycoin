"""Automate the actual graphical installer; not a clean-OS/human acceptance claim."""
import argparse
import json
import os
from pathlib import Path
import time
from apps.network_v1.desktop import safe_root
from apps.network_v1.setup import Installer


def main():
    p=argparse.ArgumentParser();p.add_argument('--archives',type=Path,required=True);p.add_argument('--destination',required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    if a.report.exists() or not a.destination.startswith('/home/privacydev/pc-v1-rc4-'):raise ValueError('NEW_PRIVATE_TEST_DESTINATION')
    release=json.loads((a.archives/'RELEASE.json').read_text());suffix='windows-wsl2-x86_64.zip' if os.name=='nt' else 'linux-x86_64.zip'
    filename=next(name for name in release['archives'] if name.endswith(suffix));root=safe_root();root.withdraw();installer=Installer(root);checks=[];start=time.monotonic()
    def wait():
        end=time.monotonic()+660
        while installer.busy and time.monotonic()<end:root.update();time.sleep(.01)
        if installer.busy:raise TimeoutError('installer deadline')
        root.update()
    try:
        installer.archive.set(str((a.archives/filename).resolve()));installer.digest.set('0'*64);installer.destination.set(a.destination);installer.install();wait()
        assert not hasattr(installer,'installed');checks.append('incorrect external SHA-256 rejects before private installation')
        installer.digest.set(release['archives'][filename]['sha256']);installer.install();wait()
        assert installer.installed==a.destination;assert 'disabled' not in installer.launch_button.state();checks.append('actual graphical private hash-checked installation completes')
        installer.install();wait();assert 'rejected' in installer.status.get();checks.append('same destination refuses overwrite and preserves installed files')
        report=dict(result='PASS_ACTUAL_GRAPHICAL_INSTALLER',checks=checks,elapsed_seconds=round(time.monotonic()-start,3),platform='Windows/Tk + existing WSL2' if os.name=='nt' else 'Linux/Tk',clean_os=False,services_launched=False)
    except Exception as error:report=dict(result='FAIL',failure_type=type(error).__name__,checks=checks)
    finally:root.destroy()
    with a.report.open('x',encoding='utf-8') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps(report));raise SystemExit(0 if report['result'].startswith('PASS') else 1)


if __name__=='__main__':main()
