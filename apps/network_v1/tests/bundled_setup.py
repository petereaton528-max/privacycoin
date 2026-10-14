"""Real existing graphical installer driven by bundled Python; fresh private target."""
import argparse,json,time
from pathlib import Path
from unittest.mock import patch
from apps.network_v1.desktop import safe_root
from apps.network_v1.setup import Installer

def main():
    p=argparse.ArgumentParser();p.add_argument('--archive',type=Path,required=True);p.add_argument('--sha256',required=True);p.add_argument('--destination',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    if a.destination.exists() or a.report.exists() or not str(a.destination).startswith('/home/privacydev/pc-v1-rc5-metadata-graphical/'):raise ValueError('NEW_PRIVATE_DISPOSABLE_INSTALL_ONLY')
    root=safe_root();root.withdraw();installer=Installer(root);checks=[];start=time.monotonic()
    def wait():
        end=time.monotonic()+120
        while installer.busy and time.monotonic()<end:root.update();time.sleep(.01)
        if installer.busy:raise TimeoutError('bounded graphical installation')
        root.update()
    try:
        installer.archive.set(str(a.archive));installer.destination.set(str(a.destination));installer.digest.set('0'*64);installer.install();wait()
        assert not a.destination.exists();checks.append('incorrect externally supplied checksum rejected before installation')
        installer.digest.set(a.sha256);installer.install();wait()
        assert installer.installed==str(a.destination) and (a.destination/'INSTALL_COMPLETE.json').is_file();checks.append('bundled interpreter drives real graphical private installation')
        assert (a.destination/'build/v1-native-manifest.json').stat().st_mode&0o777==0o600;checks.append('public bootstrap extraction becomes correctly private installed metadata')
        with patch('apps.network_v1.setup.subprocess.Popen') as spawn:
            installer.launch();args=spawn.call_args.args[0]
            assert args==[str(a.destination/'Launch-PC.sh')];checks.append('GUI launch selects installed bundled interpreter entrypoint, not bootstrap Python')
        installer.install();wait();assert 'rejected' in installer.status.get();checks.append('existing destination never overwritten')
        report=dict(result='PASS_REAL_GRAPHICAL_BUNDLED_INSTALLER',checks=checks,seconds=round(time.monotonic()-start,3),clean_os=False,human_acceptance=False,application_launch_in_this_harness='ARGUMENT_SELECTION_ONLY; separate installed GUI workflow executes real engine',services_started=False)
    except Exception as error:report=dict(result='FAIL',checks=checks,failure_type=type(error).__name__)
    finally:root.destroy()
    with a.report.open('x') as stream:json.dump(report,stream,indent=2);stream.write('\n')
    print(json.dumps(report));raise SystemExit(0 if report['result'].startswith('PASS') else 1)

if __name__=='__main__':main()
