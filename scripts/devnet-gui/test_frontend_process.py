"""Fresh Windows process launch timings and actual abrupt GUI-process termination."""
from pathlib import Path
import json, os, secrets, subprocess, sys, time
from bridge import Bridge

def main():
    assert os.name=='nt';out=Path(__file__).resolve().parents[2]/'docs/evidence/devnet-gui-v1/frontend-process.json';assert not out.exists()
    script=Path(__file__).with_name('test_gui_node.py');mounted='/mnt/'+script.drive[0].lower()+script.as_posix()[2:]
    node=subprocess.Popen(['wsl.exe','-d','Ubuntu-24.04','-u','privacydev','--','python3',mounted],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
    config=json.loads(node.stdout.readline());password=secrets.token_hex(24);checks=[];trials=[]
    try:
        worker=str(Path(__file__).with_name('test_frontend_worker.py'));common=[sys.executable,worker]
        for _ in range(7):
            t=time.perf_counter();p=subprocess.run(common+['launch',config['home'],str(config['port'])],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
            assert p.returncode==0 and not p.stderr
            # Child prints only after first Tk-render/event + backend hello. Pipe
            # collection includes normal shutdown, measured separately below.
            elapsed=(time.perf_counter()-t)*1000;row=json.loads(p.stdout);row['process_start_ready_and_exit_ms']=elapsed;trials.append(row)
        checks.append('seven fresh Python Tk WSL processes start and exit without stderr')
        b=Bridge(config['home'],config['port']);b.call('create',name='Crash',password=password);b.close()
        child=subprocess.Popen(common+['crash',config['home'],str(config['port'])],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        child.stdin.write((password+'\n').encode());child.stdin.flush();assert child.stdout.readline().strip()==b'READY'
        child.kill();child.wait(timeout=10);child.stdin.close();checks.append('actual Windows TerminateProcess while GUI wallet unlocked')
        b=Bridge(config['home'],config['port'])
        try:
            for i in range(50):
                try:opened=b.call('open',name='Crash',password=password);break
                except ValueError:time.sleep(.1)
            else:raise AssertionError('orphan wallet lock')
            r=b.call('refresh');assert opened['balance'] is None and r['balance']['balance']==0
            checks.append('GUI death closes private pipe, releases backend lock and reopens with full scan')
        finally:b.close()
        raw=json.dumps(dict(result='PASS_FRESH_PROCESS_AND_GUI_CRASH',checks=checks,trials=trials,scope='Fresh Python/Tk process with running WSL distro; timing includes normal shutdown, not just time to ready. Idle wallet frontend killed; uncertain-signing/backend cuts tested separately. Not reboot-cold startup or allocator peak memory.'),indent=2).encode();assert password.encode() not in raw;out.write_bytes(raw+b'\n')
        print('PASS fresh process launches and actual frontend crash recovery')
    finally:
        node.stdin.close()
        try:node.wait(timeout=15)
        except subprocess.TimeoutExpired:node.terminate()
if __name__=='__main__':main()
