"""10000-block real paginated RPC/P2P catch-up. One host, new copies only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
from apps.network_v1.rpc import rpc,GENESIS


def main():
    p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    root=Path('/home/privacydev/pc-v1-fixtures-rc4-network-growth1');source=Path('/home/privacydev/pc-v1-fixtures-rc4-growth1/chain/data.mdb')
    if root.exists() or a.report.exists():raise ValueError('NEW_FIXTURE_AND_REPORT_REQUIRED')
    os.umask(0o077);root.mkdir(mode=0o700);(root/'A').mkdir(mode=0o700)
    before=hashlib.sha256(source.read_bytes()).hexdigest();shutil.copyfile(source,root/'A/data.mdb')
    children=[];checks=[];measurements={};start=time.monotonic()
    def check(name,ok):
        if not ok:raise AssertionError(name)
        checks.append(name);print('PASS',name,flush=True)
    def launch(name,rpc_port,p2p,peer=None):
        for port in (rpc_port,p2p):
            with socket.socket() as s:s.bind(('127.0.0.1',port))
        command=[str(a.binary),'--data-dir',str(root/name),'--rpc-port',str(rpc_port),'--p2p-port',str(p2p)]
        if peer:command+=['--peer-port',str(peer)]
        child=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);children.append(child);return child
    try:
        A=launch('A',33581,33582);deadline=time.monotonic()+1000
        while time.monotonic()<deadline:
            if A.poll() is not None:raise ValueError('owned source reload failed')
            try:status=rpc(33581,'status');break
            except (ValueError,OSError):time.sleep(.5)
        else:raise TimeoutError('10000-block reload deadline')
        check('final_clean_binary_revalidates_quiescent_10000_block_copy',status['height']==10000)
        measurements['full_reload_seconds']=round(time.monotonic()-start,3)
        inventory=[];offset=0;cursor=None
        while True:
            page=rpc(33581,'inventory',offset=offset,**({'cursor':cursor} if cursor else {}))
            check('inventory_page_frame_bound_'+str(offset),0<len(page['blocks'])<=1024)
            inventory.extend(page['blocks']);offset=page['next'];cursor=page['cursor']
            if offset==page['total']:break
        check('complete_inventory_no_duplicates',len(inventory)==10001 and len(set(inventory))==10001)
        chain=[];offset=0
        while True:
            page=rpc(33581,'chain',offset=offset,tip=status['tip']);chain.extend(page['chain']);offset=page['next']
            if offset==page['total']:break
        check('complete_canonical_pages',chain[0]==GENESIS and len(chain)==10001 and chain[-1]==status['tip'])
        for h in (0,1023,1024,2047,2048,9999,10000):check('RPC_height_mapping_'+str(h),rpc(33581,'get_block',hash=chain[h])['height']==h)
        B=launch('B',33591,33592,33582);began=time.monotonic();deadline=began+1100;last=-1
        while time.monotonic()<deadline:
            if B.poll() is not None:raise ValueError('owned syncing node failed')
            try:
                observed=rpc(33591,'status')
                if observed['height']//1000!=last:
                    last=observed['height']//1000;print('SYNC_PROGRESS height='+str(observed['height']),flush=True)
                if observed['height']==10000 and observed['tip']==status['tip']:break
            except (ValueError,OSError):pass
            time.sleep(.5)
        else:raise TimeoutError('paginated 10000-block synchronization deadline')
        measurements['fresh_peer_sync_seconds']=round(time.monotonic()-began,3)
        check('fresh_independent_process_validates_all_10000_blocks_via_paged_P2P',observed['issued']==status['issued'] and observed['work']==status['work'])
        check('closed_backup_source_byte_unchanged',hashlib.sha256(source.read_bytes()).hexdigest()==before)
        report=dict(result='PASS_REAL_10000_PAGED_RPC_P2P_ONE_HOST',checks=checks,measurements=measurements,physical_hosts='ONE_ONLY',public_tor=False)
    except Exception as error:report=dict(result='FAIL',failure_type=type(error).__name__,checks=checks,measurements=measurements)
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
                try:child.wait(timeout=15)
                except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
    with a.report.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps(report));raise SystemExit(0 if report['result'].startswith('PASS') else 1)


if __name__=='__main__':main()
