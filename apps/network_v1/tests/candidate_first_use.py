"""Actual Tk/native candidate tests, independent installation and recovery.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,os,secrets,time,tkinter as tk
from pathlib import Path
from unittest.mock import patch
from apps.network_v1.candidate_client import Client,load
from apps.network_v1.candidate_gui import Window
from tools.creator_model.model import pc
def main():
    p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--native-root',type=Path,required=True);p.add_argument('--second-root',type=Path,required=True);p.add_argument('--work',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    if a.work.exists() or a.report.exists() or not a.work.name.startswith('pc-candidate-profile-'):raise ValueError('FRESH_PRIVATE_TEST_REQUIRED')
    os.umask(0o077);a.work.mkdir(mode=0o700);client=None;second=None;gui=None;recovery_gui=None;root=None;checks=[];failure=None;began=time.monotonic();password=('Disposable-'+secrets.token_hex(24)).encode()
    def check(name,ok):
        if not ok:raise AssertionError(name)
        checks.append(name);print('PASS '+name,flush=True)
    def rejected(name,fn):
        try:fn()
        except (ValueError,TimeoutError):check(name,True);return
        raise AssertionError(name)
    def pump():
        deadline=time.monotonic()+120
        while time.monotonic()<deadline:
            root.update()
            if not gui.busy:
                if gui.last_error:raise AssertionError('GUI operation rejected')
                return
            time.sleep(.01)
        raise TimeoutError('GUI_DEADLINE')
    try:
        client=Client(a.work/'A',a.build,a.native_root);root=tk.Tk();root.withdraw();gui=Window(root,client)
        gui.fields['name'].set('Owner');gui.fields['password'].set(password.decode());gui.create();pump();initial=gui.last
        check('real GUI creates encrypted draft wallet and native Genesis',initial['height']==0 and initial['available']==15962716940988482 and initial['locked']==143664452468896341 and initial['tor']=='DISABLED')
        check('GUI displays exact native totals and clears password',pc(initial['total']) in gui.summary.get() and pc(initial['locked']) in gui.summary.get() and gui.fields['password'].get()=='')
        address=initial['address'];gui.copy();check('actual Tk clipboard receiving address',root.clipboard_get()==address)
        backup=a.work/'encrypted-recovery';gui.backup(str(backup));pump();check('GUI produces encrypted private recovery',backup.stat().st_mode&0o777==0o600 and password not in backup.read_bytes())
        gui.lock();pump();rejected('wrong wallet password rejected',lambda:client.open('Owner',b'incorrect password'))
        gui.fields['name'].set('Owner');gui.fields['password'].set(password.decode());gui.open();pump();check('GUI reopens same wallet and Genesis',gui.address.get()==address and gui.last['total']==159627169409884823)
        source=Path(__file__).resolve().parents[3]/'apps/network_v1/candidate_client.py'
        check('independent installation has identical candidate source',source.read_bytes()==(a.second_root/'apps/network_v1/candidate_client.py').read_bytes())
        module=load('independent_installed_candidate',a.second_root/'apps/network_v1/candidate_client.py')
        second=module.Client(a.work/'B',a.second_root/'candidate-native/full',a.second_root)
        original_gui=gui;recovery_gui=Window(tk.Toplevel(root),second);gui=recovery_gui
        gui.fields['name'].set('Recovered');gui.fields['password'].set(password.decode());gui.restore(str(backup));pump();gui=original_gui
        check('fresh second installation GUI restores address and Genesis allocation',second.refresh()['address']==address and second.refresh()['total']==159627169409884823)
        rejected('wrong recovery password rejected',lambda:second.restore(backup,'Wrong',b'incorrect password'))
        recipient=client.create('Recipient',password)['address'];client.open('Owner',password)
        rejected('Devnet receiving address refused',lambda:client.prepare(client.f.address(client.wallet,0),10**12))
        dev=client.f.seal({'format':'privacycoin-devnet'},password,'gui-pilot-backup');dev_path=a.work/'devnet-recovery';client.c.write_private(dev_path,dev)
        rejected('actual Devnet recovery envelope refused',lambda:second.restore(dev_path,'Devnet',password))
        rejected('insufficient funds refused',lambda:client.prepare(recipient,2**63))
        rejected('fee above consensus cap refused',lambda:client.prepare(recipient,10**12,10**12+1))
        rejected('missing mandatory ring history prevents genesis-only spending',lambda:client.prepare(recipient,10**12))
        stamp=int(time.time())-500*120
        for _ in range(80):stamp+=120;client.mine_one(stamp)
        gui.refresh();pump();scan=client.adapter.scan(client.wallet,client.node.call(op='history'))
        immature=sum(x['amount'] for x in scan['owned'] if x['height']>0 and not x['spent'] and x['unlock']>80)
        check('GUI scans exact locked creator tranches plus immature native rewards',gui.last['height']==80 and gui.last['locked']==143664452468896341+immature and immature>0 and gui.last['available']>initial['available'])
        gui.fields['recipient'].set(recipient);gui.fields['amount'].set('1.000000000000')
        with patch('tkinter.messagebox.askokcancel',return_value=False):gui.send();pump()
        check('cancelled GUI payment is never submitted',client.node.call(op='pool')['transactions']==[])
        with patch('tkinter.messagebox.askokcancel',return_value=True):gui.send();pump()
        check('GUI explicit confirmation submits actual RingCT payment',client.refresh()['payment']=='PENDING')
        client.mine_one(stamp+120);gui.refresh();pump();check('GUI reconciles confirmed native payment',gui.last['payment']=='CONFIRMED')
        client.open('Recipient',password);check('actual receiving wallet scans exact payment',client.refresh()['total']==10**12)
        client.open('Owner',password)
        # Real submission executes; only its acknowledgement is deliberately lost.
        plan=client.prepare(recipient,10**12);real_call=client.node.call
        def dropped_ack(**q):
            result=real_call(**q)
            if q['op']=='payment':raise TimeoutError('INJECTED_ACK_LOSS')
            return result
        with patch.object(client.node,'call',side_effect=dropped_ack):rejected('actual submitted payment acknowledgement uncertainty retained',lambda:client.confirm(plan['id']))
        check('durable uncertain attempt reconciles to native pool without retry',client.refresh()['payment']=='PENDING')
        rejected('second submission blocked while first payment is pending',lambda:client.prepare(recipient,10**12))
        client.mine_one(stamp+240);check('uncertain attempt confirms once',client.refresh()['payment']=='CONFIRMED')
        public=client.node.call(op='blocks')['blocks'];state=client.node.call(op='history')
        for record in state['chain']:
            if not record['coinbase']:second.node.call(op='import',transaction=record['transaction'])
        for block in public[1:]:second.node.call(op='submit',block=block)
        check('fresh recovered installation independently validates and rescans chain',second.refresh()['total']==client.refresh()['total'] and second.refresh()['node']['tip']==client.refresh()['node']['tip'])
        gui.mine();pump();check('actual GUI bounded mining finishes stopped',gui.last['height']==87 and not gui.busy)
        gui.stop.set();check('mining stop signal explicit and stopped',gui.stop.is_set())
        gui.shutdown();gui=None;root=None;client=None
        reopened=Client(a.work/'A',a.build,a.native_root);client=reopened;client.open('Owner',password)
        check('real application restart preserves wallet and database',client.refresh()['height']==87 and client.refresh()['address']==address)
        for file in (a.work/'A').iterdir():
            if file.is_file():check('private profile permissions '+file.suffix,file.stat().st_mode&0o077==0)
    except BaseException as error:failure=type(error).__name__+': '+str(error);print('FAIL '+failure,flush=True)
    finally:
        if gui:gui.shutdown()
        elif client:client.close()
        if recovery_gui:recovery_gui.closed=True
        if second:second.close()
        result=dict(result='FAIL' if failure else 'PASS',failure=failure,checks=checks,seconds=round(time.monotonic()-began,3),actual_tk=True,actual_native=True,independent_installed_recovery=True,dialog_choices_mocked=True,network='offline unapproved candidate',tor=False,mainnet=False)
        with a.report.open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    if failure:raise SystemExit(1)
if __name__=='__main__':main()
