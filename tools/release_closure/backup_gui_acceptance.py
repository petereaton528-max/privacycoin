"""Drive real Tk buttons/native wallets; only file-dialog selection is automated.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,os,secrets,time,tkinter as tk,zipfile
from pathlib import Path
from unittest.mock import patch
from apps.network_v1.candidate_client import Client
from apps.network_v1.candidate_gui import Window,filedialog,messagebox
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--work',type=Path,required=True);p.add_argument('--report',type=Path,required=True);p.add_argument('--reproduce',action='store_true');a=p.parse_args()
os.umask(0o077);a.work.mkdir(mode=0o700,exist_ok=False);checks=[];clients=[];windows=[]
def check(name,condition=True):
    if not condition:raise AssertionError(name)
    checks.append(name)
def window(name):
    c=Client(a.work/name,a.root/'candidate-native/full',a.root);clients.append(c)
    r=tk.Tk();w=Window(r,c);windows.append(w);return w
def click(w,label):
    def children(x):
        for y in x.winfo_children():yield y;yield from children(y)
    b=next(x for x in children(w.root) if x.winfo_class()=='TButton' and x.cget('text')==label);b.invoke()
    end=time.monotonic()+35
    while w.busy and time.monotonic()<end:w.root.update();time.sleep(.01)
    w.root.update();check(label+' finished',not w.busy)
try:
    w=window('original');password='Disposable-'+secrets.token_hex(20);w.fields['password'].set(password);click(w,'Create');check('native GUI wallet created',w.last_error is None)
    original=w.last;history=w.client.payments();caught=[];backup=w.client.backup
    def traced(path):
        try:return backup(path)
        except Exception as e:caught.append(str(e));raise
    w.client.backup=traced
    destination=Path.home()/('PC-Disposable-Backup-'+secrets.token_hex(8))
    with patch.object(filedialog,'asksaveasfilename',return_value=str(destination)),patch.object(messagebox,'askyesno',return_value=True):click(w,'Back up')
    if a.reproduce:
        check('installed GUI reproduces private-directory rejection',caught==['private directory required'] and not destination.exists())
        result=dict(result='REPRODUCED',cause=caught[0],home_mode=oct(Path.home().stat().st_mode&0o777),gui_message=w.status.get(),checks=checks)
    else:
        target=Path.home()/'PrivacyCoin-Backups'/destination.name
        check('GUI redirect creates complete private backup',w.last_error is None and target.is_file() and not destination.exists())
        check('backup permissions',target.stat().st_mode&0o777==0o600 and target.parent.stat().st_mode&0o777==0o700)
        check('success identifies actual destination',str(target) in w.summary.get())
        recovered=window('recovered');recovered.fields['name'].set('Restored');recovered.fields['password'].set(password)
        with patch.object(filedialog,'askopenfilename',return_value=str(target)):click(recovered,'Recover')
        check('independent native recovery exact identity and balances',recovered.last_error is None and all(recovered.last[k]==original[k] for k in ('address','total','available','locked','reserved','height')))
        check('payment history matches',recovered.client.payments()==history)
        bad=window('bad-password');bad.fields['password'].set('incorrect-password')
        with patch.object(filedialog,'askopenfilename',return_value=str(target)):click(bad,'Recover')
        check('wrong password rejected without wallet publication',bad.last_error is not None and not bad.client.path('Wallet').exists())
        corrupt=a.work/'corrupt';corrupt.write_bytes(target.read_bytes()[:-30]);bad.fields['password'].set(password)
        with patch.object(filedialog,'askopenfilename',return_value=str(corrupt)):click(bad,'Recover')
        check('truncated backup rejected without wallet publication',bad.last_error is not None and not bad.client.path('Wallet').exists())
        damaged=a.work/'damaged';raw=bytearray(target.read_bytes())
        with zipfile.ZipFile(target) as archive:
            entry=archive.getinfo('recovery');offset=entry.header_offset+30+len(entry.filename.encode())+len(entry.extra)
        raw[offset+10]^=1;damaged.write_bytes(raw);bad.fields['password'].set(password)
        with patch.object(filedialog,'askopenfilename',return_value=str(damaged)):click(bad,'Recover')
        check('corrupt archive rejected with actionable error',bad.last_error=='BadZipFile' and 'damaged' in bad.status.get() and not bad.client.path('Wallet').exists())
        before=hashlib.sha256(target.read_bytes()).hexdigest()
        with patch.object(filedialog,'asksaveasfilename',return_value=str(target)):click(w,'Back up')
        check('existing backup preserved with actionable error',hashlib.sha256(target.read_bytes()).hexdigest()==before and 'already exists' in w.status.get())
        result=dict(result='PASS',checks=checks,backup=str(target),real_tk=True,real_native=True,automated_file_dialog_selection=True,network=False)
finally:
    for w in windows:
        if w.worker:w.worker.join(timeout=10)
        w.root.after_cancel(w.poll_id);w.root.destroy()
    for c in clients:c.close()
a.report.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
