"""Actual Windows Tk widgets + WSL pipes + disposable real node. Automated, no human claim."""
from pathlib import Path
import ctypes, json, os, secrets, statistics, subprocess, sys, time
from unittest.mock import patch
from bridge import Bridge
from gui import App, safe_root

checks=[]
def check(name,value=True):
    if not value:raise AssertionError(name)
    checks.append(name);print('PASS '+name,flush=True)
class Counters(ctypes.Structure):
    _fields_=[('cb',ctypes.c_ulong),('faults',ctypes.c_ulong),('peak',ctypes.c_size_t),('working',ctypes.c_size_t),('pagepeak',ctypes.c_size_t),('page',ctypes.c_size_t),('quota_peak',ctypes.c_size_t),('quota',ctypes.c_size_t),('pagefile',ctypes.c_size_t),('pagefilepeak',ctypes.c_size_t)]
def rss():
    counters=Counters();counters.cb=ctypes.sizeof(counters)
    kernel=ctypes.windll.kernel32;kernel.GetCurrentProcess.restype=ctypes.c_void_p
    query=ctypes.windll.psapi.GetProcessMemoryInfo;query.argtypes=[ctypes.c_void_p,ctypes.POINTER(Counters),ctypes.c_ulong];query.restype=ctypes.c_int
    if not query(kernel.GetCurrentProcess(),ctypes.byref(counters),counters.cb):raise ctypes.WinError()
    return counters.working
def button(root,text):
    for child in root.winfo_children():
        try:
            if child.cget('text')==text and hasattr(child,'invoke'):return child
        except Exception:pass
        found=button(child,text)
        if found:return found
def wait(root,app):
    deadline=time.monotonic()+180
    while app.busy:
        root.update()
        if time.monotonic()>deadline:raise AssertionError('GUI timeout')
        time.sleep(.005)
    root.update()
def main():
    assert os.name=='nt'
    out=Path(__file__).resolve().parents[2]/'docs/evidence/devnet-gui-v1/gui.json';assert not out.exists()
    script=Path(__file__).with_name('test_gui_node.py');mounted='/mnt/'+script.drive[0].lower()+script.as_posix()[2:]
    node=subprocess.Popen(['wsl.exe','-d','Ubuntu-24.04','-u','privacydev','--','python3',mounted],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
    config=json.loads(node.stdout.readline());password=secrets.token_hex(24);errors=[];infos=[];root=None;bridge=None
    def ctl(command,**kw):
        node.stdin.write(json.dumps(dict(command=command,**kw)).encode()+b'\n');node.stdin.flush();return json.loads(node.stdout.readline())
    try:
        with patch('gui.messagebox.showerror',side_effect=lambda *a,**kw:errors.append(a[0])),patch('gui.messagebox.showinfo',side_effect=lambda *a,**kw:infos.append(a[0])),patch('gui.simpledialog.askstring',return_value=password):
            root=safe_root();root.withdraw();bridge=Bridge(config['home'],config['port']);app=App(root,bridge);wait(root,app)
            # Explicit legacy atomic-input mode preserves the frozen workload exactly.
            app.vars['unit'].set('atomic');app.unit='atomic'
            for key,value in dict(amount='1000000',fee='188000',max_fee='500000').items():app.vars[key].set(value)
            check('actual native Tk and real WSL backend ready',app.ready_ms is not None and app.last['network']=='privacycoin-devnet')
            def creds(name):app.vars['name'].set(name);app.vars['password'].set(password)
            creds('Alice');button(root,'Create').invoke();wait(root,app);alice=app.address.get()
            check('create widget opens wallet and clears password',app.opened and not app.vars['password'].get() and app.last['balance']['balance']==0)
            creds('Bob');button(root,'Create').invoke();wait(root,app);bob=app.address.get()
            creds('Alice');button(root,'Open').invoke();wait(root,app)
            ctl('mine',address=alice,blocks=1);button(root,'Full scan / refresh').invoke();wait(root,app)
            check('GUI displays immature and zero spendable',app.last['balance']['locked_coinbase']>0 and app.last['balance']['spendable']==0)
            ctl('mine',address=alice,blocks=79);button(root,'Full scan / refresh').invoke();wait(root,app)
            check('GUI full scan exposes actual height and unknown freshness',app.last['node']['height']==80 and 'UNKNOWN' in app.overview.get('1.0','end'))
            app.vars['destination'].set(bob);app.vars['max_fee'].set('1');button(root,'Review private payment…').invoke();wait(root,app)
            check('GUI fee cap rejection leaves empty pool',app.last_error is not None and not ctl('pool')['transactions'])
            button(root,'Full scan / refresh').invoke();wait(root,app);app.vars['max_fee'].set('500000');app.vars['amount'].set(str(2**63));button(root,'Review private payment…').invoke();wait(root,app)
            check('GUI insufficient funds rejected',app.last_error is not None)
            button(root,'Full scan / refresh').invoke();wait(root,app);app.vars['amount'].set('1000000')
            with patch('gui.simpledialog.askstring',return_value=None):button(root,'Review private payment…').invoke();wait(root,app)
            check('cancel review never broadcasts',not ctl('pool')['transactions'])
            t=time.perf_counter()
            with patch('gui.simpledialog.askstring',return_value='CONFIRM'):button(root,'Review private payment…').invoke();wait(root,app)
            workflow_ms=(time.perf_counter()-t)*1000
            check('actual GUI approved private payment and pending reservation',len(ctl('pool')['transactions'])==1 and app.last['balance']['reserved_inputs']>0)
            creds('Bob');button(root,'Open').invoke();wait(root,app)
            check('GUI pending incoming labelled honestly',app.last['balance']['pending_incoming']==1000000 and app.last['balance']['spendable']==0)
            ctl('mine',address=alice,blocks=2);button(root,'Full scan / refresh').invoke();wait(root,app)
            check('GUI receives exact private payment amount',app.last['balance']['balance']==1000000)
            check('transaction history shows normal locked output honestly','LOCKED' in app.history.get('1.0','end') and app.last['balance']['locked_normal']==1000000)
            app.vars['backup'].set('Bob-recovery');button(root,'Create encrypted backup').invoke();wait(root,app)
            check('GUI encrypted backup completed',infos==['Backup created'])
            app.vars['restore_name'].set('Bob-restored');app.vars['restore_source'].set('Bob-recovery');app.vars['restore_password'].set(password);app.restore_ack.set(True);button(root,'Restore encrypted backup').invoke();wait(root,app)
            check('GUI restore identity and independent full rescan',app.address.get()==bob and app.last['balance']['balance']==1000000)
            ctl('stop');button(root,'Full scan / refresh').invoke();wait(root,app)
            check('GUI disconnected node invalidates balance and signing',app.last_error is not None and 'UNVERIFIED' in app.overview.get('1.0','end') and app.send_button.instate(['disabled']))
            ctl('start');button(root,'Full scan / refresh').invoke();wait(root,app)
            check('GUI reconnect does not lose wallet',app.last['balance']['balance']==1000000)
            button(root,'Lock / close').invoke();wait(root,app)
            check('GUI lock clears address and balance',not app.opened and app.address.get()=='Wallet locked.' and 'UNKNOWN' in app.overview.get('1.0','end'))
            app.vars['name'].set('Bob');app.vars['password'].set(password+'wrong');button(root,'Open').invoke();wait(root,app)
            check('GUI wrong password redacted and invalidated',app.last_error is not None and password not in app.status.get())
            check('failed open clears displayed identity',not app.opened and 'awaiting' in app.address.get())
            app.callback_failed(ValueError,password,None)
            check('Tk callback exception cannot log password',password not in app.status.get() and app.send_button.instate(['disabled']))
            creds('Bob');button(root,'Open').invoke();wait(root,app)
            bridge.close();bridge=Bridge(config['home'],config['port']);app.bridge=bridge
            creds('Bob');button(root,'Open').invoke();wait(root,app)
            check('GUI backend restart opens persisted wallet and rescans',app.last['balance']['balance']==1000000)
            creds('Alice');button(root,'Open').invoke();wait(root,app)
            transaction_trials=[]
            for _ in range(7):
                started=time.perf_counter()
                with patch('gui.simpledialog.askstring',return_value='CONFIRM'):button(root,'Review private payment…').invoke();wait(root,app)
                check('repeated approved workflow '+str(len(transaction_trials)+1),app.last_error is None)
                transaction_trials.append((time.perf_counter()-started)*1000)
            trials=[]
            for _ in range(7):
                # Paired same-session hello is the GUI dispatch overhead control.
                t=time.perf_counter();hello=bridge.call('hello');direct=(time.perf_counter()-t)*1000
                t=time.perf_counter();app.run('hello',{},lambda _:None);wait(root,app);gui_ms=(time.perf_counter()-t)*1000
                trials.append(dict(pipe_hello_ms=direct,gui_dispatch_hello_ms=gui_ms,added_dispatch_ms=gui_ms-direct,windows_working_set_bytes=rss(),backend_rss_kib=hello['rss_kib']))
            coldish=[]
            for _ in range(7):
                t=time.perf_counter();extra=safe_root();extra.withdraw();b=Bridge(config['home'],config['port']);a=App(extra,b);wait(extra,a)
                coldish.append(dict(tk_and_wsl_ready_ms=(time.perf_counter()-t)*1000,windows_working_set_bytes=rss()));a.shutdown()
            check('Windows process working set measured',all(x['windows_working_set_bytes']>0 for x in trials))
            evidence=dict(result='PASS_AUTOMATED_NATIVE_TK_WSL_CASES',checks=checks,tk_version=str(root.tk.call('info','patchlevel')),workflow_sign_broadcast_refresh_ms=workflow_ms,transaction_workflow_trials_ms=transaction_trials,dispatch_trials=trials,launch_trials=coldish,errors_expected=len(errors),scope='Real Tk widgets, automated approval, real disposable devnet. No human acceptance/review claim. Launch includes Tk+WSL bridge in warm Python/WSL, not reboot cold start. Seven real send workflows exclude human deliberation.')
            raw=json.dumps(evidence,indent=2).encode();assert password.encode() not in raw
            out.write_bytes(raw+b'\n')
    finally:
        if bridge:bridge.close()
        if root:
            try:root.destroy()
            except Exception:pass
        node.stdin.close()
        try:node.wait(timeout=15)
        except subprocess.TimeoutExpired:node.terminate()

if __name__=='__main__':main()
