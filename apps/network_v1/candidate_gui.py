"""Actual offline candidate Tk wallet; no public/network activation interface.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,errno,os,queue,re,threading,time,tkinter as tk,zipfile
from pathlib import Path
from tkinter import ttk,filedialog,messagebox,simpledialog
from .candidate_client import Client,amount
from tools.creator_model.model import pc
def safe_error(error):
    if isinstance(error,zipfile.BadZipFile):return 'The backup archive is damaged or incomplete. Select the original complete backup; no recovery was completed.'
    if isinstance(error,OSError) and error.errno==errno.ENOSPC:return 'There is not enough disk space for a complete backup. Free space and retry with a new filename; preserve existing backups.'
    if isinstance(error,FileNotFoundError):return 'The selected backup or folder is missing. Select the original backup or an existing private destination folder.'
    if isinstance(error,FileExistsError):return 'A backup with that name already exists. Choose a new filename; the existing backup was preserved.'
    if isinstance(error,PermissionError):return 'Cannot write or read the selected location. Choose your private PrivacyCoin-Backups folder; do not change wallet security permissions.'
    messages={
        'wrong password or corrupt encrypted file':'The password is incorrect or the encrypted backup is damaged. Check the original password and backup; no recovery was completed.',
        'private directory required':'This folder is not owner-only. Choose PrivacyCoin-Backups in your home folder. Changing the wallet password will not fix folder permissions.',
        'BACKUP_PRIVATE_FOLDER_REQUIRED':'Cannot safely create the private backup folder. Choose an existing owner-only folder. No security permissions were changed.',
        'WALLET_LOCKED':'Open the wallet with its password before backing up. An already open wallet uses its authenticated password automatically.',
        'BACKUP_DIRECTORY':'The backup is incomplete or damaged. Select the original complete backup; no wallet was recovered.',
        'BACKUP_DIRECTORY_BOUND':'The backup is incomplete, damaged or unsupported. Select the original complete backup; no wallet was recovered.',
        'INCOMPLETE_RECOVERY_USE_ORIGINAL_BACKUP_AND_NEW_NAME':'Recovery was interrupted. Keep the original complete backup and recover it under a NEW wallet name. Do not remove recovery markers.',
        'NEW_WALLET_REQUIRED':'That wallet name already exists or has an incomplete recovery. Choose a new name; existing files were preserved.',
        'RECONCILE_OUTSTANDING_PAYMENT_FIRST':'A previous payment is pending or uncertain. Refresh and inspect History. Do not resend or create a replacement payment.',
        'BACKUP_CAPACITY':'The complete backup exceeds this release\'s 256 MiB limit. No incomplete backup was published. Preserve the original wallet and payment history.',
        'INSUFFICIENT_AVAILABLE_FUNDS':'Not enough available funds. Locked rewards and pending spends cannot be used.',
        'WAIT_FOR_15_ELIGIBLE_RING_DECOYS':'Wait for more mature chain outputs before sending. Privacy rules were not relaxed.',
        'CANDIDATE_GENESIS_MISMATCH':'This recovery belongs to a different network or Genesis. Open the matching isolated client profile.'}
    return messages.get(str(error),'Operation rejected or incomplete. Check password, network, available funds and original private files. An uncertain payment must be reconciled; do not resend.')
class Window:
    def __init__(self,root,client):
        self.root=root;self.client=client;self.busy=False;self.closed=False;self.events=queue.Queue(maxsize=16);self.stop=threading.Event();self.worker=None;self.last_error=None;self.last=None
        root.title('Privacy Coin Mainnet V1 - release candidate' if getattr(client,'production',False) else 'Privacy Coin - OFFLINE Mainnet candidate');root.geometry('790x590')
        frame=ttk.Frame(root,padding=18);frame.pack(fill='both',expand=True)
        ttk.Label(frame,text=('Mainnet V1 release candidate - Tor OFF until explicitly connected' if getattr(client,'production',False) else 'NON-LAUNCHABLE disposable PC - Internet/Tor disabled'),font=('TkDefaultFont',12,'bold')).pack(anchor='w')
        ttk.Label(frame,text=('Approved Mainnet Genesis. New wallets own no creator allocation.' if getattr(client,'production',False) else 'Pinned laboratory Genesis; independently owned local full node.' if client.external else 'First wallet initializes a disposable Genesis. No production creator address is selected.'),wraplength=740).pack(anchor='w',pady=6)
        self.fields={name:tk.StringVar(root) for name in ('name','password','recipient','amount')};self.fields['name'].set('Wallet')
        row=ttk.Frame(frame);row.pack(fill='x')
        for name,label in [('name','Wallet name'),('password','Password (12+ characters)')]:
            box=ttk.Frame(row);box.pack(side='left',fill='x',expand=True,padx=4);ttk.Label(box,text=label).pack(anchor='w');ttk.Entry(box,textvariable=self.fields[name],show='*' if name=='password' else '').pack(fill='x')
        buttons=ttk.Frame(frame);buttons.pack(fill='x',pady=8)
        for label,fn in [('Create',self.create),('Open',self.open),('Lock',self.lock),('Back up',self.backup),('Recover',self.restore),('Refresh',self.refresh),('History',self.history),('Connect Tor',self.connect_tor)]:ttk.Button(buttons,text=label,command=fn).pack(side='left',padx=2)
        ttk.Button(frame,text='Node status / public peer link',command=self.node_info).pack(anchor='w')
        self.tor_summary=tk.StringVar(root,value='Tor disabled.');ttk.Label(frame,textvariable=self.tor_summary,wraplength=740).pack(anchor='w')
        self.address=tk.StringVar(root);ttk.Label(frame,text='Receiving address').pack(anchor='w');ttk.Entry(frame,textvariable=self.address,state='readonly').pack(fill='x');ttk.Button(frame,text='Copy address',command=self.copy).pack(anchor='w',pady=3)
        self.summary=tk.StringVar(root,value='Wallet locked. Mining stopped.');ttk.Label(frame,textvariable=self.summary,wraplength=740,justify='left').pack(anchor='w',pady=8)
        for name,label in [('recipient','Recipient (selected network only)'),('amount','Amount in PC')]:ttk.Label(frame,text=label).pack(anchor='w');ttk.Entry(frame,textvariable=self.fields[name]).pack(fill='x')
        ttk.Button(frame,text='Review payment',command=self.send).pack(anchor='w',pady=5)
        mining=ttk.Frame(frame);mining.pack(fill='x',pady=4);ttk.Button(mining,text='Mine blocks (one CPU worker)',command=self.mine).pack(side='left');self.mine_count=tk.StringVar(root,value='5');ttk.Spinbox(mining,from_=1,to=160,width=5,textvariable=self.mine_count).pack(side='left');ttk.Button(mining,text='Stop mining',command=self.stop.set).pack(side='left',padx=4)
        self.status=tk.StringVar(root,value='Offline candidate ready. No networking or mining started.');ttk.Label(frame,textvariable=self.status,wraplength=740).pack(anchor='w',pady=6)
        root.protocol('WM_DELETE_WINDOW',self.shutdown);self.poll_id=root.after(25,self.poll)
    def run(self,fn,done=None,quiet=False):
        if self.busy or self.closed:return
        self.busy=True;self.background=quiet
        if not quiet:self.last_error=None;self.status.set('Working…')
        def work():
            try:self.events.put((True,fn(),done))
            except Exception as error:self.events.put((False,(type(error).__name__,safe_error(error)),None))
        self.worker=threading.Thread(target=work);self.worker.start()
    def poll(self):
        if self.closed:return
        try:
            ok,result,done=self.events.get_nowait()
            if ok is None:
                self.status.set(result);self.poll_id=self.root.after(25,self.poll);return
            self.busy=False
            if ok:
                if done:done(result)
                if not self.busy and not self.background:self.status.set('Completed. Tor was not activated by this operation.' if not getattr(self.client.node,'tor',None) else 'Completed. Refresh for Tor and verified peer status.')
            elif self.background:self.tor_summary.set('Tor status inspection unavailable. Open Node status; preserve any failure report.')
            else:self.last_error=result[0];self.status.set(result[1])
        except queue.Empty:pass
        tor=getattr(self.client.node,'tor',None)
        if tor and not self.busy and time.monotonic()>=getattr(self,'tor_poll_at',0):
            self.tor_poll_at=time.monotonic()+3
            self.run(tor.status,self.show_tor,quiet=True)
        self.poll_id=self.root.after(25,self.poll)
    def show_tor(self,result):
        state=result['state'];detail={
            'CONTROL_STARTING':'Waiting for the local Tor control listener.',
            'CONTROL_UNAVAILABLE':'Local Tor control is unavailable. Close normally and preserve the status report; do not repeatedly reconnect.',
            'DISCONNECTED':'Tor exited (code '+str(result.get('tor_exit_code'))+'). Close normally and preserve the status report.',
            'TOR_READY':'Tor bootstrapped; verified peer traffic and chain synchronization are still required.'}.get(state,'Waiting for Tor bootstrap through the configured route.')
        self.tor_summary.set('Tor: '+state+'; '+str(result.get('bootstrap_percent',0))+'%. '+detail)
    def show(self,result):
        self.last=result;self.address.set(result['address'])
        self.summary.set('Verified height: '+str(result['height'])+' • release interval: '+str(result['interval'])+' blocks\nTotal: '+pc(result['total'])+' PC\nAvailable: '+pc(result['available'])+' PC • Locked: '+pc(result['locked'])+' PC\nReserved: '+pc(result['reserved'])+' PC • Payment: '+result['payment']+'\nUnlocked outputs still need 15 eligible decoys. Mining rewards require normal maturity.')
    def connect_tor(self):
        if not hasattr(self.client.node,'connect_tor'):
            self.status.set('This wallet attaches to an independent node, or uses the offline pipe. Configure Tor with the node owner.');return
        seeds=simpledialog.askstring('Public peer links','Paste public pcnode links, separated by commas. No private invitation is needed.',parent=self.root)
        if seeds is None:return
        proxy=simpledialog.askstring('Optional upstream SOCKS5','Optional private proxy IP:port; leave empty for ordinary Tor relay connectivity.',parent=self.root)
        if proxy is None:return
        try:
            from .peer_uri import parse
            peers=[parse(value.strip()) for value in seeds.split(',') if value.strip()]
            upstream=None
            if proxy:
                host,port=proxy.rsplit(':',1);upstream=dict(host=host.strip('[]'),port=int(port))
                from .upstream import validate
                upstream=validate(upstream)
        except (ValueError,TypeError):self.status.set('Invalid public peer link or private SOCKS5 route. Nothing started.');return
        if not messagebox.askokcancel('Activate Tor',('This activates Privacy Coin MAINNET Internet connectivity. Proceed only after explicit launch authorization. No mining starts.' if getattr(self.client,'production',False) else 'This activates Internet Tor for the explicitly selected non-production network. No mining starts. Continue?'),parent=self.root):return
        self.run(lambda:self.client.node.connect_tor(self.client.native_root/'runtime/bin/tor',peers,upstream,'CONNECT VIA TOR'),self.show_tor)
    def node_info(self):
        def inspect():
            state=self.client.node.call(op='status');tor=getattr(self.client.node,'tor',None)
            if tor:
                from .peer_uri import format_link
                transport=tor.status();link=''
                if transport['state']=='TOR_READY':
                    try:link=format_link(tor.public_descriptor())
                    except (ValueError,OSError):pass # Keep diagnostic status even during publication/restart races.
                return state,transport,link
            return state,{'state':'DISABLED'},''
        def show(value):
            import json
            state,transport,link=value;window=tk.Toplevel(self.root);window.title('Public node information - '+('Mainnet V1' if getattr(self.client,'production',False) else 'non-production'))
            text=tk.Text(window,width=100,height=22);text.pack(fill='both',expand=True)
            text.insert('end',json.dumps(dict(node=state,transport=transport),indent=2)+'\n\n'+(link or 'No Onion endpoint activated.'))
            text.configure(state='disabled')
            if link:ttk.Button(window,text='Copy PUBLIC peer link',command=lambda:(self.root.clipboard_clear(),self.root.clipboard_append(link))).pack()
        self.run(inspect,show)
    def credentials(self):
        name=self.fields['name'].get();password=self.fields['password'].get().encode();self.fields['password'].set('');return name,password
    def create(self):
        name,password=self.credentials();self.run(lambda:self.client.create(name,password),self.show)
    def open(self):
        name,password=self.credentials();self.run(lambda:self.client.open(name,password),self.show)
    def lock(self):
        self.stop.set();self.run(self.client.lock_wallet,lambda _:self.summary.set('Wallet locked.'))
    def refresh(self):self.run(self.client.refresh,self.show)
    def backup(self,path=None):
        if self.busy or self.closed:return
        try:
            if self.client.wallet is None:raise ValueError('WALLET_LOCKED')
            from .portable_backup import default_directory
            folder=default_directory(self.client.c)
            path=path or filedialog.asksaveasfilename(parent=self.root,title='Save complete encrypted backup',initialdir=str(folder),defaultextension='.pc-candidate-recovery')
            if not path:return
            path=Path(path)
            try:
                with self.client.c.directory(path.parent):pass
            except ValueError as error:
                if str(error)!='private directory required':raise
                if not messagebox.askyesno('Use private backup folder','The selected folder is not owner-only. Save the same filename in your private PrivacyCoin-Backups folder instead? Existing files will not be overwritten.',parent=self.root):return
                path=folder/path.name
        except Exception as error:
            self.last_error=type(error).__name__;self.status.set(safe_error(error));return
        self.run(lambda:self.client.backup(path),lambda _:self.summary.set('Complete encrypted backup saved to '+str(path)+'. Keep the password separately. Test recovery before relying on this backup.'))
    def restore(self,path=None):
        path=path or filedialog.askopenfilename(title='Select encrypted candidate recovery')
        if path:
            name,password=self.credentials();self.run(lambda:self.client.restore(path,name,password),self.show)
    def history(self,offset=0):
        def show(rows):
            window=tk.Toplevel(self.root);window.title('Reconciled payment history')
            ttk.Button(window,text='Previous 50',state='normal' if offset else 'disabled',command=lambda:(window.destroy(),self.history(max(0,offset-50)))).pack()
            ttk.Button(window,text='Next 50',state='normal' if len(rows)==50 else 'disabled',command=lambda:(window.destroy(),self.history(offset+50))).pack()
            text=tk.Text(window,width=100,height=20);text.pack(fill='both',expand=True)
            for row in rows:text.insert('end',row['id']+' '+row['state']+' '+pc(row['amount'])+' PC\n')
            text.configure(state='disabled')
        self.run(lambda:self.client.payments(offset,50),show)
    def copy(self):self.root.clipboard_clear();self.root.clipboard_append(self.address.get())
    def send(self):
        recipient=self.fields['recipient'].get()
        try:value=amount(self.fields['amount'].get())
        except ValueError:self.status.set('Enter a positive PC amount with at most 12 decimals.');return
        def review(plan):
            if messagebox.askokcancel('Confirm payment','Recipient: '+plan['address']+'\nAmount: '+pc(plan['amount'])+' PC\nFee: '+pc(plan['fee'])+' PC'):
                self.run(lambda:(self.client.confirm(plan['id']),self.client.refresh())[1],self.show)
        self.run(lambda:self.client.prepare(recipient,value),review)
    def mine(self):
        if self.busy:return
        try:
            count=int(self.mine_count.get())
            if not 1<=count<=160:raise ValueError()
        except ValueError:self.status.set('Choose 1 to 160 blocks. Mining stays stopped.');return
        self.stop.clear()
        def progress(state):
            try:self.events.put_nowait((None,'Mining: '+format(state['hashrate'],'.1f')+' hashes/s; verified height '+str(state['height'])+'. Stop cancels the current native job.',None))
            except queue.Full:pass
        def bounded():
            for _ in range(count):
                if self.stop.is_set():break
                self.client.mine_one(cancel=self.stop,progress=progress)
            return self.client.refresh()
        self.run(bounded,self.show)
    def shutdown(self):
        self.stop.set()
        if self.busy:self.status.set('Finishing current owned operation before shutdown…');self.root.after(100,self.shutdown);return
        self.closed=True;self.root.after_cancel(self.poll_id);self.client.close();self.root.destroy()
def main():
    p=argparse.ArgumentParser();p.add_argument('--home',type=Path,required=True);p.add_argument('--build',type=Path,required=True);p.add_argument('--native-root',type=Path,required=True);p.add_argument('--authorize-disposable-profile',action='store_true');p.add_argument('--profile',type=Path);p.add_argument('--node-port',type=int);p.add_argument('--start-node',action='store_true');a=p.parse_args()
    if not a.authorize_disposable_profile:raise SystemExit('EXPLICIT_DISPOSABLE_PROFILE_REQUIRED')
    options={}
    if a.profile or a.node_port or a.start_node:
        if not a.profile or not (a.node_port or a.start_node):raise ValueError('PROFILE_AND_NODE_PORT_REQUIRED')
        os.environ['PC_DEVELOPMENT_NETWORK']='candidate-lab';os.environ['PC_CANDIDATE_PROFILE']=str(a.profile.resolve())
        from .candidate_profile import load
        from .candidate_rpc import Node
        profile=load(a.profile)
        if a.start_node:
            from .candidate_runtime import Runtime
            node=Runtime(a.home,a.build,a.profile,rpc_port=a.node_port or 28281)
        else:node=Node(a.node_port,profile)
        options=dict(profile=profile,node=node)
    client=Client(a.home,a.build,a.native_root,**options);root=tk.Tk();Window(root,client);root.mainloop()
if __name__=='__main__':main()
