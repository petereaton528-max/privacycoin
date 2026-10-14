"""Tk presentation and private backend pipe; Windows native preview or WSL2.

The distributed Windows compatibility package remains WSL2-dependent. Explicit
Windows source roots select the unfinished native backend, without WSL fallback.
No credentials in argv/environment, local HTTP or browser storage.
"""
import argparse
import io
import json
import os
from pathlib import Path,PurePosixPath
import secrets
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk,messagebox,simpledialog

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/devnet-gui'))
from bridge import Bridge
from gui import App,safe_root


class ProductBridge(Bridge):
    def __init__(self, backend_root=None, home=None, port=29881, p2p=29882):
        self.backend_root=backend_root
        self.native_windows=False
        if os.name=='nt':
            if not backend_root or '\n' in backend_root or '\r' in backend_root:raise ValueError('EXPLICIT_INSTALLED_BACKEND_ROOT_REQUIRED')
            if backend_root.startswith('/'):
                if '..' in PurePosixPath(backend_root).parts:raise ValueError('ABSOLUTE_INSTALLED_WSL_BACKEND_REQUIRED')
                args=['wsl.exe','-d','Ubuntu-24.04','--cd',backend_root,'--','/bin/sh',backend_root+'/apps/network_v1/Backend-PC.sh']
            else:
                if not Path(backend_root).is_absolute() or '..' in Path(backend_root).parts:raise ValueError('ABSOLUTE_NATIVE_BACKEND_ROOT_REQUIRED')
                self.native_windows=True
                args=[sys.executable,'-B','-m','apps.network_v1.desktop_backend']
        else:args=[sys.executable,'-B','-m','apps.network_v1.desktop_backend']
        if home:args+=['--home',home]
        args+=['--port',str(port),'--p2p',str(p2p)]
        self.timeout=120;self.lock=threading.Lock();self.closed=False
        self.port=port
        if os.name!='nt' and backend_root and (not Path(backend_root).is_absolute() or '..' in Path(backend_root).parts):raise ValueError('ABSOLUTE_BACKEND_ROOT_REQUIRED')
        if self.native_windows:
            from .windows_owned import spawn
            self.process=spawn(args,cwd=backend_root,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,bufsize=0)
        else:self.process=subprocess.Popen(args,cwd=backend_root if os.name!='nt' and backend_root else ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,bufsize=0,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        self.process.stdout=io.BufferedReader(self.process.stdout)

    def close(self):
        if self.closed:return
        self.closed=True
        try:self.process.stdin.close()
        except OSError:pass
        try:self.process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=5)
        finally:
            if self.native_windows:
                from .windows_owned import stop
                stop(self.process)
            self.process.stdout.close()


class Desktop(App):
    def __init__(self,root,bridge):
        super().__init__(root,bridge)
        root.title('Privacy Coin Network V1 · TESTNET · '+('Windows native preview' if getattr(bridge,'native_windows',False) else 'Windows + WSL2 backend' if os.name=='nt' else 'Linux'))
        self.vars['port'].set(str(bridge.port));self.product_timer=None;self.prediction_rows={};self.prediction_enabled=False
        home=ttk.Frame(self.tabs,padding=16);self.tabs.insert(0,home,text='Start / Tor / mining');self.tabs.select(home)
        ttk.Label(home,text='TESTNET ONLY — no monetary value',font=('Segoe UI',16,'bold')).pack(anchor='w')
        from .onboarding import Guide
        ttk.Button(home,text='Guided setup: wallet → verified recovery → network',command=lambda:Guide(self)).pack(anchor='w',pady=8)
        self.connection_summary=tk.StringVar(root,value='Local services stopped. Mining is OFF.');ttk.Label(home,textvariable=self.connection_summary,wraplength=850).pack(anchor='w',pady=5)
        from .rpc import NETWORK
        ttk.Label(home,text='Create or open your wallet with Guided setup; the local node starts automatically.\nVerify an encrypted backup, then add public peer links and connect through bundled Tor.\nDisposable '+NETWORK+' development network only; no Mainnet or real monetary value.\nMining and optional applications stay disabled until you explicitly start them.',wraplength=850).pack(anchor='w',pady=8)
        row=ttk.Frame(home);row.pack(fill='x')
        for label,cmd in [('Start node','node_start'),('Stop own services','node_stop'),('Refresh status','product_status')]:ttk.Button(row,text=label,command=lambda c=cmd:self.action(c,{},self.show_product)).pack(side='left',padx=4)
        row=ttk.Frame(home);row.pack(fill='x',pady=8)
        controls=[('Download verified Tor',self.provision_tor),('Set Tor executable (advanced)',self.configure_tor),('Add Onion peer',self.add_peer),
                  ('Import seed catalogs',self.import_bootstrap),('Connect via Tor',self.start_tor),
                  ('Disconnect Tor',lambda:self.action('tor_stop',{},self.show_product)),
                  ('Copy my public peer link',self.copy_peer_link),('Upstream proxy (optional)',self.configure_upstream),
                  ('Discover candidates',lambda:self.action('discover_peers',{},self.show_product))]
        for i,(label,command) in enumerate(controls):
            ttk.Button(row,text=label,command=command).grid(row=i//4,column=i%4,sticky='ew',padx=4,pady=3)
        row=ttk.Frame(home);row.pack(fill='x',pady=8)
        ttk.Label(row,text='CPU preset (one worker):').pack(side='left');self.cpu_preset=tk.StringVar(root,value='balanced');ttk.Combobox(row,textvariable=self.cpu_preset,state='readonly',values=('light','balanced','maximum'),width=12).pack(side='left',padx=6)
        ttk.Label(row,text='Stop after blocks:').pack(side='left');self.block_limit=tk.StringVar(root,value='1');ttk.Spinbox(row,from_=1,to=100,width=5,textvariable=self.block_limit).pack(side='left',padx=6)
        ttk.Button(row,text='Start CPU mining…',command=self.start_mining).pack(side='left',padx=4)
        ttk.Button(row,text='Stop mining',command=lambda:self.action('mine_stop',{},self.show_product)).pack(side='left',padx=4)
        ttk.Label(home,text='Solo rewards are variable; no guaranteed earnings. Coinbase rewards mature after 60 blocks.\nLight and balanced insert pauses; no fixed CPU percentage is promised. Maximum uses one worker continuously.\nAn empty peer list means no external synchronization. Global freshness remains UNKNOWN.',wraplength=850).pack(anchor='w',pady=8)
        self.product_output=self.text(home);self.product_output.pack(fill='both',expand=True)
        page=ttk.Frame(self.tabs,padding=16);self.tabs.add(page,text='Explorer / rankings')
        row=ttk.Frame(page);row.pack(fill='x');self.day=tk.StringVar(root,value=time.strftime('%Y-%m-%d',time.gmtime()))
        for label,kind in [('Network','network'),('Recent blocks','blocks'),('Cumulative voluntary scores','rankings')]:ttk.Button(row,text=label,command=lambda k=kind:self.action('explore',dict(kind=k,day=None),lambda v:self.put(self.explorer,json.dumps(v,indent=2)))).pack(side='left',padx=4)
        ttk.Entry(row,textvariable=self.day,width=12).pack(side='left');ttk.Button(row,text='UTC day',command=lambda:self.action('explore',dict(kind='rankings',day=self.day.get()),lambda v:self.put(self.explorer,json.dumps(v,indent=2)))).pack(side='left')
        ttk.Label(page,text='Only participating output controllers are ranked, not every miner or unique people.\nLocal index is non-authoritative. Scores may be provisional; see confirmation policy and privacy disclosure.',wraplength=850).pack(anchor='w',pady=8)
        self.explorer=self.text(page);self.explorer.pack(fill='both',expand=True)
        self.recovery_page();self.storage_page()
        page=ttk.Frame(self.tabs,padding=16);self.tabs.add(page,text='Help / privacy');helptext=self.text(page);helptext.pack(fill='both',expand=True)
        self.put(helptext,(ROOT/'docs/network-v1/PRODUCT_GUIDE.md').read_text(encoding='utf-8'))
        # All tabs remain reachable on narrow displays, even when Tk clips the
        # long notebook strip. Keyboard traversal and readonly navigation agree.
        nav=ttk.Frame(self.tabs.master);nav.pack(fill='x',before=self.tabs,pady=4)
        ttk.Label(nav,text='Go to:').pack(side='left');self.navigation=tk.StringVar(root,value=self.tabs.tab(self.tabs.select(),'text'))
        picker=ttk.Combobox(nav,textvariable=self.navigation,state='readonly',values=[self.tabs.tab(t,'text') for t in self.tabs.tabs()],width=35);picker.pack(side='left',padx=8)
        picker.bind('<<ComboboxSelected>>',lambda _:self.tabs.select(picker.current()));self.tabs.enable_traversal()
        self.tabs.bind('<<NotebookTabChanged>>',lambda _:self.navigation.set(self.tabs.tab(self.tabs.select(),'text')))
        self.product_timer=root.after(1500,self.auto_status)

    def hello(self,result):
        super().hello(result)
        if not result['wallets'] and not getattr(self,'welcome_shown',False):
            self.welcome_shown=True
            if self.root.state()!='withdrawn':
                from .onboarding import Guide
                self.guide=Guide(self)

    def action(self,cmd,fields,callback):self.run(cmd,fields,callback)
    def refresh(self):
        # Opening a wallet may finish before full native history validation.
        # Never turn this expected loading state into a balance/error dialog.
        if not getattr(self,'node_ready',False):
            self.invalidate();self.status.set('Starting or validating the local chain; balances unavailable.');return
        super().refresh()
    def show_product(self,value):
        self.product_state=value
        self.put(self.product_output,json.dumps(value,indent=2))
        node=value.get('node')
        if node:
            was_ready=getattr(self,'node_ready',False)
            self.node_ready=node.get('state')=='LOCAL_VALIDATING_NODE'
            if self.node_ready and not was_ready and self.opened:
                self.root.after(0,self.refresh)
            tor=value.get('tor',{});mining=value.get('mining',{})
            connection={'DISABLED':'Tor is off','BOOTSTRAPPING':'Starting Tor','DISCONNECTED':'Tor disconnected; reconnect required','CONTROL_UNAVAILABLE':'Tor status unavailable; check runtime','TOR_READY':'Tor ready; peer synchronization unverified'}.get(tor.get('state'),'Network status unavailable')
            if tor.get('recent_authenticated_peers',0)>0:connection='Authenticated peers connected; global freshness remains unknown'
            connection=value.get('network_identity','Development network')+' | '+connection
            self.connection_summary.set(connection+' · '+str(tor.get('bootstrap_percent',0))+'% bootstrap\n'+
                ('Local validated height '+str(node.get('height'))+' · difficulty '+str(node.get('difficulty','unknown')) if node.get('state')=='LOCAL_VALIDATING_NODE' else 'Starting or validating chain; balances unavailable' if node.get('state')=='STARTING_OR_UNAVAILABLE' else 'Local node is stopped')+
                '\nMining: '+str(mining.get('state','OFF'))+' · observed worker hashes/s: '+str(mining.get('observed_hashrate') or 'not measured'))
            if value.get('tor_runtime_warning'):self.connection_summary.set(self.connection_summary.get()+'\n'+value['tor_runtime_warning'])
        if node and (node.get('state')!='LOCAL_VALIDATING_NODE' or self.snapshot and node.get('tip')!=self.snapshot.get('node',{}).get('tip')):self.invalidate()
    def auto_status(self):
        if self.closed:return
        if not self.busy and not self.modal:self.action('product_status',{},self.show_product)
        self.product_timer=self.root.after(5000,self.auto_status)
    def configure_tor(self):
        location='Absolute Windows path to your reviewed Tor binary.' if getattr(self.bridge,'native_windows',False) else 'Absolute Linux path to your reviewed Tor binary (WSL path on Windows).'
        value=simpledialog.askstring('Tor executable',location+'\nNo downloads or system changes will be performed.',parent=self.root)
        if value:self.action('tor_configure',dict(binary=value),self.show_product)
    def provision_tor(self):
        if getattr(self.bridge,'native_windows',False):
            self.validation('This preview bundles its reviewed Tor runtime. Automatic Ubuntu-package provisioning is unavailable on native Windows. Use Configure Tor only for a separately verified compatible runtime.');return
        if messagebox.askyesno('Download verified Tor runtime','Download Tor from the official Tor Project archive over HTTPS?\nThe publisher key, signed metadata and package hashes are checked.\nUbuntu 24.04 amd64 (including WSL2) is currently supported.\nNo wallet data is sent. No system packages or services are changed.\nTor networking and mining remain OFF. A failed download may be retried.',parent=self.root):
            self.action('tor_provision',dict(consent='DOWNLOAD VERIFIED TOR'),self.show_product)
    def add_peer(self):
        value=simpledialog.askstring('Add public network peer','Paste a public pcnode:// link from an independent operator.\nNo ticket, account or individual approval is required.\nPeer hints never authorize blockchain state.',parent=self.root)
        if value:
            self.action('peer_link_add',dict(link=value.strip()),self.show_product)
    def copy_peer_link(self):
        from .peer_uri import format_link
        def copied(value):
            link=format_link(value);self.root.clipboard_clear();self.root.clipboard_append(link)
            self.status.set('Public node link copied. It contains a node identity, not a wallet or admission secret.')
        self.action('tor_descriptor',{},copied)
    def configure_upstream(self):
        host=simpledialog.askstring('Optional upstream SOCKS5 proxy','Numeric local/private proxy IP, as reachable from this backend.\nBlank removes the explicit upstream requirement. Disconnect Tor before changing it.\nEach machine must verify its own endpoint.',parent=self.root)
        if host is None:return
        if not host.strip():self.action('upstream_configure',dict(route=None),self.show_product);return
        port=simpledialog.askinteger('Upstream SOCKS5 port','Local proxy port; no authentication is supported.',minvalue=1024,maxvalue=65535,parent=self.root)
        if port:self.action('upstream_configure',dict(route=dict(host=host.strip(),port=port)),self.show_product)
    def start_tor(self):
        consent=messagebox.askyesno('Connect through Tor','Allow the application to start its own Tor session?\nTor contacts relay/bootstrap infrastructure. PC traffic remains Onion-only.\nA reviewed runtime and peer catalog must already be configured. Mining stays OFF.',parent=self.root)
        if consent:self.action('tor_start',dict(consent='CONNECT VIA TOR'),self.show_product)
    def start_mining(self):
        if not self.opened:self.validation('Open your full wallet first.');return
        try:blocks=int(self.block_limit.get())
        except ValueError:self.validation('Use an integer block limit.');return
        if not messagebox.askokcancel('Explicit CPU mining','Use one CPU worker now, up to '+str(blocks)+' blocks?\nTESTNET ONLY. Without independently checked peers you may mine an isolated fork.\nYou can stop it; startup never resumes mining.',parent=self.root):return
        password=simpledialog.askstring('Unlock mining reward wallet','Wallet password (private pipe only):',show='●',parent=self.root)
        if password:self.action('mine_start',dict(blocks=blocks,consent='START CPU MINING',password=password,cpu_preset=self.cpu_preset.get()),self.show_product)

    def prediction_page(self):
        page=ttk.Frame(self.tabs,padding=16);self.tabs.add(page,text='Prediction · optional')
        ttk.Label(page,text='SIMULATION ONLY · local credits are NOT PC · disabled by default',font=('Segoe UI',12,'bold')).pack(anchor='w')
        ttk.Label(page,text='This local operator can see choices and amounts and decides outcomes. No decentralized oracle.\nPooled integer settlement, no fixed return; no winning participants means refund. No live-value wagering.',wraplength=850).pack(anchor='w',pady=8)
        row=ttk.Frame(page);row.pack(fill='x')
        ttk.Button(row,text='Enable simulation',command=lambda:self.action('prediction_enable',dict(consent='ENABLE SIMULATION ONLY'),self.show_prediction)).pack(side='left')
        ttk.Button(row,text='Disable',command=lambda:self.action('prediction_disable',{},self.show_prediction)).pack(side='left',padx=4)
        ttk.Button(row,text='Refresh',command=lambda:self.action('prediction_view',{},self.show_prediction)).pack(side='left',padx=4)
        ttk.Button(row,text='Create event…',command=self.create_event).pack(side='left',padx=4)
        self.events=ttk.Treeview(page,columns=('question','state','outcome'),show='headings',height=5)
        for col in ('question','state','outcome'):self.events.heading(col,text=col);self.events.column(col,width=280 if col=='question' else 200)
        self.events.pack(fill='x',pady=8)
        row=ttk.Frame(page);row.pack(fill='x');self.credit_amount=tk.StringVar(self.root,value='100');ttk.Label(row,text='Stake credits (integer):').pack(side='left');ttk.Entry(row,textvariable=self.credit_amount,width=10).pack(side='left')
        for side in ('YES','NO'):ttk.Button(row,text='Participate '+side,command=lambda s=side:self.bet(s)).pack(side='left',padx=4)
        for label,action in [('Close','CLOSE'),('Propose result','PROPOSE'),('Dispute','DISPUTE'),('Finalize','FINALIZE'),('Void / refund','VOID')]:ttk.Button(row,text=label,command=lambda a=action:self.adjudicate(a)).pack(side='left',padx=2)
        self.prediction_output=self.text(page);self.prediction_output.pack(fill='both',expand=True)
    def show_prediction(self,value):
        self.put(self.prediction_output,json.dumps(value,indent=2));self.events.delete(*self.events.get_children())
        for e in value.get('events',[]):self.events.insert('', 'end',iid=e['id'],values=(e['question'],e['state'],e['outcome'] or ''))
    def chosen_event(self):
        chosen=self.events.selection()
        if not chosen:self.validation('Select an event first.');return None
        return chosen[0]
    def create_event(self):
        values={}
        for k,prompt in [('question','Binary YES/NO question'),('criteria','Exact outcome criteria; terms freeze immediately'),('source','Evidence source'),('authority','Disclosed local adjudication authority')]:
            v=simpledialog.askstring('Create simulated event',prompt,parent=self.root)
            if not v:return
            values[k]=v
        minutes=simpledialog.askinteger('Participation deadline','Minutes until participation closes (1–43200):',minvalue=1,maxvalue=43200,parent=self.root)
        if minutes is None:return
        now=int(time.time());values.update(close=now+minutes*60,resolve=now+minutes*60+86400,cancellation='Operator may VOID with recorded reason; all stakes refunded.')
        self.action('prediction_create',values,lambda _:self.action('prediction_view',{},self.show_prediction))
    def bet(self,side):
        event=self.chosen_event()
        if not event:return
        try:amount=int(self.credit_amount.get())
        except ValueError:self.validation('Use integer simulation credits.');return
        self.action('prediction_bet',dict(event=event,side=side,amount=amount,key=secrets.token_hex(16)),lambda _:self.action('prediction_view',{},self.show_prediction))
    def adjudicate(self,action):
        event=self.chosen_event()
        if not event:return
        outcome=None;evidence=None;consent=None
        if action in ('PROPOSE','FINALIZE'):
            outcome=simpledialog.askstring('Authenticated local operator','Outcome YES or NO (not an oracle):',parent=self.root)
            if outcome not in ('YES','NO'):return
        if action in ('PROPOSE','VOID','DISPUTE'):
            evidence=simpledialog.askstring('Record decision','Evidence or reason (durable private audit):',parent=self.root)
            if not evidence:return
        if action in ('FINALIZE','VOID'):
            if not messagebox.askokcancel('Simulation settlement','Confirm this immutable simulated settlement?',parent=self.root):return
            consent='CONFIRM SIMULATION SETTLEMENT'
        self.action('prediction_adjudicate',dict(event=event,action=action,outcome=outcome,evidence=evidence,consent=consent),lambda _:self.action('prediction_view',{},self.show_prediction))

    def storage_page(self):
        page=ttk.Frame(self.tabs,padding=16);self.tabs.add(page,text='Privacy Storage · optional')
        ttk.Label(page,text='Optional online Provider · encrypted files · bounded retention · disabled by default',font=('Segoe UI',12,'bold')).pack(anchor='w')
        ttk.Label(page,text='Import only a NEW V1 private profile through a private authenticated channel. Never use historical N2 orders.\nThe Provider sees payment/order timing, quota and ciphertext; recovery credentials decrypt the file.\nUnknown payment results require reconciliation. Expiry never authorizes repayment.',wraplength=850).pack(anchor='w',pady=8)
        self.storage_key=tk.StringVar(self.root,value='');self.storage_source=tk.StringVar(self.root,value='')
        for label,var in [('Order idempotency key (keep it unchanged)',self.storage_key),('Private Linux source/bundle path',self.storage_source)]:ttk.Label(page,text=label).pack(anchor='w');ttk.Entry(page,textvariable=var).pack(fill='x')
        row=ttk.Frame(page);row.pack(fill='x',pady=8)
        ttk.Button(page,text='Detach service; keep private recovery data',command=lambda:self.action('storage_detach',{},self.storage_result)).pack(anchor='w')
        for label,fn in [('Attach private profile',self.storage_attach),('Request quote',self.storage_request),('Authorize once',self.storage_pay),('Reconcile',lambda:self.storage_call('storage_observe')),('Upload original file',lambda:self.storage_call('storage_upload',source=self.storage_source.get())),('Export recovery',self.storage_export),('Recover to new file',self.storage_restore)]:ttk.Button(row,text=label,command=fn).pack(side='left',padx=2)
        self.storage_output=self.text(page);self.storage_output.pack(fill='both',expand=True);self.storage_review=None
    def storage_result(self,v):self.put(self.storage_output,json.dumps(v,indent=2))
    def storage_call(self,cmd,**fields):self.action(cmd,dict(key=self.storage_key.get(),**fields),self.storage_result)
    def storage_attach(self):
        p=simpledialog.askstring('Private profile','Absolute Linux path to private V1 profile (0600); no capability in this dialog:',parent=self.root)
        if p:self.action('storage_attach',dict(profile=p),self.storage_result)
    def storage_request(self):
        size=simpledialog.askinteger('Quote size','Exact plaintext byte count (1–1048576):',minvalue=1,maxvalue=1048576,parent=self.root)
        if size is not None:
            def reviewed(v):self.storage_review=(self.storage_key.get(),v);self.storage_result(v)
            self.action('storage_request',dict(key=self.storage_key.get(),bytes=size),reviewed)
    def storage_pay(self):
        if not self.storage_review or self.storage_review[0]!=self.storage_key.get():self.validation('Request and inspect this quote first.');return
        v=self.storage_review[1]
        consent=simpledialog.askstring('Authorize real TESTNET PC once',json.dumps(v['review'],indent=2)+'\nFee 188000 atomic; maximum 500000. Type CONFIRM.\nSubmission is not settlement. Unknown means reconcile, never repay.',parent=self.root)
        if consent=='CONFIRM':self.storage_call('storage_pay',consent=consent)
    def storage_export(self):
        dest=simpledialog.askstring('New encrypted recovery bundle','NEW private Linux destination:',parent=self.root);password=simpledialog.askstring('Encrypt recovery bundle','Recovery password; keep separate from bundle:',show='●',parent=self.root) if dest else None
        if password:self.storage_call('storage_export',destination=dest,password=password)
    def storage_restore(self):
        dest=simpledialog.askstring('Recover plaintext','NEW private Linux destination (no overwrite):',parent=self.root);password=simpledialog.askstring('Unlock recovery bundle','Recovery password:',show='●',parent=self.root) if dest else None
        if password:self.action('storage_restore',dict(source=self.storage_source.get(),destination=dest,password=password),self.storage_result)
    def import_bootstrap(self):
        path=simpledialog.askstring('Reviewed public bootstrap catalogs','Private Linux path of reviewed catalog JSON (0600); stop own services first:',parent=self.root)
        if path:self.action('bootstrap_import',dict(path=path),self.show_product)

    def recovery_page(self):
        page=ttk.Frame(self.tabs,padding=16);self.tabs.add(page,text='Wallet recovery')
        ttk.Label(page,text='Keep an encrypted backup outside this computer',font=('Segoe UI',14,'bold')).pack(anchor='w')
        ttk.Label(page,text='Portable recovery includes your wallet, payment journal and saved chain observation.\nKeep the encrypted file AND its adjacent .journal-archive folder together when present.\nKeep the password separately. Import creates a NEW alias of the SAME funds.\nNever spend independently from two copies or repay an unknown transaction.\nChoose an existing private folder. A local export alone is not an off-device backup.',wraplength=820).pack(anchor='w',pady=12)
        ttk.Button(page,text='Export encrypted wallet recovery…',command=self.export_recovery).pack(anchor='w',pady=6)
        ttk.Button(page,text='Import encrypted recovery…',command=self.import_recovery).pack(anchor='w',pady=6)
        ttk.Button(page,text='Use data from a previous compatible installation…',command=self.upgrade_data).pack(anchor='w',pady=6)
        self.recovery_output=self.text(page);self.recovery_output.pack(fill='both',expand=True,pady=8)

    def recovery_file(self,save=False):
        if os.name=='nt' and not getattr(self.bridge,'native_windows',False):
            return simpledialog.askstring('Private WSL2 file','Absolute Linux path in an existing private folder.\nWindows filesystem transfer is not supported by this WSL2 package.',parent=self.root)
        from tkinter import filedialog
        if save:return filedialog.asksaveasfilename(parent=self.root,title='NEW encrypted recovery file in a private folder',defaultextension='.pc-recovery',confirmoverwrite=True)
        return filedialog.askopenfilename(parent=self.root,title='Encrypted recovery file in a private folder')

    def export_recovery(self):
        if not self.opened:self.validation('Open your wallet first.');return
        if self.busy:return
        destination=self.recovery_file(save=True)
        if destination:self.action('wallet_export',dict(destination=destination),lambda v:self.put(self.recovery_output,'Encrypted recovery exported and decoded successfully.\nNo existing file was overwritten.\n'+v['warning']))

    def import_recovery(self,callback=None):
        if self.busy:return
        source=self.recovery_file()
        if not source:return
        name=simpledialog.askstring('New wallet alias','NEW wallet name (letters, digits, _ or -):',parent=self.root)
        if not name:return
        password=simpledialog.askstring('Unlock encrypted recovery','Backup password (private pipe only):',show='●',parent=self.root)
        if not password:return
        if not messagebox.askokcancel('Same funds; preserve unknown payments','Only import your own portable recovery for this TESTNET.\nThis creates another alias of the same funds. Do not spend from two copies.\nUnknown submissions remain blocked until reconciliation.',parent=self.root):return
        self.begin_unlock()
        self.action('wallet_import',dict(source=source,name=name,password=password,format='portable',consent='IMPORT SAME TESTNET WALLET'),callback or self.unlocked)

    def upgrade_data(self):
        if self.busy:return
        platform='Windows' if getattr(self.bridge,'native_windows',False) else 'Linux'
        previous=simpledialog.askstring('Previous installation','Absolute '+platform+' path of the previous verified installation. Close its application first.',parent=self.root)
        if not previous:return
        data=simpledialog.askstring('Previous application data','Absolute private '+platform+' application data directory. Never use N2 data.',parent=self.root)
        if not data:return
        def checked(value):
            if not value.get('compatible'):return
            if not messagebox.askokcancel('Compatible update; preserve originals',value['warning']+'\nClose this session and open that data with mining and Tor OFF?',parent=self.root):return
            old=self.bridge
            # Close only the currently owned backend, then acquire the old data's
            # real OS lock in a new backend. A competing session still fails closed.
            old.close();self.begin_unlock()
            self.bridge=ProductBridge(old.backend_root,value['data'],value['rpc'],value['p2p'])
            self.node_ready=False;self.known_wallets=[];self.known_backups=[]
            self.action('hello',{},self.hello)
        self.action('upgrade_check',dict(old_root=previous,data=data),checked)

    def shutdown(self):
        if self.product_timer:self.root.after_cancel(self.product_timer)
        super().shutdown()


def main():
    p=argparse.ArgumentParser();p.add_argument('--backend-root');p.add_argument('--home');p.add_argument('--port',type=int,default=29881);p.add_argument('--p2p',type=int,default=29882);a=p.parse_args()
    root=safe_root()
    if os.name=='nt' and not a.backend_root:
        a.backend_root=simpledialog.askstring('Installed WSL2 backend','Absolute Linux directory of your verified testnet candidate installation:',parent=root)
        if not a.backend_root:root.destroy();return
    Desktop(root,ProductBridge(a.backend_root,a.home,a.port,a.p2p));root.mainloop()


if __name__=='__main__':main()
