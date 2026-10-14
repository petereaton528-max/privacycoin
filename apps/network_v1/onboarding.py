"""Small Tk guide; wallet authority stays in the existing private-pipe backend."""
import tkinter as tk
from tkinter import ttk,messagebox
import re

# User-facing copy is separate from flow logic to permit translation.
STRINGS={
 'en':dict(title='Welcome to Privacy Coin',warning='Experimental TESTNET. PC here has no monetary value.',
           create='Create wallet',open='Open existing wallet',backup='Create and verify encrypted backup',
            acknowledge='I will keep the encrypted backup AND its companion folder together, with the password separate, outside this computer.',
           next='Continue to network',password='Password (at least 12 characters)',repeat='Repeat password'),
 'zh':dict(title='欢迎使用 Privacy Coin',warning='实验测试网；此处的 PC 不具有货币价值。',
           create='创建钱包',open='打开已有钱包',backup='创建并验证加密备份',
           acknowledge='我会在本电脑以外分别保存加密备份和密码。',next='继续设置网络',password='密码（至少 12 个字符）',repeat='再次输入密码')}


class Guide:
    def __init__(self,app):
        self.app=app;self.verified=False;self.window=tk.Toplevel(app.root)
        self.window.title(STRINGS['en']['title']);self.window.transient(app.root)
        self.frame=ttk.Frame(self.window,padding=20);self.frame.pack(fill='both',expand=True)
        self.step=tk.StringVar(value='1 / 3  Wallet');self.name=tk.StringVar(value='MyWallet')
        self.password=tk.StringVar();self.repeat=tk.StringVar();self.ack=tk.BooleanVar()
        self.message=tk.StringVar(value=STRINGS['en']['warning'])
        ttk.Label(self.frame,textvariable=self.step,font=('Segoe UI',16,'bold')).pack(anchor='w')
        ttk.Label(self.frame,textvariable=self.message,wraplength=520).pack(anchor='w',pady=10)
        for label,var,secret in [('Wallet name',self.name,False),(STRINGS['en']['password'],self.password,True),(STRINGS['en']['repeat'],self.repeat,True)]:
            ttk.Label(self.frame,text=label).pack(anchor='w');ttk.Entry(self.frame,textvariable=var,show='●' if secret else '',width=45).pack(fill='x',pady=3)
        buttons=ttk.Frame(self.frame);buttons.pack(fill='x',pady=10)
        self.create_button=ttk.Button(buttons,text=STRINGS['en']['create'],command=lambda:self.unlock('create'));self.create_button.pack(side='left')
        self.open_button=ttk.Button(buttons,text=STRINGS['en']['open'],command=lambda:self.unlock('open'));self.open_button.pack(side='left',padx=8)
        ttk.Button(buttons,text='Import encrypted recovery…',command=lambda:app.import_recovery(self.imported)).pack(side='left')
        ttk.Label(self.frame,text='Import an encrypted recovery bundle using Your wallet → Restore.\nA restored alias controls the same funds; never repay an unknown transaction.',wraplength=520).pack(anchor='w')
        self.backup_button=ttk.Button(self.frame,text=STRINGS['en']['backup'],command=self.backup,state='disabled');self.backup_button.pack(fill='x',pady=10)
        ttk.Checkbutton(self.frame,text=STRINGS['en']['acknowledge'],variable=self.ack,command=self.acknowledge).pack(anchor='w')
        self.next_button=ttk.Button(self.frame,text=STRINGS['en']['next'],command=self.network,state='disabled');self.next_button.pack(fill='x',pady=10)
        self.window.protocol('WM_DELETE_WINDOW',self.close);self.window.bind('<Escape>',lambda _:self.close())

    def unlock(self,command):
        if self.app.busy:return
        name=self.name.get();password=self.password.get()
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,40}',name) or not 12<=len(password)<=1024:
            self.message.set('Use a short wallet name and a password of at least 12 characters.');return
        if command=='create' and password!=self.repeat.get():self.message.set('The two passwords do not match.');return
        self.password.set('');self.repeat.set('');self.app.begin_unlock()
        def opened(value):
            self.app.unlocked(value)
            if self.window.winfo_exists():
                self.step.set('2 / 3  Secure recovery');self.message.set('Wallet opened. Create a new encrypted backup and verify it before continuing.');self.backup_button.state(['!disabled'])
        self.app.action(command,dict(name=name,password=password),opened)

    def backup(self):
        if self.app.busy or not self.app.opened:return
        self.verified=False;self.ack.set(False);self.acknowledge()
        from tkinter import simpledialog
        name=simpledialog.askstring('New backup name','A NEW name for this encrypted recovery bundle:',initialvalue=self.app.vars['name'].get()+'-recovery',parent=self.window)
        if name is None:return
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,40}',name):self.message.set('Use 1–40 letters, digits, _ or -.');return
        def saved(value):
            path=value['backup']
            def verified(result):
                if not result.get('verified'):return
                self.verified=True;self.message.set('Restore check passed. Encrypted file:\n'+path+'\nKeep this file AND its adjacent .journal-archive folder when present.\nThis same-computer copy is NOT an off-device backup. Copy the complete set securely; keep the password separately.');self.acknowledge()
            self.app.action('verify_backup',dict(name=name),verified)
        self.app.action('backup',dict(name=name),saved)

    def imported(self,value):
        self.app.unlocked(value)
        self.step.set('2 / 3  Secure recovery');self.message.set('Wallet imported with its payment journal. Create and verify a new backup before continuing.');self.backup_button.state(['!disabled'])

    def acknowledge(self):self.next_button.state(['!disabled'] if self.verified and self.ack.get() else ['disabled'])

    def network(self):
        if not self.verified or not self.ack.get():return
        self.step.set('3 / 3  Connect through Tor')
        self.message.set('Checking local node and network configuration. Mining remains OFF.')
        def checked(status):
            self.app.show_product(status)
            if not self.window.winfo_exists():return
            guidance=('Reviewed peer hints are configured. Use Connect via Tor on the Start page; peer authentication and synchronization must still succeed.' if status.get('configured_peers') else 'No operational peer catalog is configured: external synchronization is not yet available. Import reviewed public catalogs from independent operators; no personal node approval is required.')
            runtime='A Tor runtime is configured.' if status.get('tor_runtime_configured') else 'Configure a reviewed Tor runtime before connecting.'
            node='Your local validating node is ready.' if status.get('node',{}).get('state')=='LOCAL_VALIDATING_NODE' else 'Local chain validation is not ready. Spending remains unavailable.'
            mining={'DISABLED':'Mining is OFF.','STOPPED':'Mining is stopped.','RUNNING':'Mining is running because you started it; use Stop mining on the Start page.'}.get(status.get('mining',{}).get('state'),'Check mining status on the Start page.')
            self.message.set(node+' '+mining+'\n'+runtime+'\n'+guidance+'\nGlobal freshness remains unknown. You can explore the wallet and local network now.')
        self.app.action('product_status',{},checked)
        self.next_button.configure(text='Explore application',command=self.close)

    def close(self):
        self.password.set('');self.repeat.set('');self.window.destroy()
