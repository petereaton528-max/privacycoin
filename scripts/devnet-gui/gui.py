"""Disposable-devnet Tk client. No wallet business logic or cryptography here."""
import argparse, ctypes, json, os, queue, re, threading, time, tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from bridge import Bridge
from amounts import parse, display, format_pc, MAX_ATOMIC, ATOMIC_PER_PC

class App:
    def __init__(self,root,bridge):
        self.root=root;self.bridge=bridge;self.jobs=queue.Queue();self.busy=False;self.opened=False;self.closed=False
        self.modal=False;self.generation=0;self.sequence=0;self.callbacks={}
        root.report_callback_exception=self.callback_failed
        self.last=None;self.last_error=None;self.started=time.perf_counter();self.ready_ms=None
        from layout import build
        build(self)
        self.known_wallets=[];self.known_backups=[];self.snapshot=None;self.unit='PC'
        root.protocol('WM_DELETE_WINDOW',self.shutdown);self.poll_id=root.after(40,self.poll)
        self.run('hello',{},self.hello)
    @staticmethod
    def text(parent):
        widget=tk.Text(parent,wrap='word',background='#17273b',foreground='#e6edf5',insertbackground='white',relief='flat',padx=12,pady=12,state='disabled',font=('Consolas',10))
        scrollbar=ttk.Scrollbar(parent,orient='vertical',command=widget.yview);scrollbar.pack(side='right',fill='y')
        widget.configure(yscrollcommand=scrollbar.set);return widget
    def entry(self,parent,label,key,row,col,width,secret=False):
        ttk.Label(parent,text=label).grid(row=row,column=col,columnspan=2,sticky='w',padx=(0,8))
        ttk.Entry(parent,textvariable=self.vars[key],width=width,show='●' if secret else '').grid(row=row+1,column=col,columnspan=2,sticky='we',padx=(0,8),pady=(3,8))
    @staticmethod
    def put(widget,text):widget.configure(state='normal');widget.delete('1.0','end');widget.insert('end',text);widget.configure(state='disabled')
    def run(self,command,fields,callback):
        if self.busy or self.modal or self.closed:return
        self.busy=True;self.status.set('Working: '+command+'…');self.last_error=None
        self.send_button.state(['disabled'])
        self.sequence+=1;ticket=self.sequence
        self.callbacks[ticket]=(callback,self.generation,command)
        # Workers must not retain Tk/App objects or bound UI callbacks.
        bridge=self.bridge;jobs=self.jobs
        def work():
            try:jobs.put((True,bridge.call(command,**fields),ticket))
            except Exception:
                hints=dict(open='Open failed. Check the wallet name, password and original private files. Wrong password, damage or permissions cannot be distinguished safely.',create='Create failed. Check name availability and private storage permissions. No existing wallet is overwritten.',restore='Restore/open failed. Check the backup password, source, NEW destination and private files. An interrupted restore may leave sidecars; preserve originals and investigate before retrying.',backup='Backup failed. Check the new backup name and private storage permissions. Preserve the original wallet.',refresh='Full scan failed. The local node may be offline, stale or inconsistent. Balances are UNKNOWN; a restored file may still exist. Reconnect and refresh.',confirm='Submission result UNKNOWN. Preserve original wallet/journal and reconcile. Do not blindly resend or restore stale state.')
                hints['history_page']=hints['refresh']
                jobs.put((False,hints.get(command,'Backend operation failed or was rejected. No verified result; uncertain submission requires reconciliation.'),ticket))
        threading.Thread(target=work,daemon=True).start()
    def poll(self):
        try:
            ok,result,ticket=self.jobs.get_nowait();self.busy=False
            callback,generation,command=self.callbacks.pop(ticket)
            if generation!=self.generation:
                self.last_error='Stale response discarded; reopen and refresh the intended wallet.';self.status.set(self.last_error);self.invalidate()
            elif ok:self.last=result;self.status.set('Completed: '+command);callback(result)
            else:
                self.last_error=result;self.status.set(result);self.invalidate()
                messagebox.showerror('Operation rejected — no verified result',result,parent=self.root)
        except queue.Empty:pass
        except Exception:self.callback_failed()
        finally:
            if not self.busy and not self.closed and self.snapshot:
                self.send_button.state(['!disabled'] if self.opened and self.snapshot['balance']['signing_available'] and not self.snapshot['unknown_attempts'] else ['disabled'])
            if not self.closed:self.poll_id=self.root.after(40,self.poll)
    def invalidate(self):
        self.snapshot=None
        self.history_newer.state(['disabled']);self.history_older.state(['disabled']);self.history_position.set('Refresh to view owned outputs')
        for value in self.summary.values():value.set('UNKNOWN / unavailable')
        self.qualification.set('No current spendable-state assurance. Open / refresh a consistent local node.')
        self.history_table.delete(*self.history_table.get_children())
        self.put(self.overview,'UNVERIFIED / UNKNOWN\nRefresh against a consistent local validating node before relying on balances.\nNo global freshness guarantee.');self.put(self.history,'No current verified history. Refresh required.');self.send_button.state(['disabled'])
    def callback_failed(self,*_):
        # Tk's default traceback prints exception values. Never log them.
        self.begin_unlock();self.vars['password'].set('');self.vars['restore_password'].set('');self.last_error='Interface operation failed. No verified result; close and reopen the wallet.'
        self.status.set(self.last_error);self.invalidate()
        messagebox.showerror('Interface operation failed',self.last_error,parent=self.root)
    def hello(self,result):
        self.ready_ms=(time.perf_counter()-self.started)*1000
        self.known_wallets=result['wallets'];self.known_backups=result.get('backups',[])
        self.wallet_picker.configure(values=self.known_wallets);self.backup_picker.configure(values=self.known_backups)
        self.status.set('Ready. Choose a wallet and enter its password, or create a new wallet.')
        self.network_status.set('Private WSL store: '+result['home']+'\nGlobal freshness UNKNOWN; no independent network verification.')
        self.invalidate()
        if self.opened:self.refresh()
    def unlocked(self,result):
        if result.get('authority') not in ('full','view') or not isinstance(result.get('address'),str) or not re.fullmatch(r'PCdv1-[0-9a-f]{148}',result['address']):raise ValueError('Invalid wallet response')
        self.opened=True;self.address.set(result['address'])
        name=result.get('path','').rsplit('/',1)[-1].removesuffix('.wallet') or self.vars['name'].get()
        self.vars['name'].set(name);self.active_wallet.set('Open wallet: '+name+' · '+('Spend authority' if result['authority']=='full' else 'Incoming view only — cannot spend'))
        if name and name not in self.known_wallets:self.known_wallets.append(name);self.wallet_picker.configure(values=sorted(self.known_wallets))
        self.vars['backup'].set(name+'-recovery');self.invalidate();self.refresh()
    def validation(self,text):
        self.last_error=text;self.status.set(text);messagebox.showerror('Check your entry',text,parent=self.root)
    def valid_name(self,key):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,40}',self.vars[key].get()):
            self.validation('Use 1–40 letters, digits, underscores or hyphens for the wallet / backup name.');return False
        return True
    def valid_password(self,key='password'):
        value=self.vars[key].get()
        if not 12<=len(value)<=1024:
            self.vars[key].set('');self.validation('Enter the '+('backup encryption ' if key=='restore_password' else 'wallet ')+'password (12–1024 characters). Nothing was opened or submitted.');return False
        return True
    def credentials(self):
        fields=dict(name=self.vars['name'].get(),password=self.vars['password'].get());self.vars['password'].set('');return fields
    def create(self):
        if self.busy or self.modal or self.closed:return
        if not self.valid_name('name') or not self.valid_password():return
        if self.vars['name'].get() in self.known_wallets:self.validation('That wallet name already exists. Use Open, or choose a new name.');return
        fields=self.credentials()
        self.modal=True
        try:again=simpledialog.askstring('Create DEVNET wallet','Re-enter your password. Keep it separate from the encrypted backup.\nLost backup/password cannot be recovered by us.',show='●',parent=self.root)
        finally:self.modal=False
        if self.closed:return
        if again is None:self.status.set('Wallet creation cancelled. No new wallet was created.');return
        if again!=fields['password']:
            messagebox.showerror('Password mismatch','Wallet creation cancelled.',parent=self.root);return
        self.begin_unlock();self.run('create',fields,self.unlocked)
    def open(self):
        if self.busy or self.modal or self.closed:return
        if not self.valid_name('name') or not self.valid_password():return
        self.begin_unlock();self.run('open',self.credentials(),self.unlocked)
    def begin_unlock(self):
        self.generation+=1
        self.opened=False;self.active_wallet.set('No verified wallet identity — awaiting successful open.')
        self.address.set('Wallet locked — awaiting successful open.');self.invalidate()
    def close_wallet(self):
        if self.busy or self.modal or self.closed:return
        self.generation+=1
        self.opened=False;self.active_wallet.set('No wallet open');self.address.set('Wallet locked.');self.invalidate();self.run('close',{},lambda _:None)
    def connect(self):
        if self.busy or self.modal or self.closed:return
        self.generation+=1
        self.invalidate()
        try:port=int(self.vars['port'].get())
        except ValueError:messagebox.showerror('Invalid port','Use a local integer RPC port.',parent=self.root);return
        self.run('connect',dict(port=port),lambda _:self.refresh() if self.opened else None)
    def refresh(self):
        if self.busy or self.modal or self.closed:return
        self.invalidate();self.run('refresh',{},self.observed)
    def page_history(self,direction):
        if self.busy or self.modal or self.closed or not self.opened or not self.snapshot:return
        page=self.snapshot.get('history_page',{})
        offset=page.get('previous_offset' if direction<0 else 'next_offset')
        if offset is None:return
        self.invalidate();self.run('history_page',dict(offset=offset),self.observed)
    def observed(self,result):
        balance=result['balance'];node=result['node']
        unknown=result['unknown_attempts'];authority=balance['authority'];trust=balance['chain_trust']
        if type(unknown) is not int or unknown<0 or authority not in ('full','view') or trust not in ('TRUSTED_LOCAL_VALIDATING_ANCHOR','STALE_OR_ROLLBACK') or type(balance['signing_available']) is not bool:raise ValueError('Invalid balance response')
        for key in ('balance','spendable','sufficiently_confirmed_unspent','locked_coinbase','locked_normal','reserved_inputs','pending_incoming','pending_change'):
            value=balance.get(key)
            if value is not None and (type(value) is not int or value<0):raise ValueError('Invalid amount response')
        restricted=authority=='view' or trust=='STALE_OR_ROLLBACK' or unknown>0
        if restricted and (balance['signing_available'] or balance.get('spendable') is not None):raise ValueError('Inconsistent authority response')
        if not restricted and (balance.get('balance') is None or balance.get('spendable') is None):raise ValueError('Incomplete balance response')
        self.snapshot=result
        page=result.get('history_page')
        if page is not None:
            for key in ('offset','total','limit'):
                if type(page[key]) is not int or page[key]<0:raise ValueError('Invalid history page')
            self.history_position.set('No owned outputs' if not page['total'] else 'Outputs '+str(page['offset']+1)+'–'+str(min(page['total'],page['offset']+page['limit']))+' of '+str(page['total'])+' (newest first)')
            self.history_newer.state(['disabled'] if page['previous_offset'] is None else ['!disabled'])
            self.history_older.state(['disabled'] if page['next_offset'] is None else ['!disabled'])
        for key,value in self.summary.items():value.set(display(balance.get(key)))
        self.qualification.set(('Incoming view only: spent status and available balance are UNKNOWN. ' if authority=='view' else '')+('UNVERIFIED: stale / rollback observation. ' if trust=='STALE_OR_ROLLBACK' else 'Observed by the local validating node. ')+('UNKNOWN submission: signing blocked; preserve original state and reconcile. ' if unknown else '')+str(balance.get('warning','')))
        progress=balance['scan_progress'];self.status.set('Height '+str(node['height'])+' · Full scan '+str(progress['records_processed'])+'/'+str(progress['records_expected'])+' · Global freshness UNKNOWN')
        self.network_status.set(node['endpoint']+' · '+trust+'\nFull scan relative to this anchor, not independent network verification. Global freshness UNKNOWN.')
        def amount(key):
            value=balance.get(key)
            return 'UNKNOWN / unavailable' if value is None else f'{value:,} atomic units'
        lines=['BALANCES RELATIVE TO THE CONFIGURED LOCAL NODE','',
               'Spendable                 '+amount('spendable'),
               'Chain balance             '+amount('balance'),
               'Sufficiently confirmed    '+amount('sufficiently_confirmed_unspent'),
               'Immature coinbase         '+amount('locked_coinbase'),
               'Other locked funds        '+amount('locked_normal'),
               'Inputs reserved by pool   '+amount('reserved_inputs'),
               'Pending incoming          '+amount('pending_incoming'),
               'Pending change            '+amount('pending_change'),'',
               'Authority: '+balance['authority']+' · Spent status: '+balance['spent_status'],
               'Chain trust: '+balance['chain_trust'],
               'Global freshness: UNKNOWN — no independent network verification',
               'Confirmation policy: '+str(balance['minimum_confirmations'])+' blocks; not finality',
               'Unknown submission attempts: '+str(result['unknown_attempts']),'',
               'Node: '+node['endpoint']+' · Height: '+str(node['height'])+' · Work: '+str(node['work']),
               'Tip: '+node['tip'],
               'Full scan: '+str(balance['scan_progress']['records_processed'])+'/'+str(balance['scan_progress']['records_expected'])+' records relative to this anchor.',
               'Network-wide sync/peer independence: UNKNOWN.']
        if balance.get('warning'):lines+=['',balance['warning']]
        self.put(self.overview,'\n'.join(lines))
        lines=['OWNED OUTPUTS (includes change; not a net payment ledger)',
               'Outgoing below includes local approvals only; external outgoing history may be incomplete.',
               'Observation trust: '+balance['chain_trust']+' · Global freshness UNKNOWN',
               'Statuses are relative to the configured node; chain observation is not finality.','']
        for item in reversed(result['history']):lines += [item['status']+' · '+str(item['amount'])+' atomic · '+('coinbase' if item['coinbase'] else 'private output')+(' · spent' if item['spent'] else ''),'  '+item['transaction_id']]
        lines+=['','LOCAL OUTGOING ATTEMPTS']
        for item in reversed(result['outgoing']):lines += [('CHAIN_INCLUDED (local)' if item['status']=='CONFIRMED' else item['status'])+' · '+str(item['amount'])+' atomic · fee '+str(item['fee']), '  '+str(item['transaction_id'] or 'UNKNOWN transaction identity')]
        self.put(self.history,'\n'.join(lines))
        self.history_table.delete(*self.history_table.get_children())
        for item in reversed(result['history']):self.history_table.insert('', 'end', values=('Mining output' if item['coinbase'] else 'Private output',item['status']+(' · spent' if item['spent'] else ''),format_pc(item['amount']),''))
        for item in reversed(result['outgoing']):self.history_table.insert('', 'end', values=('Local outgoing','CHAIN_INCLUDED (local)' if item['status']=='CONFIRMED' else item['status'],format_pc(item['amount']),format_pc(item['fee'])))
        self.send_button.state(['!disabled'] if balance['signing_available'] and not result['unknown_attempts'] else ['disabled'])
    def change_unit(self,*_):
        new=self.vars['unit'].get()
        try:values={key:parse(self.vars[key].get(),self.unit,positive=False) for key in ('amount','fee','max_fee')}
        except ValueError as error:self.vars['unit'].set(self.unit);self.validation(str(error));return
        for key,value in values.items():self.vars[key].set(format_pc(value) if new=='PC' else str(value))
        self.unit=new
    def review(self):
        if self.busy or self.modal or self.closed:return
        try:fields=dict(destination=self.vars['destination'].get(),**{k:parse(self.vars[k].get(),self.vars['unit'].get()) for k in ('amount','fee','max_fee')})
        except ValueError as error:self.validation(str(error));return
        if not re.fullmatch(r'PCdv1-[0-9a-f]{148}',fields['destination']):self.validation('Enter a complete PCdv1 Devnet recipient address.');return
        if fields['fee']>fields['max_fee'] or fields['max_fee']>ATOMIC_PER_PC:self.validation('The fee must not exceed your maximum fee; maximum fee is at most 1 PC.');return
        if fields['amount']+fields['fee']>MAX_ATOMIC:self.validation('Payment plus fee exceeds the atomic-unit limit.');return
        if not self.opened or not self.snapshot or not self.snapshot['balance']['signing_available'] or self.snapshot['unknown_attempts']:
            self.validation('No current spending assurance. Open and refresh the wallet; reconcile UNKNOWN submissions before sending.');return
        if fields['amount']+fields['fee']>=self.snapshot['balance']['spendable']:
            self.validation('Insufficient available funds for this payment, fee and required positive change. Pending / locked funds cannot be spent.');return
        self.run('prepare',fields,self.approve)
    def approve(self,result):
        review=result['review'];amount=review['amount'];fee=review['fee']
        if type(amount) is not int or type(fee) is not int or amount+fee>MAX_ATOMIC:raise ValueError('Invalid review')
        summary='Recipient:\n'+review['destination']+'\n\nPayment: '+display(amount)+'\nFee: '+display(fee)+'\nTotal cost: '+display(amount+fee)+'\nMaximum fee: '+display(review['max_fee'])+'\n\nExact atomic units: payment '+str(amount)+', fee '+str(fee)+', total '+str(amount+fee)+'.\nLocal chain height: '+str(review['height'])+'. Inclusion is not finality.'
        self.modal=True;generation=self.generation
        try:consent=simpledialog.askstring('Review — DEVNET ONLY',summary+'\n\nType CONFIRM within 120 seconds to sign and broadcast.\nCancel sends nothing.',parent=self.root)
        finally:self.modal=False
        if self.closed or generation!=self.generation:return
        if consent=='CONFIRM':self.run('confirm',dict(token=result['token'],consent=consent),lambda _:self.refresh())
        else:self.refresh()
    def backup(self):
        if self.busy or self.modal or self.closed:return
        if not self.opened:self.validation('Open the wallet to back up first.');return
        if not self.valid_name('backup'):return
        name=self.vars['backup'].get()
        if name in self.known_backups:self.validation('That backup name already exists. Choose a new name; backups are never overwritten.');return
        def saved(result):
            self.known_backups.append(name);self.backup_picker.configure(values=sorted(set(self.known_backups)));self.vars['restore_source'].set(name);self.vars['restore_name'].set(self.vars['name'].get()+'-restored')
            messagebox.showinfo('Backup created',result['backup']+'\n'+result['warning']+'\nPreserve the original until recovery is verified.',parent=self.root)
        self.run('backup',dict(name=name),saved)
    def restore(self):
        if self.busy or self.modal or self.closed:return
        if not self.valid_name('restore_source') or not self.valid_name('restore_name') or not self.valid_password('restore_password'):return
        if self.vars['restore_name'].get() in self.known_wallets:self.validation('Destination wallet already exists. Choose a NEW wallet name. Restore never overwrites.');return
        if not self.restore_ack.get():self.validation('A restored alias controls the same funds. Read and acknowledge the alias warning before restoring.');return
        password=self.vars['restore_password'].get();self.vars['restore_password'].set('');self.vars['password'].set('')
        self.begin_unlock()
        self.run('restore',dict(name=self.vars['restore_name'].get(),backup=self.vars['restore_source'].get(),password=password),self.unlocked)
    def copy_address(self):
        if self.opened:self.root.clipboard_clear();self.root.clipboard_append(self.address.get());self.status.set('Complete public address copied. No seed or private key copied.')
    def shutdown(self):
        # EOF closes the backend session; never send an implicit transaction.
        self.closed=True;self.root.after_cancel(self.poll_id)
        self.callbacks.clear();self.root.report_callback_exception=lambda *_:None
        self.vars['password'].set('');self.vars['restore_password'].set('')
        self.bridge.close();self.root.destroy()

def safe_root():
    # Tk() normally executes HOME/cwd .<class>.tcl/.py profile files. Load Tk
    # directly into a Tcl interpreter instead; no profile loading occurs.
    root=tk.Tk(useTk=False);root.loadtk();return root

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--home');parser.add_argument('--port',type=int,default=48081);args=parser.parse_args()
    root=safe_root();bridge=Bridge(args.home,args.port);App(root,bridge);root.mainloop()

if __name__=='__main__': main()
