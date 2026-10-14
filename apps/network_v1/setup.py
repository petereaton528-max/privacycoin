"""Graphical no-clobber installation, existing Python/Tk and POSIX/WSL required.

Never elevates, installs a distro, starts services or overwrites a destination.
"""
import argparse
import hashlib
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import uuid
import tkinter as tk
from tkinter import ttk,filedialog,messagebox
from .desktop import safe_root,ROOT
from .rpc import VERSION


class Installer:
    def __init__(self,root):
        self.root=root;self.busy=False;self.jobs=queue.Queue();root.title('Privacy Coin — experimental testnet setup')
        frame=ttk.Frame(root,padding=20);frame.pack(fill='both',expand=True)
        ttk.Label(frame,text='Install '+VERSION,font=('Segoe UI',15,'bold')).pack(anchor='w')
        bundled=(ROOT/'runtime/python/bin/python3').is_file()
        ttk.Label(frame,text=('Requires existing Windows Python/Tk and WSL2 Ubuntu-24.04. NOT a native Windows backend.' if os.name=='nt' else 'Uses bundled Python/Tk/Tor and native libraries; requires Ubuntu 24.04 x86_64 and a graphical desktop.' if bundled else 'Requires Ubuntu 24.04 / Python 3.12 / Tk and documented runtime libraries.')+'\nDoes not start Tor or enable mining. Unsigned experimental testnet; no monetary value.',wraplength=640).pack(anchor='w',pady=10)
        name='candidate5-'+uuid.uuid4().hex[:8]
        self.archive=tk.StringVar();self.digest=tk.StringVar();self.destination=tk.StringVar(value=('~/pc-v1-installations/'+name if os.name=='nt' else str(Path.home()/'pc-v1-installations'/name)))
        for label,var in [('Release ZIP',self.archive),('Expected SHA-256 from a trusted channel',self.digest),('NEW private destination (Linux path on Windows)',self.destination)]:
            ttk.Label(frame,text=label).pack(anchor='w');ttk.Entry(frame,textvariable=var,width=80).pack(fill='x',pady=3)
        ttk.Button(frame,text='Choose release ZIP',command=self.choose).pack(anchor='w',pady=6)
        self.install_button=ttk.Button(frame,text='Verify and install',command=self.install);self.install_button.pack(anchor='w')
        self.status=tk.StringVar(value='Nothing installed. Existing wallets/data are preserved.');ttk.Label(frame,textvariable=self.status,wraplength=640).pack(anchor='w',pady=10)
        self.launch_button=ttk.Button(frame,text='Launch application (mining stays off)',command=self.launch,state='disabled');self.launch_button.pack(anchor='w')
        root.protocol('WM_DELETE_WINDOW',self.close);root.after(100,self.poll)

    def choose(self):
        if self.busy:return
        path=filedialog.askopenfilename(parent=self.root,title='Choose the reviewed release archive',filetypes=[('ZIP archive','*.zip')])
        if path:self.archive.set(path)

    def install(self):
        if self.busy:return
        archive=self.archive.get();digest=self.digest.get().strip().lower();destination=self.destination.get()
        if len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):messagebox.showerror('Checksum required','Enter the full expected SHA-256 from the owner’s authenticated release materials.',parent=self.root);return
        if '\n' in destination or '\r' in destination: return
        # Capture plain values before entering a worker. No Tk in worker threads.
        self.busy=True;self.install_button.state(['disabled']);self.launch_button.state(['disabled']);self.status.set('Verifying and installing; this may take a few minutes…')
        jobs=self.jobs
        def work():
            try:
                path=Path(archive)
                if path.is_symlink() or not path.is_file() or path.stat().st_size>320*1024*1024:raise ValueError('ARCHIVE')
                with path.open('rb') as source:actual=hashlib.file_digest(source,'sha256').hexdigest()
                if actual!=digest:raise ValueError('CHECKSUM')
                from .release import verify
                if verify(path)['kind']!=('windows-wsl2-x86_64' if os.name=='nt' else 'linux-x86_64'):raise ValueError('PLATFORM_ARCHIVE_REQUIRED')
                if os.name=='nt':
                    def linux_path(value):return subprocess.check_output(['wsl.exe','-d','Ubuntu-24.04','--','wslpath','-a','-u',value],timeout=30,creationflags=subprocess.CREATE_NO_WINDOW).decode().strip()
                    if destination.startswith('~/'):
                        home=subprocess.check_output(['wsl.exe','-d','Ubuntu-24.04','--','printenv','HOME'],timeout=30,creationflags=subprocess.CREATE_NO_WINDOW).decode().strip();target=home+destination[1:]
                    else:target=destination
                    if not target.startswith('/home/') or '..' in Path(target).parts:raise ValueError('PRIVATE_LINUX_DESTINATION')
                    # Installer creates its own private parent only, never chmods
                    # or adopts an existing shared parent. Backend validates it.
                    command=['wsl.exe','-d','Ubuntu-24.04','--cd',linux_path(str(ROOT)),'--','python3','-B','-m','apps.network_v1.release','install','--archive',linux_path(str(path.resolve())),'--destination',target,'--create-private-parent']
                    result=subprocess.run(command,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=600,creationflags=subprocess.CREATE_NO_WINDOW)
                    if result.returncode:raise ValueError('INSTALL')
                else:
                    from .release import install,create_private_parent
                    target=str(Path(destination));create_private_parent(Path(target))
                    install(path,Path(target))
                jobs.put((True,target))
            except Exception:jobs.put((False,'Installation rejected. Check checksum, dependencies, private parent permissions and NEW destination. Preserve any partial directory; choose a different destination after investigation.'))
        threading.Thread(target=work,daemon=True).start()

    def poll(self):
        try:
            ok,result=self.jobs.get_nowait();self.busy=False;self.install_button.state(['!disabled'])
            if ok:self.installed=result;self.status.set('Verified private installation complete. No services started.');self.launch_button.state(['!disabled'])
            else:self.status.set(result)
        except queue.Empty:pass
        self.root.after(100,self.poll)

    def launch(self):
        if not getattr(self,'installed',None):return
        if os.name=='nt':args=[sys.executable,'-B','-m','apps.network_v1.desktop','--backend-root',self.installed];cwd=ROOT
        elif (Path(self.installed)/'Launch-PC.sh').is_file():args=[str(Path(self.installed)/'Launch-PC.sh')];cwd=self.installed
        else:args=[sys.executable,'-B','-m','apps.network_v1.desktop'];cwd=self.installed
        subprocess.Popen(args,cwd=cwd,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,**({'creationflags':subprocess.CREATE_NO_WINDOW} if os.name=='nt' else {}))

    def close(self):
        if self.busy:messagebox.showinfo('Installation in progress','Wait for the bounded installation to finish. A partial directory must never be reused.',parent=self.root);return
        self.root.destroy()


def main():
    argparse.ArgumentParser(description='Graphical private installation of a reviewed experimental testnet ZIP; no services or mining start automatically.').parse_args()
    root=safe_root();Installer(root);root.mainloop()
if __name__=='__main__':main()
