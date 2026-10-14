"""Per-user graphical preview installer. New destinations; no data migration."""
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk,messagebox

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))

def install(destination):
    from apps.network_v1.release import install as unpack
    from src.phase6a import windows_private as private
    if os.name!='nt':raise ValueError('WINDOWS_ONLY')
    destination=Path(destination)
    if not destination.is_absolute() or '..' in destination.parts or destination.exists() or any('privacycoin-n2' in x.lower() for x in destination.parts):raise ValueError('NEW_NON_N2_DESTINATION_REQUIRED')
    # Only create one new private parent beneath an existing local directory.
    private.mkdir(destination.parent)
    return unpack(ROOT/'NATIVE_PAYLOAD.zip',destination)

def main():
    root=tk.Tk();root.title('Privacy Coin · experimental native preview setup')
    frame=ttk.Frame(root,padding=24);frame.pack(fill='both',expand=True)
    ttk.Label(frame,text='Native Windows engineering preview',font=('Segoe UI',16,'bold')).pack(anchor='w')
    ttk.Label(frame,text='TESTNET ONLY. Not approved for public release.\nThe coin backend is blocked by Code Integrity on the development host.\nThis preview does not establish wallet/mining acceptance on your computer.\nNo WSL, Python or Tor installation is required. No mining or network starts here.\nExisting wallets and N2 data are never imported automatically.',wraplength=620).pack(anchor='w',pady=12)
    destination=tk.StringVar(value=str(Path(os.environ['LOCALAPPDATA'])/'PrivacyCoinV1-installations'/'rc5-native-preview-1'))
    ttk.Label(frame,text='NEW application directory (existing destinations are refused):').pack(anchor='w')
    ttk.Entry(frame,textvariable=destination,width=85).pack(fill='x',pady=8)
    status=tk.StringVar(value='Wallet data stays separately in LocalAppData/PrivacyCoinV1-testnet.\nAn interrupted installation remains incomplete; choose a NEW directory to retry.')
    ttk.Label(frame,textvariable=status,wraplength=620).pack(anchor='w',pady=10)
    replies=queue.Queue();busy=False;installed=None
    def close():
        if busy:messagebox.showinfo('Installing','Wait for verification to finish. No wallet data is being modified.',parent=root)
        else:root.destroy()
    def start():
        nonlocal busy
        if busy:return
        if not messagebox.askokcancel('Install unsigned experimental preview','Install only if you verified the externally supplied SHA-256.\nChecksums inside the archive do not authenticate its publisher.\nNo Windows security policy will be changed.',parent=root):return
        target=destination.get();busy=True;button.state(['disabled']);status.set('Verifying and installing. Please wait…')
        def work():
            try:install(target);replies.put((True,target))
            except Exception as error:replies.put((False,type(error).__name__))
        threading.Thread(target=work,daemon=False).start()
    def poll():
        nonlocal busy,installed
        try:ok,value=replies.get_nowait()
        except queue.Empty:pass
        else:
            busy=False;button.state(['!disabled'])
            if ok:
                installed=Path(value);status.set('Installed and hash-verified. Mining and Tor are OFF.\nLaunch remains an experimental preview; OS execution policy still applies.');launch.state(['!disabled'])
            else:status.set('Installation failed safely ('+value+'). Existing files were not overwritten.\nKeep any incomplete directory for diagnosis; choose a NEW private destination.')
        root.after(100,poll)
    def open_app():
        if installed is None:return
        try:subprocess.Popen([str(installed/'PrivacyCoin.exe')],cwd=installed,close_fds=True)
        except OSError:messagebox.showerror('Preview could not launch','Check Windows protection history and the verified package. Do not disable security controls. Wallet data was not changed.',parent=root)
    button=ttk.Button(frame,text='Install experimental preview',command=start);button.pack(anchor='w',pady=6)
    launch=ttk.Button(frame,text='Launch preview',command=open_app,state='disabled');launch.pack(anchor='w',pady=6)
    root.protocol('WM_DELETE_WINDOW',close);root.after(100,poll);root.mainloop()

if __name__=='__main__':main()
