"""Windows one-action launcher; UI/backend keep inherited anonymous pipes."""
from pathlib import Path
import argparse,json,os,queue,subprocess,threading,time
from tkinter import ttk,messagebox
from gui import App,safe_root
from bridge import Bridge

MESSAGES=dict(WSL2_REQUIRED='Ubuntu-24.04 must run under WSL2.',NATIVE_BINARY_MISSING_OR_CHANGED='A pinned native node / private transaction helper is missing or changed. Rebuild/verify using the project instructions.',WALLET_HELPER_MISSING='The existing wallet helper is missing.',SESSION_ALREADY_OPEN_OR_UNSAFE_DATA='A managed wallet session is already open, or the private node directory is unsafe. Close the first managed wallet or investigate permissions; no process was stopped.',RPC_PORT_IN_USE_OR_WRONG_NETWORK='The local RPC port is occupied by an incompatible or unresponsive service. Use the debug instructions; no unrelated process was stopped.',P2P_PORT_IN_USE='The local P2P port is already occupied. No unrelated process was stopped.',NODE_START_FAILED='The Devnet node did not start. Check ports, private directory permissions and native dependencies. Existing data was not reset.',NODE_READY_TIMEOUT='The local Devnet node did not become ready within 60 seconds.',LOCAL_STARTUP_FAILED='Local startup failed. Check Ubuntu-24.04, user privacydev, native helpers and private directories.')
class LaunchFailure(ValueError):pass

def host_command(args):
    path=Path(__file__).with_name('launcher_host.py').resolve();mounted='/mnt/'+path.drive[0].lower()+path.as_posix()[2:]
    command=['wsl.exe','-d','Ubuntu-24.04','-u','privacydev','--','python3',mounted,'--port',str(args.port),'--p2p-port',str(args.p2p_port)]
    if args.data:command+=['--data',args.data]
    return command
def stop_host(host):
    if host is None:return
    try:host.stdin.close()
    except OSError:pass
    try:host.wait(timeout=20)
    except subprocess.TimeoutExpired:
        # Kill only the Windows child we created; EOF is normal owned-node cleanup.
        host.terminate();host.wait(timeout=5)
def prepare(args,result,cancel):
    host=None;bridge=None
    try:
        if os.name!='nt':raise LaunchFailure('Use Windows Python with Tk.')
        distros=subprocess.run(['wsl.exe','--list','--quiet'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW)
        if distros.returncode or 'Ubuntu-24.04' not in distros.stdout.decode('utf-16le',errors='ignore'):raise LaunchFailure('WSL Ubuntu-24.04 is unavailable. Install/configure the documented development environment; no administrator action is automated.')
        if cancel.is_set():raise LaunchFailure('Startup cancelled.')
        host=subprocess.Popen(host_command(args),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
        reply=queue.Queue()
        def read():
            try:reply.put(json.loads(host.stdout.readline(16385)))
            except Exception:reply.put(None)
        threading.Thread(target=read,daemon=True).start();ready=reply.get(timeout=90)
        if not isinstance(ready,dict) or ready.get('ok') is not True:raise LaunchFailure(MESSAGES.get(ready.get('code') if isinstance(ready,dict) else '',MESSAGES['LOCAL_STARTUP_FAILED']))
        if cancel.is_set():raise LaunchFailure('Startup cancelled.')
        bridge=Bridge(args.home,args.port);hello=bridge.call('hello')
        if hello.get('network')!='privacycoin-devnet' or hello.get('full_sync') is not True or hello.get('production_safe') is not False:raise LaunchFailure('Wallet backend returned incompatible capabilities. Startup stopped.')
        if cancel.is_set():raise LaunchFailure('Startup cancelled.')
        result.put((True,host,bridge,ready));return
    except Exception as error:
        # Only our deliberate fixed messages are displayed; arbitrary exception values redacted.
        message=str(error) if isinstance(error,LaunchFailure) else MESSAGES['LOCAL_STARTUP_FAILED']
        if bridge is not None:bridge.close()
        stop_host(host);result.put((False,None,None,message))
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--port',type=int,default=48081);parser.add_argument('--p2p-port',type=int,default=48080);parser.add_argument('--home');parser.add_argument('--data');a=parser.parse_args()
    root=safe_root();root.title('Privacy Coin — DEVNET ONLY');root.geometry('650x180');root.resizable(False,False)
    status=ttk.Label(root,text='Starting disposable Devnet wallet…\nChecking WSL2, pinned helpers and local node readiness.\nNo mining starts automatically.',padding=20,wraplength=600);status.pack(fill='both',expand=True)
    results=queue.Queue();cancel=threading.Event();owned=[]
    def closing():cancel.set();status.configure(text='Cancelling startup and stopping owned processes…')
    root.protocol('WM_DELETE_WINDOW',closing)
    threading.Thread(target=prepare,args=(a,results,cancel),daemon=True).start()
    def poll():
        try:ok,host,bridge,data=results.get_nowait()
        except queue.Empty:root.after(50,poll);return
        if not ok:
            if not cancel.is_set():messagebox.showerror('Wallet startup stopped',data,parent=root)
            root.destroy();return
        owned.extend([host,bridge])
        if cancel.is_set():bridge.close();stop_host(host);root.destroy();return
        for child in root.winfo_children():child.destroy()
        App(root,bridge)
    root.after(50,poll)
    try:root.mainloop()
    finally:
        cancel.set()
        if owned:owned[1].close();stop_host(owned[0])
if __name__=='__main__':main()
