"""Real bundled Tor + Tk regression, DisableNetwork=1 throughout; no relay traffic.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import os,socket,subprocess,sys,tempfile,threading,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from apps.network_v1 import onion
onion.dependencies()
from tor_runtime import OwnedTor,write_config

ROOT=Path(os.environ['PC_DEVNET_NATIVE_ROOT'])
def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def ready(tor):
    end=time.monotonic()+8
    while time.monotonic()<end:
        if tor.process.poll() is not None:raise AssertionError('Tor exited before control readiness')
        try:
            value=tor.control('GETINFO status/bootstrap-phase')
            if b'PROGRESS=0' in value:return
        except (OSError,ValueError):pass
        time.sleep(.05)
    raise AssertionError('disabled control deadline')

class WorkerOwnership(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='pc-tor-worker-');self.home=Path(self.temp.name);self.port=port()
        write_config(self.home/'torrc',[f'DataDirectory {self.home}','DisableNetwork 1','SocksPort 0',f'ControlPort 127.0.0.1:{self.port}','CookieAuthentication 1','RunAsDaemon 0','SafeLogging 1'])
        self.tor=OwnedTor(ROOT/'runtime/bin/tor',self.home/'torrc')
    def tearDown(self):self.tor.close();self.temp.cleanup()
    def test_short_lived_worker_control_and_cleanup(self):
        t=threading.Thread(target=self.tor.start);t.start();t.join(10);self.assertFalse(t.is_alive())
        ready(self.tor);time.sleep(.15);self.assertIsNone(self.tor.process.poll());self.assertTrue(self.tor.owner.is_alive())
        with self.assertRaisesRegex(ValueError,'TOR_ALREADY_OWNED'):self.tor.start()
        self.tor.close();self.assertFalse(self.tor.owner.is_alive());self.assertIsNotNone(self.tor.process.poll())
        with socket.socket() as s:self.assertNotEqual(s.connect_ex(('127.0.0.1',self.port)),0)
    def test_parent_exit_still_terminates_owned_tor(self):
        code='from apps.network_v1.onion import dependencies; dependencies(); from tor_runtime import OwnedTor; import sys,time,os; t=OwnedTor(sys.argv[1],sys.argv[2]); t.start(); time.sleep(1); print(t.process.pid,flush=True); os._exit(0)'
        result=subprocess.run([sys.executable,'-c',code,str(self.tor.binary),str(self.tor.config)],capture_output=True,timeout=8,check=True)
        pid=int(result.stdout);end=time.monotonic()+5
        while time.monotonic()<end:
            stat=Path(f'/proc/{pid}/stat')
            if not stat.exists() or stat.read_text().split()[2]=='Z':break
            time.sleep(.05)
        else:self.fail('orphan Tor survives parent exit')
    def test_launch_failure_propagates(self):
        with patch.object(self.tor,'verify'),patch('tor_runtime.subprocess.Popen',side_effect=OSError('test')):
            with self.assertRaises(OSError):self.tor.start()
        self.tor.owner.join(1);self.assertFalse(self.tor.owner.is_alive())
    def test_invalid_config_rejected(self):
        write_config(self.tor.config,['InvalidPCOption 1'])
        with self.assertRaisesRegex(ValueError,'TOR_CONFIG_INVALID'):self.tor.start()
        self.assertIsNone(self.tor.process)
    def test_legacy_worker_reproduces_early_exit(self):
        # Reproduce the released preexec/PDEATHSIG ownership on a disposable Tor.
        from launcher_host import child_parent_guard
        parent=os.getpid();holder=[]
        def launch():
            holder.append(subprocess.Popen([str(self.tor.binary),'-f',str(self.tor.config)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,preexec_fn=lambda:child_parent_guard(parent)))
        worker=threading.Thread(target=launch);worker.start();worker.join(5)
        child=holder[0]
        try:self.assertIsNotNone(child.wait(timeout=5))
        finally:
            if child.poll() is None:child.terminate();child.wait(timeout=5)
    def test_control_startup_grace_is_bounded(self):
        session=onion.TorSession.__new__(onion.TorSession)
        session.owned=SimpleNamespace(process=SimpleNamespace(poll=lambda:None),started_at=time.monotonic(),control=lambda cmd:(_ for _ in ()).throw(OSError()))
        session.channels=[];session.peers=[]
        self.assertEqual(session.status()['state'],'CONTROL_STARTING')
        session.owned.started_at-=11
        self.assertEqual(session.status()['state'],'CONTROL_UNAVAILABLE')
    def test_actual_gui_worker_and_unready_status_panel(self):
        import tkinter as tk
        from apps.network_v1.candidate_gui import Window
        outer=self
        class OfflineNode:
            tor=None
            def connect_tor(self,*args):
                # Only substitute external activation; use actual Tor/control and GUI worker.
                self.tor=self;outer.tor.start();return self.status()
            def status(self):
                try:outer.tor.control('GETINFO status/bootstrap-phase');state='BOOTSTRAPPING'
                except (OSError,ValueError):state='CONTROL_STARTING'
                return dict(state=state,bootstrap_percent=0)
            def call(self,**kwargs):return dict(height=0)
            def public_descriptor(self):raise AssertionError('unready descriptor must not hide status')
        node=OfflineNode();root=tk.Tk();root.withdraw()
        client=SimpleNamespace(external=True,node=node,native_root=ROOT,close=outer.tor.close)
        window=Window(root,client)
        try:
            with patch('apps.network_v1.candidate_gui.simpledialog.askstring',side_effect=['','127.0.0.1:22307']),patch('apps.network_v1.candidate_gui.messagebox.askokcancel',return_value=True):window.connect_tor()
            end=time.monotonic()+10
            while window.busy and time.monotonic()<end:root.update();time.sleep(.01)
            self.assertIsNone(window.last_error);ready(outer.tor);self.assertIsNone(outer.tor.process.poll())
            window.node_info()
            while window.busy and time.monotonic()<end:root.update();time.sleep(.01)
            self.assertIsNone(window.last_error)
            self.assertTrue(any(isinstance(w,tk.Toplevel) for w in root.winfo_children()))
            window.show_tor(dict(state='DISCONNECTED',bootstrap_percent=0,tor_exit_code=-15))
            self.assertIn('code -15',window.tor_summary.get())
        finally:
            window.closed=True;root.after_cancel(window.poll_id);outer.tor.close();root.destroy()

if __name__=='__main__':unittest.main(verbosity=2)
