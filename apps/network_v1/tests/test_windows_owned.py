"""Actual Windows Job Object tests with disposable Python processes only."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

@unittest.skipUnless(os.name=='nt','Actual Windows Job Object supervision')
class WindowsOwnedTests(unittest.TestCase):
    def setUp(self):
        from apps.network_v1 import windows_owned as owned
        self.owned=owned;self.root=Path(tempfile.gettempdir())/('pc-v1-win-owned-'+uuid.uuid4().hex);self.root.mkdir()
    def spawn(self,code,**kwargs):
        return self.owned.spawn([sys.executable,'-B','-c',code],cwd=Path(__file__).resolve().parents[3],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,**kwargs)
    def test_exit_status_and_explicit_stdin(self):
        child=self.spawn("import sys; print(len(sys.stdin.buffer.read()),flush=True); sys.exit(7)",stdin=subprocess.PIPE)
        try:
            output,_=child.communicate(b'public dummy',timeout=15)
            self.assertEqual(child.returncode,7);self.assertEqual(output.strip(),b'12')
        finally:self.owned.stop(child)
    def test_reject_nonowned_and_relative(self):
        with self.assertRaises(ValueError):self.owned.spawn(['relative.exe'])
        with self.assertRaises(ValueError):self.owned.stop(subprocess.CompletedProcess([],0))
    def test_assignment_failure_cannot_launch_target(self):
        from unittest.mock import patch
        marker=self.root/'not-created'
        with patch.object(self.owned.Job,'attach',side_effect=OSError('synthetic assignment denial')):
            with self.assertRaises(OSError):self.spawn('from pathlib import Path;Path('+repr(str(marker))+').write_text("public")')
        self.assertFalse(marker.exists())
    def test_gated_wrapper_ignores_python_startup_hooks(self):
        from unittest.mock import patch
        marker=self.root/'startup-not-created'
        (self.root/'sitecustomize.py').write_text('from pathlib import Path\nPath('+repr(str(marker))+').write_text("public startup hook")\n')
        def reject(_job,_child):time.sleep(.3);raise OSError('synthetic assignment denial')
        with patch.object(self.owned.Job,'attach',reject):
            with self.assertRaises(OSError):self.spawn('pass',stdin=subprocess.DEVNULL,env=dict(os.environ,PYTHONPATH=str(self.root)))
        self.assertFalse(marker.exists())
    def test_stop_tree_preserves_unrelated_process(self):
        unrelated=subprocess.Popen([sys.executable,'-B','-c','import time; time.sleep(30)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        child=self.spawn('import subprocess,sys,time; p=subprocess.Popen([sys.executable,"-B","-c","import time;time.sleep(30)"]); print(p.pid,flush=True); time.sleep(30)',stdin=subprocess.DEVNULL)
        from ctypes import wintypes as W
        C=self.owned.C;opened=self.owned.bind('OpenProcess',W.HANDLE,[W.DWORD,W.BOOL,W.DWORD]);query=self.owned.bind('GetExitCodeProcess',W.BOOL,[W.HANDLE,C.POINTER(W.DWORD)])
        handle=None
        try:
            # Test-owned pipe; bounded total child lifetime and timeout below.
            import threading
            captured=[];reader=threading.Thread(target=lambda:captured.append(child.stdout.readline()),daemon=True);reader.start();reader.join(10)
            self.assertFalse(reader.is_alive());pid=int(captured[0]);handle=opened(0x1000,False,pid);self.assertTrue(handle)
            self.owned.stop(child);status=W.DWORD()
            for _ in range(50):
                self.assertTrue(query(handle,C.byref(status)))
                if status.value!=259:break
                time.sleep(.05)
            self.assertNotEqual(status.value,259);self.assertIsNone(unrelated.poll())
        finally:
            self.owned.stop(child)
            child.stdout.close()
            if handle:self.owned.close(handle)
            if unrelated.poll() is None:unrelated.terminate()
            unrelated.wait(timeout=10)
    def test_parent_crash_kills_owned_tree(self):
        marker=self.root/'pid'
        code='''import os,sys,time
from pathlib import Path
from apps.network_v1.windows_owned import spawn
p=spawn([sys.executable,'-B','-c','import os,time;from pathlib import Path;Path('+repr(sys.argv[1])+').write_text(str(os.getpid()));time.sleep(30)'],stdout=-3,stderr=-3,stdin=-3)
while not Path(sys.argv[1]).exists():time.sleep(.02)
os._exit(73)
'''
        parent=subprocess.Popen([sys.executable,'-B','-c',code,str(marker)],cwd=Path(__file__).resolve().parents[3],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        from ctypes import wintypes as W
        C=self.owned.C;opened=self.owned.bind('OpenProcess',W.HANDLE,[W.DWORD,W.BOOL,W.DWORD]);query=self.owned.bind('GetExitCodeProcess',W.BOOL,[W.HANDLE,C.POINTER(W.DWORD)])
        try:
            self.assertEqual(parent.wait(timeout=15),73);self.assertTrue(marker.exists())
            handle=opened(0x1000,False,int(marker.read_text()))
            if handle:
                try:
                    status=W.DWORD()
                    for _ in range(50):
                        self.assertTrue(query(handle,C.byref(status)))
                        if status.value!=259:break
                        time.sleep(.05)
                    self.assertNotEqual(status.value,259)
                finally:self.owned.close(handle)
        finally:
            if parent.poll() is None:parent.terminate()
            parent.wait(timeout=10)

if __name__=='__main__':unittest.main()
