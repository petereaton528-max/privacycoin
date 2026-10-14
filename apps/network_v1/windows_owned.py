"""Windows owned process trees. Parent-held kill-on-close Job Object.

The trusted Python trampoline cannot launch the command before job assignment:
it waits on an inherited pipe, whose EOF cancels startup. No breakaway is allowed.
No process-name/PID sweeps, privileged service or host-policy modification.
"""
import ctypes as C
from ctypes import wintypes as W
import os
from pathlib import Path
import signal
import subprocess
import sys

if os.name!='nt':raise RuntimeError('Windows owned processes only')
K=C.WinDLL('kernel32',use_last_error=True)
def bind(name,result,args):
    f=getattr(K,name);f.restype=result;f.argtypes=args;return f
create=bind('CreateJobObjectW',W.HANDLE,[C.c_void_p,W.LPCWSTR])
set_info=bind('SetInformationJobObject',W.BOOL,[W.HANDLE,C.c_int,C.c_void_p,W.DWORD])
assign=bind('AssignProcessToJobObject',W.BOOL,[W.HANDLE,W.HANDLE])
terminate=bind('TerminateJobObject',W.BOOL,[W.HANDLE,W.UINT])
close=bind('CloseHandle',W.BOOL,[W.HANDLE])
class Basic(C.Structure):
    _fields_=[('per_process',C.c_int64),('per_job',C.c_int64),('flags',W.DWORD),('min_working',C.c_size_t),('max_working',C.c_size_t),('active',W.DWORD),('affinity',C.c_size_t),('priority',W.DWORD),('scheduling',W.DWORD)]
class IO(C.Structure):_fields_=[(name,C.c_uint64) for name in ('read_ops','write_ops','other_ops','read_bytes','write_bytes','other_bytes')]
class Extended(C.Structure):
    _fields_=[('basic',Basic),('io',IO),('process_memory',C.c_size_t),('job_memory',C.c_size_t),('peak_process',C.c_size_t),('peak_job',C.c_size_t)]

class Job:
    def __init__(self):
        self.handle=create(None,None)
        if not self.handle:raise C.WinError(C.get_last_error())
        limits=Extended();limits.basic.flags=0x2000  # KILL_ON_JOB_CLOSE
        if not set_info(self.handle,9,C.byref(limits),C.sizeof(limits)):
            error=C.WinError(C.get_last_error());self.close();raise error
    def attach(self,process):
        if not assign(self.handle,int(process._handle)):raise C.WinError(C.get_last_error())
    def kill(self):
        if self.handle and not terminate(self.handle,125):raise C.WinError(C.get_last_error())
    def close(self):
        if self.handle:close(self.handle);self.handle=None

def spawn(args,**kwargs):
    if not args or not Path(args[0]).is_absolute():raise ValueError('absolute owned executable required')
    if any(n in kwargs for n in ('creationflags','startupinfo','close_fds','preexec_fn','start_new_session')):raise ValueError('owned creation settings required')
    import msvcrt
    job=Job();child=None;reader,writer=os.pipe();handle=msvcrt.get_osfhandle(reader)
    try:
        os.set_handle_inheritable(handle,True)
        startup=subprocess.STARTUPINFO();startup.lpAttributeList={'handle_list':[handle]}
        child=subprocess.Popen([sys.executable,'-I','-S','-B',str(Path(__file__).resolve()),'--gate',str(handle),'--',*args],
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP|subprocess.CREATE_NO_WINDOW,close_fds=True,startupinfo=startup,**kwargs)
        os.set_handle_inheritable(handle,False);os.close(reader);reader=None
        job.attach(child)
        os.write(writer,b'G');os.close(writer);writer=None
        child._pc_owned_job=job
        return child
    except BaseException:
        job.close()
        if child is not None:
            # Only this Popen handle, never an arbitrary PID or process name.
            if child.poll() is None:child.terminate()
            child.wait(timeout=10)
            for stream in (child.stdin,child.stdout,child.stderr):
                if stream is not None:stream.close()
        raise
    finally:
        if reader is not None:os.close(reader)
        if writer is not None:os.close(writer)

def stop(child):
    if child is None:return
    job=getattr(child,'_pc_owned_job',None)
    if job is None:raise ValueError('owned Windows job required')
    try:
        if child.poll() is None:
            # CTRL_BREAK requires a shared console. GUI/no-console deployments
            # may reject it; the bounded job fallback is abrupt, not a claimed
            # graceful database checkpoint.
            try:child.send_signal(signal.CTRL_BREAK_EVENT);child.wait(timeout=3)
            except (OSError,subprocess.TimeoutExpired):job.kill();child.wait(timeout=10)
    finally:job.close()  # Also terminates any still-owned descendants.

def main():
    if len(sys.argv)<5 or sys.argv[1]!='--gate' or sys.argv[3]!='--':raise SystemExit(125)
    import msvcrt
    fd=msvcrt.open_osfhandle(int(sys.argv[2]),os.O_RDONLY)
    try:ready=os.read(fd,1)
    finally:os.close(fd)
    if ready!=b'G' or not Path(sys.argv[4]).is_absolute():raise SystemExit(125)
    # Do not pass the gate onward. Stdio carries any explicitly supplied private
    # input, never arguments or environment credentials.
    signal.signal(signal.SIGBREAK,lambda *_:(_ for _ in ()).throw(KeyboardInterrupt()))
    child=subprocess.Popen(sys.argv[4:],close_fds=True)
    try:return child.wait()
    except KeyboardInterrupt:
        try:return child.wait(timeout=2)
        except subprocess.TimeoutExpired:return 125  # Parent closes whole job.

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:raise SystemExit(125) from None
