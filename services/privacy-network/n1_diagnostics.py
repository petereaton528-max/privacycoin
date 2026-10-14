"""Opt-in bounded private diagnostics: fixed fields only, no protocol secrets."""
from common import c,f,Path
import os,time,threading

class Diagnostics:
    def __init__(self,path,limit=1024*1024):
        self.path=Path(path);self.limit=limit;self.lock=threading.Lock()
        if not self.path.exists():c.write_private(self.path,b'')
        c.read_private(self.path)
    def event(self,event,**fields):
        allowed={'trace','operation','stage','state','code','elapsed_ms','role','pid','progress','bytes','attempt','status'}
        if set(fields)-allowed:raise ValueError('DIAGNOSTIC_SCHEMA')
        # Call sites supply only fixed stage/error labels, random request IDs and
        # numeric measurements. Bodies, headers, destinations and IDs are absent.
        raw=f.canonical(dict(monotonic_ns=time.monotonic_ns(),event=event,**fields))+b'\n'
        with self.lock:
            fd=os.open(self.path,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
            try:
                stat=os.fstat(fd)
                if stat.st_nlink!=1 or stat.st_uid!=os.getuid() or stat.st_mode&0o077:raise ValueError('DIAGNOSTIC_PERMISSIONS')
                if stat.st_size+len(raw)<=self.limit:os.write(fd,raw)
            finally:os.close(fd)

def emit(diagnostics,event,**fields):
    if diagnostics is not None:diagnostics.event(event,**fields)
