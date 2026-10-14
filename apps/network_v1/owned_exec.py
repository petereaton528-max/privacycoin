"""Install Linux parent-death guard after exec, avoiding preexec_fn in Tk workers."""
import ctypes
import os
import signal
import sys


def main():
    if len(sys.argv)<3 or os.name!='posix':raise SystemExit(125)
    parent=int(sys.argv[1]);libc=ctypes.CDLL(None,use_errno=True)
    if libc.prctl(1,signal.SIGTERM,0,0,0)!=0 or os.getppid()!=parent:raise SystemExit(125)
    if not os.path.isabs(sys.argv[2]):raise SystemExit(125)
    os.execv(sys.argv[2],sys.argv[2:])


if __name__=='__main__':main()
