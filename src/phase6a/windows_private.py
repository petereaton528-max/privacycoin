"""Owner-only NTFS file primitives. No host-policy changes or crypto algorithms.

Strict local drive paths, no reparse points/ADS/UNC, one current-user full-access
ACE, single-link regular files. Open ancestor handles deny directory deletion.
MoveFileEx write-through publishes within one directory; no cross-volume copies.
This does not protect against an administrator, same-user debugger or power loss.
"""
import ctypes as C
from ctypes import wintypes as W
from contextlib import contextmanager
import os,re,uuid
from pathlib import Path

if os.name!='nt':raise RuntimeError('Windows filesystem adapter only')
K=C.WinDLL('kernel32',use_last_error=True);A=C.WinDLL('advapi32',use_last_error=True)
def bind(dll,name,result,args):
    function=getattr(dll,name);function.restype=result;function.argtypes=args;return function
HANDLE=W.HANDLE;PTR=C.c_void_p;DWORD=W.DWORD;BOOL=W.BOOL
close=bind(K,'CloseHandle',BOOL,[HANDLE])
create=bind(K,'CreateFileW',HANDLE,[W.LPCWSTR,DWORD,DWORD,PTR,DWORD,DWORD,HANDLE])
last=lambda:C.WinError(C.get_last_error())
local_free=bind(K,'LocalFree',PTR,[PTR])
current=bind(K,'GetCurrentProcess',HANDLE,[])
open_token=bind(A,'OpenProcessToken',BOOL,[HANDLE,DWORD,C.POINTER(HANDLE)])
token_info=bind(A,'GetTokenInformation',BOOL,[HANDLE,DWORD,PTR,DWORD,C.POINTER(DWORD)])
get_security=bind(A,'GetSecurityInfo',DWORD,[HANDLE,DWORD,DWORD,C.POINTER(PTR),C.POINTER(PTR),C.POINTER(PTR),C.POINTER(PTR),C.POINTER(PTR)])
equal_sid=bind(A,'EqualSid',BOOL,[PTR,PTR])
get_ace=bind(A,'GetAce',BOOL,[PTR,DWORD,C.POINTER(PTR)])
acl_info=bind(A,'GetAclInformation',BOOL,[PTR,PTR,DWORD,DWORD])
sid_string=bind(A,'ConvertSidToStringSidW',BOOL,[PTR,C.POINTER(W.LPWSTR)])
sddl=bind(A,'ConvertStringSecurityDescriptorToSecurityDescriptorW',BOOL,[W.LPCWSTR,DWORD,C.POINTER(PTR),C.POINTER(DWORD)])
mkdir_api=bind(K,'CreateDirectoryW',BOOL,[W.LPCWSTR,PTR])
move=bind(K,'MoveFileExW',BOOL,[W.LPCWSTR,W.LPCWSTR,DWORD])
delete=bind(K,'DeleteFileW',BOOL,[W.LPCWSTR])
flush=bind(K,'FlushFileBuffers',BOOL,[HANDLE])
read=bind(K,'ReadFile',BOOL,[HANDLE,PTR,DWORD,C.POINTER(DWORD),PTR])
write=bind(K,'WriteFile',BOOL,[HANDLE,PTR,DWORD,C.POINTER(DWORD),PTR])
volume=bind(K,'GetVolumeInformationW',BOOL,[W.LPCWSTR,W.LPWSTR,DWORD,C.POINTER(DWORD),C.POINTER(DWORD),C.POINTER(DWORD),W.LPWSTR,DWORD])
class Info(C.Structure):
    _fields_=[('attributes',DWORD),('created',W.FILETIME),('accessed',W.FILETIME),('modified',W.FILETIME),('volume',DWORD),('size_high',DWORD),('size_low',DWORD),('links',DWORD),('index_high',DWORD),('index_low',DWORD)]
file_info=bind(K,'GetFileInformationByHandle',BOOL,[HANDLE,C.POINTER(Info)])
class ACLInfo(C.Structure):_fields_=[('count',DWORD),('used',DWORD),('free',DWORD)]
class SA(C.Structure):_fields_=[('length',DWORD),('descriptor',PTR),('inherit',BOOL)]

def principal():
    token=HANDLE()
    if not open_token(current(),8,C.byref(token)):raise last()
    try:
        size=DWORD();token_info(token,1,None,0,C.byref(size))
        if not 8<=size.value<=4096:raise ValueError('token size')
        buffer=C.create_string_buffer(size.value)
        if not token_info(token,1,buffer,size,C.byref(size)):raise last()
        sid=C.cast(buffer,C.POINTER(PTR))[0]
        return buffer,sid
    finally:close(token)

def path(value):
    value=Path(value)
    if not value.is_absolute() or not re.fullmatch('[A-Za-z]:',value.drive) or len(str(value))>=240:raise ValueError('local bounded NTFS drive path required')
    reserved={'CON','PRN','AUX','NUL',*[f'{p}{n}' for p in ('COM','LPT') for n in range(1,10)]}
    for part in value.parts[1:]:
        if part in ('.','..') or ':' in part or part.endswith(('.', ' ')) or part.split('.')[0].upper() in reserved:raise ValueError('unsafe Windows path')
    filesystem=C.create_unicode_buffer(32)
    if not volume(value.anchor,None,0,None,None,None,filesystem,len(filesystem)):raise last()
    if filesystem.value.upper()!='NTFS':raise ValueError('NTFS required')
    return value

def information(handle):
    info=Info()
    if not file_info(handle,C.byref(info)):raise last()
    if info.attributes&0x400:raise ValueError('reparse point rejected')
    return info

def private(handle):
    buffer,sid=principal();owner=PTR();dacl=PTR();descriptor=PTR()
    error=get_security(handle,1,5,C.byref(owner),None,C.byref(dacl),None,C.byref(descriptor))
    if error:raise C.WinError(error)
    try:
        if not owner or not equal_sid(owner,sid) or not dacl:raise ValueError('private owner/DACL required')
        info=ACLInfo()
        if not acl_info(dacl,C.byref(info),C.sizeof(info),2):raise last()
        # Refuse ambiguous/object/callback/extra ACEs rather than approximating
        # the complete Windows effective-access algorithm.
        if info.count!=1:raise ValueError('one owner-only ACE required')
        ace=PTR()
        if not get_ace(dacl,0,C.byref(ace)):raise last()
        header=C.string_at(ace,8);mask=int.from_bytes(header[4:8],'little')
        if header[0]!=0 or header[1]&8 or mask&0x1f01ff!=0x1f01ff or not equal_sid(ace.value+8,sid):raise ValueError('owner full-access ACE required')
    finally:local_free(descriptor)

def opened(value,access,disposition,sharing=1,flags=0x200080):
    handle=create(str(value),access|0x20000,sharing,None,disposition,flags,None)
    if handle==C.c_void_p(-1).value:raise last()
    return handle

@contextmanager
def directory(value,require_private=True):
    value=path(value);handles=[];cursor=Path(value.anchor)
    try:
        for part in (None,*value.parts[1:]):
            if part is not None:cursor/=part
            handle=opened(cursor,1,3,sharing=3,flags=0x2200000);handles.append(handle)
            if not information(handle).attributes&0x10:raise ValueError('directory required')
        if require_private:private(handles[-1])
        yield value
    finally:
        for handle in reversed(handles):close(handle)

def checked(handle,limit):
    info=information(handle);size=(info.size_high<<32)|info.size_low
    if info.attributes&0x10 or info.links!=1 or size>limit:raise ValueError('private bounded single-link regular file required')
    private(handle);return size

@contextmanager
def security():
    buffer,sid=principal();text=W.LPWSTR();descriptor=PTR()
    if not sid_string(sid,C.byref(text)):raise last()
    try:rule='O:'+text.value+'D:P(A;OICI;FA;;;'+text.value+')'
    finally:local_free(C.cast(text,PTR))
    if not sddl(rule,1,C.byref(descriptor),None):raise last()
    try:yield SA(C.sizeof(SA),descriptor,False)
    finally:local_free(descriptor)

def mkdir(value,exclusive=False):
    value=path(value)
    with directory(value.parent,require_private=False),security() as attributes:
        if not mkdir_api(str(value),C.byref(attributes)):
            if C.get_last_error()!=183 or exclusive:raise last()
        with directory(value):pass

def read_private(value,limit=4*1024*1024):
    value=path(value)
    with directory(value.parent):
        handle=opened(value,0x80000000,3)
        try:
            expected=checked(handle,limit);buffer=C.create_string_buffer(expected+1);count=DWORD()
            if not read(handle,buffer,expected+1,C.byref(count),None):raise last()
            if count.value!=expected:raise ValueError('file changed')
            return buffer.raw[:expected]
        finally:close(handle)

def write_private(value,raw,replace=False,fault=None,limit=4*1024*1024):
    if not isinstance(raw,bytes) or len(raw)>limit:raise ValueError('write bound')
    value=path(value)
    with directory(value.parent):
        try:existing=opened(value,0x80000000,3)
        except OSError as error:
            if error.winerror!=2:raise
        else:
            try:checked(existing,limit)
            finally:close(existing)
            if not replace:raise ValueError('no overwrite')
        temporary=value.parent/('.pcwallet-'+uuid.uuid4().hex+'.tmp');handle=None
        try:
            handle=opened(temporary,0xc0000000,1,flags=0x80200080);checked(handle,limit)
            count=DWORD();buffer=C.create_string_buffer(raw)
            if not write(handle,buffer,len(raw),C.byref(count),None) or count.value!=len(raw):raise last()
            if fault:fault('during_write')
            if not flush(handle):raise last()
            close(handle);handle=None
            if fault:fault('before_publish')
            if not move(str(temporary),str(value),8|(1 if replace else 0)):raise last()
            if fault:fault('after_publish')
        finally:
            if handle is not None:close(handle)
            delete(str(temporary))  # only this owned temporary leaf, never recursion

@contextmanager
def lock(value):
    value=path(value)
    with directory(value.parent):
        handle=opened(str(value)+'.lock',0xc0000000,4,sharing=1)
        try:checked(handle,4*1024*1024);yield
        finally:close(handle)

def harden():
    if C.sizeof(PTR)!=8:raise ValueError('64-bit Windows required')
    principal();os.umask(0o077)  # DACLs, not this compatibility umask, protect files.

def rss_kib():
    class Memory(C.Structure):
        _fields_=[('size',DWORD),('faults',DWORD),*[(name,C.c_size_t) for name in ('peak','working','peak_paged','paged','peak_nonpaged','nonpaged','pagefile','peak_pagefile')]]
    info=Memory();info.size=C.sizeof(info)
    query=bind(K,'K32GetProcessMemoryInfo',BOOL,[HANDLE,PTR,DWORD])
    if not query(current(),C.byref(info),C.sizeof(info)):raise last()
    return info.working//1024
