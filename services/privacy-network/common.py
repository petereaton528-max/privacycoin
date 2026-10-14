"""Isolated Devnet resource pilot. Reuses frozen wallet/native components."""
from pathlib import Path
import base64,ctypes,hashlib,http.client,json,os,secrets,sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/devnet-gui'))
from backend import Session,c,f,w,native,NATIVE
MAX_PLAIN=1024*1024
MAX_CIPHER=MAX_PLAIN+44
def digest(raw):return hashlib.sha256(raw).hexdigest()
def token():return secrets.token_hex(32)
def identity(value):f.unhex(value,32);return value
def private_dir(path):
    path=Path(path);path.mkdir(mode=0o700,parents=True,exist_ok=True)
    with c.directory(path):pass
    return path
def save_json(path,value,replace=False):c.write_private(Path(path),f.canonical(value),replace=replace)
def load_json(path):return f.decode(c.read_private(Path(path)))
def crypt(raw,key,aad,decrypt=False):
    """Existing libsodium XChaCha20-Poly1305 binding, fresh 192-bit nonce."""
    if len(key)!=32:raise ValueError('key')
    lib=f.sodium();size=ctypes.c_ulonglong()
    if decrypt:
        if not 44<=len(raw)<=MAX_CIPHER or raw[:4]!=b'PN01':raise ValueError('ciphertext frame')
        nonce=raw[4:28];body=raw[28:];out=ctypes.create_string_buffer(len(body))
        if lib.crypto_aead_xchacha20poly1305_ietf_decrypt(out,ctypes.byref(size),None,body,len(body),aad,len(aad),nonce,key):raise ValueError('integrity verification failed')
        return out.raw[:size.value]
    if not 0<len(raw)<=MAX_PLAIN:raise ValueError('file bound')
    nonce=os.urandom(24);out=ctypes.create_string_buffer(len(raw)+16)
    if lib.crypto_aead_xchacha20poly1305_ietf_encrypt(out,ctypes.byref(size),raw,len(raw),aad,len(aad),None,nonce,key):raise ValueError('encryption failed')
    return b'PN01'+nonce+out.raw[:size.value]
def aad(provider,quote):return f.canonical(dict(protocol='PC-resource-v01',provider=provider,quote=quote))
def call(port,command,bearer=None,**fields):
    f.integer(port,1024,65535);headers={'Content-Type':'application/json'}
    if bearer is not None:headers['Authorization']='Bearer '+identity(bearer)
    connection=http.client.HTTPConnection('127.0.0.1',port,timeout=40)
    try:
        connection.request('POST','/'+command,body=f.canonical(fields),headers=headers)
        reply=connection.getresponse();raw=reply.read(2*MAX_CIPHER+8193)
        if len(raw)>2*MAX_CIPHER+8192:raise ValueError('response bound')
        result=f.decode(raw)
        if reply.status!=200 or result.get('ok') is not True:raise ValueError(result.get('code','PROVIDER_REJECTED'))
        return result['result']
    finally:connection.close()
def encode(raw):return base64.b64encode(raw).decode('ascii')
def decode(value):
    if not isinstance(value,str) or len(value)>2*MAX_CIPHER:raise ValueError('ciphertext bound')
    return base64.b64decode(value,validate=True)
