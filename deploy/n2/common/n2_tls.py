"""Separate operator TLS identities; public-only, explicitly pinned enrollment."""
from pathlib import Path
import argparse,hashlib,json,ssl,subprocess,time
import role
if __name__=='__main__':role.bootstrap()
from common import c,f,private_dir,save_json,load_json
from role import checked_path

def sha(raw):return hashlib.sha256(raw).hexdigest()
def certificate(raw):
    if b'PRIVATE KEY' in raw or raw.count(b'BEGIN CERTIFICATE')!=1:raise ValueError('PUBLIC_CERTIFICATE_ONLY')
    return ssl.PEM_cert_to_DER_cert(raw.decode('ascii'))
def generate(home,purpose):
    home=checked_path(str(home))
    if purpose not in ('p2p','resource') or home.exists():raise ValueError('NEW_IDENTITY_REQUIRED')
    private_dir(home)
    args=['openssl','req','-x509','-newkey','rsa:3072','-nodes','-keyout',str(home/'own.key'),'-out',str(home/'own.pem'),'-days','30','-subj','/CN=PN-N2-'+purpose,'-addext','subjectAltName=DNS:pcp2p.local','-addext','extendedKeyUsage=serverAuth,clientAuth','-addext','basicConstraints=critical,CA:TRUE']
    subprocess.run(args,check=True,capture_output=True,timeout=30)
    for p in home.iterdir():p.chmod(0o600)
    raw=c.read_private(home/'own.pem');pin=sha(certificate(raw))
    save_json(home/'public.json',dict(version=1,purpose=purpose,sha256=pin,certificate=raw.decode('ascii')))
    return pin
def enroll(home,public,expected,purpose):
    with c.directory(home):pass
    # Public transfer may be on USB: bounded no-symlink regular-file read.
    p=checked_path(str(public))
    if not p.is_file() or p.stat().st_size>16384:raise ValueError('PUBLIC_FILE_BOUND')
    record=f.decode(p.read_bytes());f.fields(record,'version purpose sha256 certificate')
    if type(record['version']) is not int or record['version']!=1 or record['purpose']!=purpose:raise ValueError('PURPOSE')
    f.unhex(expected,32);raw=record['certificate'].encode('ascii')
    if sha(certificate(raw))!=expected or record['sha256']!=expected:raise ValueError('OUT_OF_BAND_PIN_MISMATCH')
    c.write_private(home/'peer.pem',raw) # immutable; pin rotation is explicit new identity directory
    save_json(home/'peer.json',dict(purpose=purpose,sha256=expected))
def channel(home,role,listen,target,endpoint='127.0.0.1',socks=None,purpose=None):
    import p2p_channel as pc
    peer=load_json(home/'peer.json')
    if peer['purpose']!=load_json(home/'public.json')['purpose']:raise ValueError('IDENTITY_PURPOSE_MISMATCH')
    if purpose is not None and peer['purpose']!=purpose:raise ValueError('CHANNEL_PURPOSE_MISMATCH')
    value=dict(version=1,role=role,listen_port=listen,target_port=target,endpoint=endpoint,socks_port=socks,cert=str(home/'own.pem'),key=str(home/'own.key'),ca=str(home/'peer.pem'),peer_sha256=peer['sha256'])
    pc.validate(value);pc.context(value);return value

def verify_identity(home,purpose):
    own=load_json(home/'public.json');peer=load_json(home/'peer.json')
    if own['purpose']!=purpose or peer['purpose']!=purpose:raise ValueError('PURPOSE')
    for name,record in (('own',own),('peer',peer)):
        raw=c.read_private(home/(name+'.pem'))
        if sha(certificate(raw))!=record['sha256']:raise ValueError('CERTIFICATE_PIN_CHANGED')
        # Validate expiry, purpose and expected SAN using installed OpenSSL.
        for usage in ('sslclient','sslserver'):
            args=['openssl','verify','-CAfile',str(home/(name+'.pem')),'-purpose',usage]
            if usage=='sslserver':args+=['-verify_hostname','pcp2p.local']
            subprocess.run(args+[str(home/(name+'.pem'))],check=True,capture_output=True,timeout=10)
    channel(home,'acceptor',19510,19480,purpose=purpose) # private key/cert correspondence, no listener
def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=['generate','enroll','verify']);p.add_argument('--home',type=Path,required=True);p.add_argument('--purpose',choices=['p2p','resource'],required=True);p.add_argument('--public',type=Path);p.add_argument('--expect-sha256');a=p.parse_args();c.harden()
    if a.action=='generate':print('PUBLIC CERTIFICATE SHA256',generate(a.home,a.purpose))
    elif a.action=='enroll':enroll(a.home,a.public,a.expect_sha256,a.purpose);print('Public peer certificate pinned; private keys were not transferred.')
    else:verify_identity(a.home,a.purpose);print('Local identities: pins, expiry, TLS purposes, SAN, permissions and key correspondence checked. No connection made.')
if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('TLS operation rejected; no existing identity overwritten. Check public pin, purpose, private paths and OpenSSL.')
