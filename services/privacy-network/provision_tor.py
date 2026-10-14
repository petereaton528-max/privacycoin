"""Extract authenticated official Ubuntu or Tor Project packages into NEW data.

No sudo, package installation, service activation or downloaded script execution.
Run only on Ubuntu 24.04 amd64. Fresh metadata stays in the new private target.
"""
import argparse,hashlib,json,pathlib,re,subprocess,urllib.request,os,datetime,email.utils,lzma,stat
import platform,shutil
from tor_policy import require_current,version_policy

ORIGIN='https://archive.ubuntu.com/ubuntu/'
KEYRING='/usr/share/keyrings/ubuntu-archive-keyring.gpg'
TOR_ORIGIN='https://deb.torproject.org/torproject.org/'
# Published by https://support.torproject.org/little-t-tor/getting-started/installing/
TOR_FINGERPRINT='A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89'

def fetch(url,limit,origin=ORIGIN):
    if not url.startswith(origin):raise RuntimeError('Unexpected archive URL')
    with urllib.request.urlopen(url,timeout=45) as response:
        if not response.geturl().startswith(origin):raise RuntimeError('Unexpected archive redirect')
        raw=response.read(limit+1)
    if len(raw)>limit:raise RuntimeError('Archive download bound')
    return raw

def authenticate(release,keyring=KEYRING):
    verified=subprocess.run(['gpgv','--keyring',str(keyring),str(release)],capture_output=True,timeout=10)
    if verified.returncode:raise RuntimeError('Ubuntu archive signature verification failed')
    text=release.read_text();date=re.search(r'^Date: (.+)$',text,re.M);valid=re.search(r'^Valid-Until: (.+)$',text,re.M);now=datetime.datetime.now(datetime.timezone.utc)
    if not date or not -86400<=(now-email.utils.parsedate_to_datetime(date[1])).total_seconds()<=7*86400:raise RuntimeError('APT metadata is stale or future-dated')
    if valid and now>email.utils.parsedate_to_datetime(valid[1]):raise RuntimeError('APT metadata expired')
    return verified,text

def private_target(destination):
    # A new destination beneath existing trusted directories. Never traverse a
    # symlink or a directory writable by another user; do not modify system APT.
    if os.name!='posix' or not destination.is_absolute() or '..' in destination.parts:raise RuntimeError('Absolute POSIX destination required')
    for parent in reversed(destination.parents):
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,os.getuid()) or info.st_mode&0o022:raise RuntimeError('Unsafe destination ancestor')
    destination.mkdir(mode=0o700,exist_ok=False)

def fresh_metadata(destination):
    release=destination/'InRelease'
    release.write_bytes(fetch(ORIGIN+'dists/noble-updates/InRelease',1024*1024))
    _,text=authenticate(release)
    match=re.search(r'^ ([0-9a-f]{64})\s+(\d+) universe/binary-amd64/Packages.xz$',text,re.M)
    if not match or int(match[2])>32*1024*1024:raise RuntimeError('Signed compressed index missing or too large')
    raw=fetch(ORIGIN+'dists/noble-updates/universe/binary-amd64/Packages.xz',32*1024*1024)
    if len(raw)!=int(match[2]) or hashlib.sha256(raw).hexdigest()!=match[1]:raise RuntimeError('Signed compressed-index hash mismatch')
    decoder=lzma.LZMADecompressor(memlimit=128*1024*1024)
    data=decoder.decompress(raw,max_length=128*1024*1024+1)
    if len(data)>128*1024*1024 or not decoder.eof or decoder.unused_data:raise RuntimeError('Package-index decompression bound or framing')
    packages=destination/'Packages';packages.write_bytes(data)
    return release,packages

def project_metadata(destination):
    """Pin the official repository primary key in an isolated public keyring.

    No personal GPG home, system keyring, APT sources or running Tor is modified.
    Key rotation fails closed and requires a reviewed publisher-pin update.
    """
    key=destination/'archive-key.asc';key.write_bytes(fetch(TOR_ORIGIN+TOR_FINGERPRINT+'.asc',128*1024,TOR_ORIGIN))
    home=destination/'gpg';home.mkdir(mode=0o700)
    command=['gpg','--batch','--no-options','--homedir',str(home)]
    result=subprocess.run(command+['--with-colons','--show-keys',str(key)],capture_output=True,timeout=10)
    if result.returncode:raise RuntimeError('Tor archive key parsing failed')
    primary=[];expect=False
    for line in result.stdout.decode('ascii').splitlines():
        fields=line.split(':')
        if fields[0]=='pub':expect=True
        elif fields[0]=='fpr' and expect:primary.append(fields[9]);expect=False
    if primary!=[TOR_FINGERPRINT]:raise RuntimeError('Tor archive primary-key fingerprint mismatch')
    keyring=destination/'archive-key.gpg'
    result=subprocess.run(command+['--dearmor','--output',str(keyring),str(key)],capture_output=True,timeout=10)
    if result.returncode:raise RuntimeError('Tor archive keyring preparation failed')
    release=destination/'InRelease';release.write_bytes(fetch(TOR_ORIGIN+'dists/noble/InRelease',1024*1024,TOR_ORIGIN))
    _,text=authenticate(release,keyring)
    match=re.search(r'^ ([0-9a-f]{64})\s+(\d+) main/binary-amd64/Packages$',text,re.M)
    if not match or int(match[2])>1024*1024:raise RuntimeError('Tor signed index missing or too large')
    data=fetch(TOR_ORIGIN+'dists/noble/main/binary-amd64/Packages',1024*1024,TOR_ORIGIN)
    if len(data)!=int(match[2]) or hashlib.sha256(data).hexdigest()!=match[1]:raise RuntimeError('Tor signed index hash mismatch')
    packages=destination/'Packages';packages.write_bytes(data)
    return release,packages,keyring

def provision(destination,refresh=False,source='ubuntu'):
    if source not in ('ubuntu','torproject'):raise RuntimeError('Unknown archive source')
    system=dict(line.split('=',1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if system.get('ID','').strip('"')!='ubuntu' or system.get('VERSION_ID','').strip('"')!='24.04' or platform.machine()!='x86_64':raise RuntimeError('Provisioning supports Ubuntu 24.04 amd64 only')
    destination=pathlib.Path(destination)
    if shutil.disk_usage(destination.parent).free<128*1024*1024:raise RuntimeError('Tor provisioning requires 128MiB free disk space')
    private_target(destination)
    release=pathlib.Path('/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_noble-updates_InRelease')
    packages=pathlib.Path('/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_noble-updates_universe_binary-amd64_Packages')
    origin=ORIGIN;component='universe';keyring=KEYRING
    if source=='torproject':
        release,packages,keyring=project_metadata(destination);origin=TOR_ORIGIN;component='main'
    elif refresh:release,packages=fresh_metadata(destination)
    verified,text=authenticate(release,keyring)
    data=packages.read_bytes();match=re.search(r'^ ([0-9a-f]{64})\s+(\d+) '+component+r'/binary-amd64/Packages$',text,re.M)
    if not match or len(data)!=int(match[2]) or hashlib.sha256(data).hexdigest()!=match[1]:raise RuntimeError('Signed package-index hash mismatch')
    candidates=[]
    for paragraph in data.decode().split('\n\n'):
        fields=dict(line.split(': ',1) for line in paragraph.splitlines() if ': ' in line and not line.startswith(' '))
        if fields.get('Package')=='tor' and fields.get('Architecture')=='amd64':candidates.append(fields)
    if len(candidates)!=1:raise RuntimeError('Ambiguous Tor package selection')
    pkg=candidates[0];relative=pkg['Filename']
    if not 0<int(pkg.get('Installed-Size','0'))<=64*1024:raise RuntimeError('Tor installed-size bound')
    # Refuse known outdated upstream releases BEFORE downloading/executing them.
    upstream=pkg['Version'].split(':')[-1].split('-')[0]
    version_policy('Tor version '+upstream+'.')
    if not re.fullmatch('pool/'+component+r'/t/tor/[A-Za-z0-9.+~_-]+\.deb',relative):raise RuntimeError('Unexpected package location')
    url=origin+relative
    raw=fetch(url,8*1024*1024,origin)
    if len(raw)!=int(pkg['Size']) or hashlib.sha256(raw).hexdigest()!=pkg['SHA256']:raise RuntimeError('Tor package digest mismatch')
    archive=destination/'tor.deb';archive.write_bytes(raw)
    subprocess.run(['dpkg-deb','-x',str(archive),str(destination/'root')],check=True,timeout=10)
    binary=destination/'root/usr/bin/tor'
    dependencies=subprocess.run(['ldd',str(binary)],capture_output=True,text=True,check=True,timeout=10).stdout
    if 'not found' in dependencies:raise RuntimeError('Missing native dependencies; no system changes performed')
    version=require_current(binary)
    result=dict(source=url,version=version,package_sha256=pkg['SHA256'],index_sha256=match[1],release_sha256=hashlib.sha256(release.read_bytes()).hexdigest(),signature=verified.stderr.decode(),dependencies=dependencies,archive=source,primary_key_pin=TOR_FINGERPRINT if source=='torproject' else 'installed Ubuntu archive keyring',binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),public_network_activated=False)
    with os.fdopen(os.open(destination/'provenance.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as stream:stream.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    return binary

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('destination');parser.add_argument('--refresh-metadata',action='store_true',help='Fetch signed metadata into the NEW destination; never change system APT state')
    parser.add_argument('--source',choices=['ubuntu','torproject'],default='ubuntu',help='Official archive only; torproject always fetches fresh pinned-key metadata')
    args=parser.parse_args();provision(args.destination,args.refresh_metadata,args.source)
