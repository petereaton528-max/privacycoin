"""Phase 2 development wallet; no transaction construction or chain balance.

Secret-bearing helper pipes and Python objects are private process memory, never
evidence. Python cannot guarantee erasure of immutable objects: see WALLET.md.
"""
from pathlib import Path
import argparse
import ctypes as c
import ctypes.util
import getpass
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / ('build/monero-windows/phase2/privacycoin-wallet-crypto.exe' if os.name=='nt' else 'build/monero-linux/phase2/privacycoin-wallet-crypto')
MAX_FILE = 4 * 1024 * 1024
HEADER = bytes([1, 1, 1, 1, 1])  # envelope, devnet, address, ownership, viewing

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()

def unique(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError('duplicate field')
        result[k] = v
    return result

def decode(raw):
    if len(raw) > MAX_FILE:
        raise ValueError('file too large')
    return json.loads(raw, object_pairs_hook=unique)

def fields(obj, names):
    if not isinstance(obj, dict) or set(obj) != set(names.split()):
        raise ValueError('invalid fields')

def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('integer bounds')
    return value

def unhex(value, size):
    if not isinstance(value, str) or len(value) != size * 2 or any(x not in '0123456789abcdef' for x in value):
        raise ValueError('invalid canonical hex')
    return bytes.fromhex(value)

def crypto(op, *args):
    # Secrets never enter argv/environment, errors, or log files.
    p = subprocess.run([str(HELPER)], input=(' '.join([op] + [str(x) for x in args]) + '\n').encode(),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if p.returncode:
        raise ValueError('cryptographic request rejected')
    return p.stdout.decode().strip().split()

def address(w, index):
    integer(index, 0, 9999)
    D, C = crypto('address', w['view'], w['public'], index)
    payload = HEADER + bytes([int(index != 0)]) + bytes.fromhex(D + C)
    checksum = bytes.fromhex(crypto('hash', payload.hex())[0])[:4]
    return 'PCdv1-' + (payload + checksum).hex()

def parse_address(text):
    if not isinstance(text, str) or not text.startswith('PCdv1-'):
        raise ValueError('unsupported address namespace')
    raw = unhex(text[6:], 74)
    if raw[:5] != HEADER or raw[5] not in (0, 1):
        raise ValueError('unsupported network or scheme')
    if raw[-4:] != bytes.fromhex(crypto('hash', raw[:-4].hex())[0])[:4]:
        raise ValueError('address checksum')
    D, C = raw[6:38].hex(), raw[38:70].hex()
    crypto('check', D); crypto('check', C)
    return D, C, raw[5]

def full(seed=None, count=2):
    seed = os.urandom(32).hex() if seed is None else seed
    unhex(seed, 32)
    if not any(bytes.fromhex(seed)):
        raise ValueError('zero recovery seed')
    b, a, B, A = crypto('derive', seed)
    return validate(dict(version=1, network='privacycoin-devnet', schemes=[1, 1, 1],
                         authority='full', seed=seed, view=a, public=B, count=count, outputs=[]))

def wallet_id(w):
    return hashlib.sha256(b'PrivacyCoin/wallet-id/v1/devnet/' + bytes.fromhex(w['public']) +
                          bytes.fromhex(crypto('address', w['view'], w['public'], 0)[1])).hexdigest()

def validate(w):
    fields(w, 'version network schemes authority seed view public count outputs')
    if type(w['version']) is not int or w['version'] != 1 or w['network'] != 'privacycoin-devnet' or \
            w['schemes'] != [1, 1, 1] or any(type(x) is not int for x in w['schemes']):
        raise ValueError('unsupported wallet network/version/scheme')
    integer(w['count'], 1, 10000)
    unhex(w['view'], 32); unhex(w['public'], 32)
    crypto('address', w['view'], w['public'], 0)
    if w['authority'] == 'full':
        unhex(w['seed'], 32)
        if not any(bytes.fromhex(w['seed'])):
            raise ValueError('zero recovery seed')
        _, a, B, _ = crypto('derive', w['seed'])
        if a != w['view'] or B != w['public']:
            raise ValueError('inconsistent recovery keys')
    elif w['authority'] != 'view' or w['seed'] is not None:
        raise ValueError('invalid authority')
    if not isinstance(w['outputs'], list) or len(w['outputs']) > 10000:
        raise ValueError('output bounds')
    seen = set()
    for o in w['outputs']:
        check_output(o)
        if owner(w, o) < 0 or output_id(o) in seen:
            raise ValueError('invalid wallet cache')
        seen.add(output_id(o))
    return w

def view_export(w):
    result = dict(w, authority='view', seed=None, outputs=[])
    return validate(result)

def check_output(o):
    fields(o, 'version network ownership viewing R P index amount')
    if type(o['version']) is not int or o['version'] != 1 or o['network'] != 'privacycoin-devnet' or \
            type(o['ownership']) is not int or o['ownership'] != 1 or type(o['viewing']) is not int or o['viewing'] != 1:
        raise ValueError('unsupported output scheme/network')
    unhex(o['R'], 32); unhex(o['P'], 32)
    integer(o['index'], 0, 10000); integer(o['amount'], 1, 2**63-1)
    crypto('check', o['R']); crypto('check', o['P'])

def output_id(o):
    # Amount is intentionally untrusted fixture metadata, not value consensus.
    return hashlib.sha256(canonical({k: o[k] for k in ('R', 'P', 'index')})).hexdigest()

def output(destination, amount, index=0):
    D, C, sub = parse_address(destination)
    integer(index, 0, 10000); integer(amount, 1, 2**63-1)
    R, P = crypto('output', D, C, sub, index)
    return dict(version=1, network='privacycoin-devnet', ownership=1, viewing=1,
                R=R, P=P, index=index, amount=amount)

def owner(w, o):
    check_output(o)
    return int(crypto('scan', w['view'], w['public'], w['count'], o['R'], o['P'], o['index'])[0])

def scan(w, outputs):
    if not isinstance(outputs, list) or len(outputs) > 10000:
        raise ValueError('fixture bounds')
    seen = {output_id(o) for o in w['outputs']}
    for o in outputs:
        if owner(w, o) >= 0 and output_id(o) not in seen:
            w['outputs'].append(o); seen.add(output_id(o))
    return summary(w)

def prove(w, o):
    if w['authority'] != 'full' or w['seed'] is None:
        raise ValueError('spending authority unavailable')
    check_output(o)
    b = crypto('derive', w['seed'])[0]
    return crypto('prove', w['view'], w['public'], w['count'], o['R'], o['P'], o['index'], b)[0]

def summary(w):
    return dict(wallet_id=wallet_id(w), authority=w['authority'], address_count=w['count'],
                detected_outputs=len(w['outputs']), detected_fixture_amount=sum(o['amount'] for o in w['outputs']),
                spendable_balance=None, schemes=w['schemes'])

# Fixed algorithm parameters; untrusted headers cannot request arbitrary KDF cost.
# Argon2id v1.3, 3 operations, 64 MiB. XChaCha20-Poly1305 with random 192-bit nonce.
SODIUM = None
def sodium():
    global SODIUM
    if SODIUM is None:
        bundled = ROOT / ('runtime/lib/libsodium-26.dll' if os.name=='nt' else 'runtime/lib/libsodium.so.23')
        if bundled.exists() or bundled.is_symlink():
            if bundled.is_symlink() or not bundled.is_file():raise ValueError('unsafe bundled libsodium')
            name = str(bundled)
        elif os.name=='nt':raise ValueError('bundled Windows libsodium required')
        else:name = ctypes.util.find_library('sodium')
        if not name:
            raise ValueError('libsodium unavailable')
        # Windows loads only the deliberate runtime directory and System32,
        # never the current directory or PATH for cryptographic dependencies.
        SODIUM = c.CDLL(name,winmode=0x100|0x800) if os.name=='nt' else c.CDLL(name)
        SODIUM.sodium_init.restype = c.c_int
        if SODIUM.sodium_init() < 0:
            raise ValueError('libsodium initialization')
        SODIUM.crypto_pwhash.argtypes = [c.c_void_p, c.c_ulonglong, c.c_void_p, c.c_ulonglong,
                                        c.c_void_p, c.c_ulonglong, c.c_size_t, c.c_int]
        SODIUM.crypto_aead_xchacha20poly1305_ietf_encrypt.argtypes = [c.c_void_p, c.POINTER(c.c_ulonglong),
            c.c_void_p, c.c_ulonglong, c.c_void_p, c.c_ulonglong, c.c_void_p, c.c_void_p, c.c_void_p]
        SODIUM.crypto_aead_xchacha20poly1305_ietf_decrypt.argtypes = [c.c_void_p, c.POINTER(c.c_ulonglong),
            c.c_void_p, c.c_void_p, c.c_ulonglong, c.c_void_p, c.c_ulonglong, c.c_void_p, c.c_void_p]
        SODIUM.sodium_memzero.argtypes = [c.c_void_p, c.c_size_t]
    return SODIUM

def key(password, salt):
    if not isinstance(password, bytes) or not 12 <= len(password) <= 1024:
        raise ValueError('password must be 12..1024 bytes')
    result = c.create_string_buffer(32)
    if sodium().crypto_pwhash(result, 32, password, len(password), salt, 3, 64*1024*1024, 2):
        raise ValueError('password derivation failed')
    return result

def seal(obj, password, kind):
    header = dict(format='PrivacyCoinEncrypted', version=1, network='privacycoin-devnet', kind=kind,
                  kdf='argon2id13-3-64MiB', aead='xchacha20poly1305-ietf',
                  salt=os.urandom(16).hex(), nonce=os.urandom(24).hex())
    aad = canonical(header); plain = canonical(obj)
    k = key(password, bytes.fromhex(header['salt']))
    result = c.create_string_buffer(len(plain)+16); size = c.c_ulonglong()
    try:
        if sodium().crypto_aead_xchacha20poly1305_ietf_encrypt(result, c.byref(size), plain, len(plain),
                aad, len(aad), None, bytes.fromhex(header['nonce']), k):
            raise ValueError('encryption failed')
        encoded = canonical(dict(header, ciphertext=result.raw[:size.value].hex()))
        if len(encoded) > MAX_FILE:
            raise ValueError('encrypted wallet exceeds file bound')
        return encoded
    finally:
        sodium().sodium_memzero(k, 32)

def open_sealed(raw, password, kind):
    obj = decode(raw)
    fields(obj, 'format version network kind kdf aead salt nonce ciphertext')
    if obj['format'] != 'PrivacyCoinEncrypted' or type(obj['version']) is not int or obj['version'] != 1 or \
            obj['network'] != 'privacycoin-devnet' or obj['kind'] != kind or \
            obj['kdf'] != 'argon2id13-3-64MiB' or obj['aead'] != 'xchacha20poly1305-ietf':
        raise ValueError('unsupported encrypted envelope')
    salt = unhex(obj['salt'], 16); nonce = unhex(obj['nonce'], 24)
    ciphertext = obj.pop('ciphertext')
    if not isinstance(ciphertext, str) or not 32 <= len(ciphertext) <= MAX_FILE:
        raise ValueError('ciphertext bounds')
    ciphertext = unhex(ciphertext, len(ciphertext)//2)
    aad = canonical(obj); k = key(password, salt)
    result = c.create_string_buffer(len(ciphertext)); size = c.c_ulonglong()
    try:
        if sodium().crypto_aead_xchacha20poly1305_ietf_decrypt(result, c.byref(size), None,
                ciphertext, len(ciphertext), aad, len(aad), nonce, k):
            raise ValueError('wrong password or corrupt encrypted file')
        return decode(result.raw[:size.value])
    finally:
        sodium().sodium_memzero(k, 32); sodium().sodium_memzero(result, len(result))

def read_private(path):
    if os.name != 'posix':
        raise ValueError('secure file access currently requires POSIX; Windows ACL review pending')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077 or s.st_size > MAX_FILE:
            raise ValueError('private file owner/permissions/size')
        with os.fdopen(fd, 'rb', closefd=False) as f:
            return f.read(MAX_FILE + 1)
    finally:
        os.close(fd)

def write_private(path, raw, replace=False, fault=None):
    if os.name != 'posix':
        raise ValueError('secure persistence currently requires POSIX; Windows ACL review pending')
    path = Path(path); path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    # Require a private native directory. Do not trust /mnt/d permission emulation.
    parent = path.parent.stat()
    if path.parent.is_symlink() or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
        raise ValueError('wallet directory must be private (0700)')
    if path.exists() or path.is_symlink():
        if not replace:
            raise ValueError('refusing to overwrite existing file')
        read_private(path)
    fd, temp = tempfile.mkstemp(prefix='.pcwallet-', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(raw); f.flush(); os.fsync(f.fileno())
        if fault:
            fault('before_publish')
        if replace:
            os.replace(temp, path)
        else:
            os.link(temp, path)  # atomic no-clobber creation
            os.unlink(temp)
        if fault:
            fault('after_publish')
        d = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)

def save(path, w, password, replace=False, fault=None):
    validate(w); write_private(path, seal(w, password, 'wallet'), replace, fault)

def load(path, password):
    return validate(open_sealed(read_private(path), password, 'wallet'))

def recovery(w):
    if w['authority'] != 'full':
        raise ValueError('view capability cannot export full recovery')
    return dict(format='PrivacyCoinRecovery', version=1, network=w['network'], schemes=w['schemes'],
                seed=w['seed'], count=w['count'])

def restore(r):
    fields(r, 'format version network schemes seed count')
    if r['format'] != 'PrivacyCoinRecovery' or type(r['version']) is not int or r['version'] != 1 or \
            r['network'] != 'privacycoin-devnet' or r['schemes'] != [1, 1, 1] or any(type(x) is not int for x in r['schemes']):
        raise ValueError('unsupported recovery')
    return full(r['seed'], r['count'])

def main():
    if os.name != 'posix':
        raise ValueError('authorized wallet runtime is native WSL POSIX; Windows ACL review pending')
    p = argparse.ArgumentParser(description='Privacy Coin Phase 2 development wallet; fixture amounts are not spendable funds')
    p.add_argument('command', choices=['create', 'address', 'balance', 'backup', 'restore', 'view-export', 'view-import',
                                      'fixture-output', 'scan', 'ownership-proof'])
    p.add_argument('--wallet', type=Path); p.add_argument('--password-file', type=Path)
    p.add_argument('--export-password-file', type=Path, help='separate view-capability password; otherwise prompted')
    p.add_argument('--file', type=Path); p.add_argument('--destination'); p.add_argument('--index', type=int)
    p.add_argument('--amount', type=int, default=1)
    args = p.parse_args()
    if args.command == 'fixture-output':
        o = output(args.destination, args.amount, args.index or 0)
        if not args.file:
            raise ValueError('--file required')
        # Public development fixture, no sender randomness or wallet secrets.
        with args.file.open('x', encoding='utf-8') as f:
            json.dump([o], f, sort_keys=True)
        print(json.dumps(dict(result='created public development fixture'))); return
    if not args.wallet:
        raise ValueError('--wallet required')
    password = read_private(args.password_file).rstrip(b'\r\n') if args.password_file else getpass.getpass('Wallet/backup password (at least 12 bytes): ').encode()
    # Serialize all stateful operations; view delegation has a separate password.
    import fcntl
    args.wallet.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    directory = args.wallet.parent.stat()
    if args.wallet.parent.is_symlink() or directory.st_uid != os.getuid() or directory.st_mode & 0o077:
        raise ValueError('wallet directory must be private (0700)')
    lock_path = args.wallet.with_name(args.wallet.name+'.lock')
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.command == 'create':
            w = full(); save(args.wallet, w, password)
        elif args.command == 'restore':
            w = restore(open_sealed(read_private(args.file), password, 'recovery')); save(args.wallet, w, password)
        elif args.command == 'view-import':
            w = validate(open_sealed(read_private(args.file), password, 'view'))
            if w['authority'] != 'view':
                raise ValueError('not a view capability')
            save(args.wallet, w, password)
        else:
            w = load(args.wallet, password)
            if args.command == 'address':
                n = w['count'] if args.index is None else integer(args.index, 0, 9999)
                integer(n, 0, 9999); w['count'] = max(w['count'], n+1)
                result = address(w, n); save(args.wallet, w, password, True)
                print(json.dumps(dict(address=result, index=n))); return
            if args.command == 'backup':
                write_private(args.file, seal(recovery(w), password, 'recovery'))
            elif args.command == 'view-export':
                export_password = read_private(args.export_password_file).rstrip(b'\r\n') if args.export_password_file else \
                    getpass.getpass('Separate view capability password (at least 12 bytes): ').encode()
                if export_password == password:
                    raise ValueError('view delegation requires a separate password')
                write_private(args.file, seal(view_export(w), export_password, 'view'))
            elif args.command == 'scan':
                scan(w, decode(args.file.read_bytes())); save(args.wallet, w, password, True)
            elif args.command == 'ownership-proof':
                fixtures = decode(args.file.read_bytes())
                if not fixtures:
                    raise ValueError('output required')
                print(json.dumps(dict(ownership_proof=prove(w, fixtures[0]), transaction_created=False))); return
        print(json.dumps(summary(w), sort_keys=True))
    finally:
        os.close(lock_fd)

if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, TypeError, KeyError, subprocess.SubprocessError):
        # Never interpolate untrusted/secret objects into errors.
        print('wallet operation rejected (check format, authority, password, permissions and paths)', file=sys.stderr)
        sys.exit(1)
