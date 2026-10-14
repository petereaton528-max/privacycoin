"""Bounded loopback wire adapter. Public callers cannot select RPC commands."""
import json
import socket
import struct

from src.network_identity import NETWORK, GENESIS, PROFILE
VERSION = '1.0.0-dev02-preview.2' if NETWORK=='PrivacyCoinDev02' else '1.0.0-testnet-candidate.5'


def unique(items):
    d = {}
    for k, v in items:
        if k in d:
            raise ValueError('DUPLICATE_JSON')
        d[k] = v
    return d


def rpc(port, command, *, control=False, **fields):
    allowed = {'status', 'chain', 'inventory', 'get_block', 'pool'}
    if control:
        allowed |= {'template', 'submit', 'stop_mining'}
    if command not in allowed or type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('RPC_DENIED')
    raw = json.dumps(dict(network=NETWORK, genesis=GENESIS, profile=PROFILE,
                          command=command, **fields), separators=(',', ':')).encode()
    def read(s, n):
        data = b''
        while len(data) < n:
            part = s.recv(n - len(data))
            if not part:
                raise ValueError('TRUNCATED_RPC')
            data += part
        return data
    with socket.create_connection(('127.0.0.1', port), timeout=8) as s:
        magic = b'PrivacyCoinRPC04'
        s.sendall(magic + struct.pack('>I', len(raw)) + raw)
        header = read(s, 20)
        size = struct.unpack('>I', header[16:])[0]
        if header[:16] != magic or not 0 < size <= 1048576:
            raise ValueError('RPC_FRAME')
        v = json.loads(read(s, size), object_pairs_hook=unique)
    if not isinstance(v, dict) or 'error' in v or any(v.get(k) != x for k, x in
            [('network', NETWORK), ('genesis', GENESIS), ('profile', PROFILE)]):
        raise ValueError('RPC_REJECTED_OR_WRONG_NETWORK')
    return v
