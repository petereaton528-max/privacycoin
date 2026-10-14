"""Optional explicit Tor upstream; adapted from the reviewed acceptance route guard.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import ipaddress,socket

def validate(value):
    if not isinstance(value,dict) or set(value)!={'host','port'} or not isinstance(value['host'],str):raise ValueError('UPSTREAM_SCHEMA')
    address=ipaddress.ip_address(value['host'])
    if not (address.is_loopback or address.is_private) or address.is_unspecified or address.is_multicast:raise ValueError('UPSTREAM_PRIVATE_IP_REQUIRED')
    if type(value['port']) is not int or not 1024<=value['port']<=65535:raise ValueError('UPSTREAM_PORT')
    return dict(host=str(address),port=value['port'])

def directive(value):
    value=validate(value);host=value['host']
    return 'Socks5Proxy '+('['+host+']' if ':' in host else host)+':'+str(value['port'])

def probe(value):
    """Local handshake only: no external target, no credentials, no fallback."""
    value=validate(value)
    with socket.create_connection((value['host'],value['port']),timeout=2) as stream:
        stream.settimeout(2);stream.sendall(b'\x05\x01\x00');data=b''
        while len(data)<2:
            part=stream.recv(2-len(data))
            if not part:raise ValueError('UPSTREAM_EOF')
            data+=part
        if data!=b'\x05\x00':raise ValueError('UPSTREAM_NO_AUTH_SOCKS5_REQUIRED')
