"""Public copy/paste bootstrap hint; contains no wallet or admission credential.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
from urllib.parse import urlsplit,parse_qs
from .rpc import NETWORK,GENESIS,PROFILE
from .onion import descriptor

def parse(value):
    if not isinstance(value,str) or len(value)>512 or any(c.isspace() for c in value):raise ValueError('PUBLIC_PEER_LINK')
    uri=urlsplit(value)
    query=parse_qs(uri.query,strict_parsing=True)
    if uri.scheme!='pcnode' or uri.path or uri.fragment or uri.username or uri.password or uri.port or set(query)!={'pin','network'} or any(len(v)!=1 for v in query.values()) or query['network'][0]!=NETWORK:raise ValueError('PUBLIC_PEER_NETWORK_LINK')
    return descriptor(dict(version=1,network=NETWORK,genesis=GENESIS,profile=PROFILE,onion=uri.hostname,certificate_sha256=query['pin'][0]))

def format_link(value):
    value=descriptor(value)
    return 'pcnode://'+value['onion']+'?pin='+value['certificate_sha256']+'&network='+NETWORK
