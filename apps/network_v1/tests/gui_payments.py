"""Actual GUI/private-pipe/native two-node payments over a local SOCKS fixture.
No Tor process or Internet access. Test identities and wallets are disposable.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import hashlib,os,secrets,socket,ssl,subprocess,sys,time
from pathlib import Path
from unittest.mock import patch

def exercise(app,pump,home,rpc,p2p):
    from apps.network_v1.desktop_backend import Session,f,c,ROOT
    from apps.network_v1.public_network import PeerService
    from apps.network_v1.onion import openssl_binary
    from apps.network_v1.tests.test_public_network import descriptor
    from .local_socks import Socks
    home=Path(home)/'gui-network-fixture';home.mkdir(mode=0o700)
    def port():
        with socket.socket() as stream:stream.bind(('127.0.0.1',0));return stream.getsockname()[1]
    def wait(fn):
        end=time.monotonic()+90
        while time.monotonic()<end:
            try:
                value=fn()
                if value:return value
            except (OSError,ValueError):pass
            app.root.update();time.sleep(.02)
        raise TimeoutError('GUI_NATIVE_NETWORK_BOUND')
    node=None;wallet=None;socks=None;services=[];checks=[]
    try:
        brpc,bp2p=port(),port();base=rpc+30
        args=[str(ROOT/'build/monero-linux/phase4/privacycoin-hardened-devnet'),'--data-dir',str(home/'B-node'),'--rpc-port',str(brpc),'--p2p-port',str(bp2p),'--development-network','open-dev02']
        for n in range(base,base+8):args+=['--peer-port',str(n)]
        node=subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        wait(lambda:c.w.rpc(brpc,'status'))
        wallet=Session(home/'B-wallets',brpc)
        address=wallet.dispatch(dict(command='create',name='Independent',password='Fresh-'+secrets.token_hex(24)))['address']
        identities=[]
        for index in (1,2):
            folder=home/str(index);folder.mkdir(mode=0o700);key,cert=folder/'key',folder/'cert'
            subprocess.run([openssl_binary(),'req','-x509','-newkey','ed25519','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=disposable'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
            key.chmod(0o600);cert.chmod(0o600)
            value=descriptor(rpc+index);value['certificate_sha256']=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
            identities.append((value,key,cert,port()))
        socks=Socks({v['onion']:ingress for v,_,_,ingress in identities},seed=99,connect_delay=.02,jitter=.003,chunk=97)
        for i,(value,key,cert,ingress) in enumerate(identities):
            service=PeerService(ingress,p2p if i==0 else bp2p,rpc+10 if i==0 else base,socks.port,lambda value=value:value,key,cert,[] if i==0 else [identities[0][0]])
            service.start();services.append(service)
        stamp=int(time.time())-120*500
        def mine(port,address,count):
            nonlocal stamp
            for _ in range(count):
                stamp+=120;D,C,sub=f.parse_address(address);R,P=f.crypto('output',D,C,sub,0)
                c.w.rpc(port,'mine',reward_key=P,R=R,timestamp=stamp)
        mine(rpc,app.address.get(),80);wait(lambda:c.w.rpc(brpc,'status')['height']==80)
        app.action('product_status',{},app.show_product);pump();app.refresh();pump()
        checks.append('real GUI-owned node synchronizes with unrelated ticket-free TLS peer via local SOCKS fixture')
        app.vars['unit'].set('atomic');app.unit='atomic'
        for key,value in dict(destination=address,amount='1000000',fee='188000',max_fee='500000').items():app.vars[key].set(value)
        # Drive the real review -> explicit confirmation -> private pipe -> journal path.
        with patch('tkinter.simpledialog.askstring',return_value='CONFIRM'):app.review();pump()
        wait(lambda:bool(c.w.rpc(brpc,'pool')['transactions']))
        mine(rpc,app.address.get(),11);wait(lambda:c.w.rpc(brpc,'status')['height']==91)
        app.refresh();pump()
        assert app.snapshot['outgoing'][0]['status']=='CONFIRMED'
        assert wallet.refresh()['balance']['spendable']==1000000
        checks.append('GUI explicit amount/fee review signs and confirms actual private payment; receiver independently verifies matured funds')
        approval=wallet.dispatch(dict(command='prepare',destination=app.address.get(),amount=100000,fee=188000,max_fee=500000))
        wallet.dispatch(dict(command='confirm',token=approval['token'],consent='CONFIRM'))
        wait(lambda:bool(c.w.rpc(rpc,'pool')['transactions']))
        mine(brpc,address,1);wait(lambda:c.w.rpc(rpc,'status')['height']==92)
        app.refresh();pump()
        assert any(x['amount']==100000 and not x['coinbase'] and x['status']=='LOCKED' for x in app.snapshot['history'])
        assert c.w.rpc(rpc,'status')['tip']==c.w.rpc(brpc,'status')['tip']
        checks.append('GUI displays real incoming private payment with maturity qualification and identical native tip')
        return checks
    finally:
        for service in services:service.close()
        if socks:socks.close()
        if wallet:wallet.close()
        if node and node.poll() is None:
            node.terminate()
            try:node.wait(15)
            except subprocess.TimeoutExpired:node.kill();node.wait(5)
