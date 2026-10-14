"""Mainnet-bound client. Installation never activates Tor or mining.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,os
from pathlib import Path
def main():
    os.umask(0o077)
    root=Path(__file__).resolve().parents[2]
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--home',type=Path,default=Path.home()/'.local/share/privacycoin-mainnet-v1')
    a=p.parse_args()
    os.environ['PC_OFFLINE_BINDING']=str(root/'candidate-native/full/BINDING.json')
    os.environ['PC_CANDIDATE_PROFILE']=str(root/'candidate-native/full/PROFILE.json')
    os.environ['PC_DEVELOPMENT_NETWORK']='mainnet-v1'
    os.environ['PC_DEVNET_NATIVE_ROOT']=str(root)
    from tools.mainnet_prepare.production import frozen,profile
    frozen()
    from .candidate_runtime import Runtime
    from .candidate_client import Client
    from .candidate_gui import Window
    import tkinter as tk
    node=None;client=None
    try:
        node=Runtime(a.home,root/'candidate-native/full',Path(os.environ['PC_CANDIDATE_PROFILE']))
        client=Client(a.home,root/'candidate-native/full',root,node=node,profile=profile())
        window=tk.Tk();Window(window,client);window.mainloop()
    finally:
        if client:client.close()
        elif node:node.close()
if __name__=='__main__':main()
