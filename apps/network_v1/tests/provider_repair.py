"""Run unchanged historical repair tests with immutable public source fixture.

Only substitute the historical git-show fixture lookup; no production adapter
mocking. Fresh private native build/test dirs; original N2 stores never used.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch


def main():
    p=argparse.ArgumentParser();p.add_argument('--native-root',type=Path,required=True);p.add_argument('--evidence',type=Path,required=True);a=p.parse_args()
    os.environ['PC_DEVNET_NATIVE_ROOT']=str(a.native_root);os.environ['PC_DEVNET_BUILD_MANIFEST']=str(a.native_root/'build/v1-native-manifest.json')
    root=Path(__file__).resolve().parents[3];sys.path.insert(0,str(root/'services/privacy-network'))
    fixture=Path(__file__).with_name('fixtures')/'provider_v01.py';raw=fixture.read_bytes();original=subprocess.check_output
    a.evidence.mkdir(mode=0o700,exist_ok=False)
    def lookup(command,*args,**kw):
        if isinstance(command,list) and command[0]=='git' and command[-2:]==['show','24d223e:services/privacy-network/provider.py']:return raw
        return original(command,*args,**kw)
    spec=importlib.util.spec_from_file_location('retained_provider_repair',root/'services/privacy-network/repair_tests.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);module.OUT=a.evidence
    (a.evidence/'fixture-source-sha256.txt').write_text(hashlib.sha256(raw).hexdigest()+'\n')
    with patch.object(subprocess,'check_output',side_effect=lookup):module.main()


if __name__=='__main__':main()
