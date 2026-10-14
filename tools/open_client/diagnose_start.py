"""Fresh disposable startup diagnostic; no exception values or wallet secrets.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,secrets,traceback,sys,os
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--product',type=Path,required=True);p.add_argument('--home',type=Path,required=True);a=p.parse_args()
if a.home.exists() or not str(a.home).startswith('/home/privacydev/pc-v1-fixtures-open-'):raise ValueError('FRESH_TEST_HOME')
sys.path.insert(0,str(a.product));os.environ['PC_DEVELOPMENT_NETWORK']='open-dev02'
from apps.network_v1.desktop_backend import Product
product=None
try:
    product=Product(a.home,34781,34782)
    product.dispatch(dict(command='create',name='Diagnostic',password='Isolated-'+secrets.token_hex(24)))
    print('CREATED')
except Exception as error:
    print(type(error).__name__)
    if isinstance(error,ValueError) and str(error) in ('BUILD_SOURCE_CHANGED','BUILD_SOURCE_INCOMPLETE','BUILD_MANIFEST_SCHEMA','BUILD_BINARY_SET','OWNED_NODE_EXITED','NODE_VALIDATION_NOT_READY_RETRY_WITHOUT_RECREATING_WALLET'):print(str(error))
    for x in traceback.extract_tb(error.__traceback__):print(x.name,x.lineno)
finally:
    if product:product.close()
