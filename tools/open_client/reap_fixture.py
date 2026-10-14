"""Recover only this harness's abandoned native children; never historical data.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,os,signal
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--fixture',type=Path,required=True);a=p.parse_args()
home=a.fixture.resolve(strict=True)
if home.parent!=Path('/home/privacydev') or not home.name.startswith('pc-v1-fixtures-open-'):raise ValueError('TEST_PROFILE_ONLY')
owned=[]
for item in Path('/proc').iterdir():
    if not item.name.isdigit():continue
    try:
        args=(item/'cmdline').read_bytes().split(b'\0')
        if not args or Path(os.fsdecode(args[0])).name!='privacycoin-hardened-devnet':continue
        index=args.index(b'--data-dir');data=Path(os.fsdecode(args[index+1])).resolve()
        if data.parent.parent!=home or data.name!='node' or data.parent.name not in ('A','B','C'):continue
        if (item/'status').stat().st_uid!=os.getuid():raise ValueError('OWNER_MISMATCH')
        owned.append(int(item.name))
    except (FileNotFoundError,ValueError):continue
for pid in owned:os.kill(pid,signal.SIGKILL)
print({'reaped_failed_fixture_children':owned,'files_removed':False})
