"""Isolated-interpreter entry point; verify package before project imports.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import hashlib,json,os,resource,runpy,sys
from pathlib import Path
try:
    os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    root=Path(__file__).resolve().parent
    manifest=json.loads((root/'FOUNDER_MANIFEST.json').read_text())
    for name,digest in manifest['files'].items():
        p=root/name
        if Path(name).is_absolute() or '..' in Path(name).parts or any(q.is_symlink() for q in (p,*p.parents)) or not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=digest:raise ValueError()
    sys.path.insert(0,str(root))
    runpy.run_module('tools.mainnet_prepare.founder',run_name='__main__')
except (Exception,KeyboardInterrupt):
    print('Founder tool stopped safely. Verify the package and offline private destination. No automatic retry.',file=sys.stderr)
    raise SystemExit(1)
