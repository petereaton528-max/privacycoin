"""Small additive source patch; leaves all previous ZIPs and private state intact."""
from pathlib import Path
import hashlib,json,zipfile,io,importlib.util,tempfile
ROOT=Path(__file__).resolve().parents[3]
OUT=ROOT/'build/n2-deployment'
FILES=['deploy/n2/common/n2_tor_diagnostics.py','deploy/n2/common/n2_start_diagnostic.py','docs/privacy-network/n2/TOR_STARTUP_DIAGNOSTICS.md','docs/privacy-network/n2/TOR_STARTUP_RESULTS.md']
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main():
    OUT.mkdir(parents=True,exist_ok=True)
    files={name:sha((ROOT/name).read_bytes()) for name in FILES}
    manifest=dict(version=1,source_base_commit='6dc552f828c6ff4b97ba9ec9a483d00c9260376a',mode='ADDITIVE_ONLY_NO_OVERWRITE',files=files)
    buffer=io.BytesIO()
    with zipfile.ZipFile(buffer,'w') as z:
        entries={name:(ROOT/name).read_bytes() for name in FILES};entries['N2_PATCH_MANIFEST.json']=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
        for name,raw in sorted(entries.items()):
            info=zipfile.ZipInfo(name,date_time=(2026,10,10,0,0,0));info.external_attr=0o100600<<16;info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,raw)
    raw=buffer.getvalue();digest=sha(raw);archive=OUT/'PrivacyNetwork-N2-startup-diagnostics-20261010.zip'
    if archive.exists():
        if archive.read_bytes()!=raw:raise ValueError('PRESERVE_EXISTING_PACKAGE_USE_NEW_FILENAME')
    else:archive.write_bytes(raw)
    archive.with_suffix('.zip.sha256').write_bytes((digest+'  '+archive.name+'\n').encode())
    installer=ROOT/'deploy/n2/common/n2_apply_patch.py';adjacent=OUT/'n2_apply_patch.py'
    if adjacent.exists() and adjacent.read_bytes()!=installer.read_bytes():raise ValueError('EXISTING_INSTALLER_CONFLICT')
    if not adjacent.exists():adjacent.write_bytes(installer.read_bytes())
    spec=importlib.util.spec_from_file_location('installer',installer);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory(prefix='n2-startup-patch-') as temporary:
        source=Path(temporary);sentinel=source/'wallet-sentinel';sentinel.write_bytes(b'existing-state-preserved')
        assert module.apply(archive,source,digest)==len(files)
        assert module.apply(archive,source,digest)==0
        assert sentinel.read_bytes()==b'existing-state-preserved'
        assert all(sha((source/name).read_bytes())==value for name,value in files.items())
    evidence=dict(archive=archive.relative_to(ROOT).as_posix(),sha256=digest,bytes=len(raw),files=len(files),installer_sha256=sha(installer.read_bytes()),manifest=manifest,extraction='PASS',repeat_application='UNCHANGED',existing_sentinel='UNCHANGED',binaries=False,private_state=False)
    (ROOT/'docs/evidence/privacy-network-n2-startup-diagnostics/package.json').write_bytes((json.dumps(evidence,indent=2)+'\n').encode());print(json.dumps({k:v for k,v in evidence.items() if k!='manifest'},indent=2))
if __name__=='__main__':main()
