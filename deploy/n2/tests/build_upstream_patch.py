"""Reproducible bounded source patch; test against genuine earlier source ZIPs."""
from pathlib import Path
import hashlib,io,json,sys,tempfile,zipfile
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'deploy/n2/common'))
import bundle,n2_apply_patch,n2_install_upstream as install
OUT=ROOT/'build/n2-deployment'
FILES=['deploy/n2/common/n2_start_diagnostic.py','deploy/n2/common/n2_upstream_socks5.py','deploy/n2/common/n2_install_upstream.py','docs/privacy-network/n2/UPSTREAM_SOCKS5.md','docs/privacy-network/n2/UPSTREAM_SOCKS5_RESULTS.md']
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main():
    entries={name:(ROOT/name).read_bytes() for name in FILES}
    manifest=dict(version=1,base='5820678df5ad28eb19b1a69d86b42e50c3bea7aa',files={name:sha(data) for name,data in entries.items()},replacement={install.LAUNCHER:install.OLD})
    entries['N2_UPSTREAM_MANIFEST.json']=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode();buffer=io.BytesIO()
    with zipfile.ZipFile(buffer,'w') as z:
        for name,data in sorted(entries.items()):
            info=zipfile.ZipInfo(name,(2026,10,10,0,0,0));info.external_attr=0o100600<<16;info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,data)
    raw=buffer.getvalue();archive=OUT/'PrivacyNetwork-N2-upstream-socks5-20261010.zip'
    if archive.exists() and archive.read_bytes()!=raw:raise ValueError('PRESERVE_PACKAGE_USE_NEW_FILENAME')
    if not archive.exists():archive.write_bytes(raw)
    sidecar=archive.with_suffix('.zip.sha256');sidecar.write_bytes((sha(raw)+'  '+archive.name+'\n').encode())
    adjacent=OUT/'n2_install_upstream.py';data=(ROOT/'deploy/n2/common/n2_install_upstream.py').read_bytes()
    if adjacent.exists() and adjacent.read_bytes()!=data:raise ValueError('INSTALLER_CONFLICT')
    if not adjacent.exists():adjacent.write_bytes(data)
    with tempfile.TemporaryDirectory(prefix='n2-upstream-package-') as temp:
        source=Path(temp)/'source';original=bundle.extract(OUT/'PrivacyNetwork-N2-connectivity-source.zip',source)
        for name in ('PrivacyNetwork-N2-operator-patch-20261010.zip','PrivacyNetwork-N2-startup-diagnostics-20261010.zip'):
            patch=OUT/name;n2_apply_patch.apply(patch,source,sha(patch.read_bytes()))
        before=(source/'N2_SOURCE_MANIFEST.json').read_bytes();sentinel=source/'private-state-sentinel';sentinel.write_bytes(b'FIXTURE-ONLY-NOT-A-WALLET')
        assert install.apply(archive,source,sha(raw))==len(FILES)
        assert install.apply(archive,source,sha(raw))==0
        assert sha((source/install.BACKUP).read_bytes())==install.OLD
        assert (source/'N2_SOURCE_MANIFEST.json').read_bytes()==before and bundle.verify_tree(source)==original
        assert sentinel.read_bytes()==b'FIXTURE-ONLY-NOT-A-WALLET'
        assert all(sha((source/name).read_bytes())==digest for name,digest in manifest['files'].items())
        for name in FILES:
            if name.endswith('.py'):compile((source/name).read_bytes(),name,'exec')
    report=dict(archive=archive.relative_to(ROOT).as_posix(),bytes=len(raw),sha256=sha(raw),installer_sha256=sha(data),manifest=manifest,actual_preceding_source_bundle='PASS',original_source_manifest_and_hashes='UNCHANGED',existing_state_sentinel='UNCHANGED',idempotent='PASS',extraction='PASS',binaries=False,private_data=False)
    path=ROOT/'docs/evidence/privacy-network-n2-upstream-socks5/package.json'
    if path.exists():raise ValueError('PRESERVE_PACKAGE_EVIDENCE')
    path.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='manifest'},indent=2))
if __name__=='__main__':main()
