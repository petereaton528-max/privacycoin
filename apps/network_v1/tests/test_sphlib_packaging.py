"""Isolated build bindings must not silently accept another backend.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from experiments.sphlib.package import native_binding
from experiments.sphlib.stage import replacements

class IsolatedBindingTests(unittest.TestCase):
    def test_substitution_manifest_matches_exact_committed_vendor_bytes(self):
        root=Path(__file__).resolve().parents[3]
        manifest=json.loads((root/'docs/network-v1/SPHLIB_SUBSTITUTION.json').read_text())
        for n,raw in replacements().items():
            self.assertEqual(manifest['source_files']['.upstream/monero/'+n],hashlib.sha256(raw).hexdigest(),n)

    def test_binding_is_read_only_and_rejects_other_binary(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'manifest.json'
            original=json.dumps({'binary_sha256':{'node':'a'*64},'source_sha256':{}}).encode()
            p.write_bytes(original)
            self.assertEqual(json.loads(native_binding(p,{'phase4/node':'a'*64}))['binary_sha256']['node'],'a'*64)
            with self.assertRaisesRegex(ValueError,'ISOLATED_NATIVE_BINDING_MISMATCH'):
                native_binding(p,{'phase4/node':'b'*64})
            self.assertEqual(p.read_bytes(),original)

    def test_missing_required_binary_cannot_pass(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'manifest.json';p.write_text('{"binary_sha256": {}}')
            with self.assertRaises(KeyError):native_binding(p,{'phase4/node':'a'*64})
