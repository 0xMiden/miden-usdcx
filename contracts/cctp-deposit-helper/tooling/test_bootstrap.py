"""Tiny archives exercise bootstrap integrity without executing downloaded code."""
import copy
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import bootstrap as b


class ReferenceSources(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'reference/cctp/src'
        self.source.mkdir(parents=True)
        self.authored = self.source / 'CodecProbe.sol'
        self.authored.write_bytes(b'owned wrapper')
        (self.source.parent / 'foundry.toml').write_bytes(b'owned config')
        self.license = self.root / 'reference/LICENSE'
        self.license.write_bytes(b'license')
        self.p = {
            'upstreams': {},
            'sources': [{'path': 'reference/cctp/src/' + n, 'upstream': 'tiny',
                         'upstreamPath': n, 'sha256': b.digest(n.encode())}
                        for n in ['a.sol', 'b.sol']],
            'licenses': [{'path': 'reference/LICENSE', 'sha256': b.digest(b'license')}],
        }
        self.contents = [('root/a.sol', b'a.sol', None), ('root/b.sol', b'b.sol', None)]
        self.make_archive()

    def make_archive(self, entries=None):
        path = self.root / 'upstream.tar.gz'
        with tarfile.open(path, 'w:gz') as tar:
            for name, data, kind in entries or self.contents:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                if kind:
                    member.type = kind
                    member.linkname = 'elsewhere'
                tar.addfile(member, io.BytesIO(data))
        self.p['upstreams']['tiny'] = {'archiveUrl': path.as_uri(),
                                      'archiveSha256': b.digest(path.read_bytes())}
        return path

    def run_materializer(self, offline=False):
        b.materialize(self.root, self.p, offline)

    def assert_authored(self):
        self.assertEqual(self.authored.read_bytes(), b'owned wrapper')
        self.assertEqual((self.source.parent / 'foundry.toml').read_bytes(), b'owned config')
        self.assertEqual(self.license.read_bytes(), b'license')

    def assert_sources_absent(self):
        self.assertFalse((self.source / 'a.sol').exists())
        self.assertFalse((self.source / 'b.sol').exists())

    def test_cold_warm_and_offline_reconstruction(self):
        self.assert_sources_absent()
        self.run_materializer()
        with patch.object(b.urllib.request, 'urlopen', side_effect=AssertionError('network forbidden')):
            self.run_materializer()
            (self.source / 'a.sol').unlink()
            (self.source / 'b.sol').unlink()
            self.run_materializer(offline=True)
        self.assertEqual((self.source / 'a.sol').read_bytes(), b'a.sol')
        self.assertEqual((self.source / 'b.sol').read_bytes(), b'b.sol')
        self.assert_authored()

    def test_offline_missing_cache(self):
        with patch.object(b.urllib.request, 'urlopen', side_effect=AssertionError('network forbidden')):
            with self.assertRaisesRegex(ValueError, 'cache missing'):
                self.run_materializer(offline=True)
        self.assert_sources_absent()

    def test_wrong_archive_hash_never_publishes_cache_or_sources(self):
        self.p['upstreams']['tiny']['archiveSha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            self.run_materializer()
        self.assertEqual(list((self.root / 'tooling/reference-cache').iterdir()), [])
        self.assert_sources_absent()

    def test_interrupted_download_and_cache_publication(self):
        for failure in ['read', 'replace']:
            with self.subTest(failure=failure):
                if failure == 'read':
                    response = unittest.mock.MagicMock()
                    response.__enter__.return_value.read.side_effect = [b'partial', OSError('interrupted read')]
                    target = patch.object(b.urllib.request, 'urlopen', return_value=response)
                else:
                    target = patch.object(b.os, 'replace', side_effect=OSError('interrupted replace'))
                with target, self.assertRaisesRegex(OSError, 'interrupted'):
                    self.run_materializer()
                self.assertEqual(list((self.root / 'tooling/reference-cache').iterdir()), [])
                self.assert_sources_absent()
        self.run_materializer()
        self.assert_authored()

    def test_missing_duplicate_and_nonregular_mapped_members(self):
        directory = ('root/a.sol', b'', tarfile.DIRTYPE)
        cases = [self.contents[:1], self.contents + self.contents[:1],
                 [directory] + self.contents, self.contents + [directory]]
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.FIFOTYPE]:
            cases.append([('root/a.sol', b'', kind), self.contents[1]])
        for entries in cases:
            with self.subTest(entries=entries):
                self.make_archive(entries)
                with self.assertRaisesRegex(ValueError, 'Missing mapped|Duplicate or nonregular'):
                    self.run_materializer()
                self.assert_sources_absent()

    def test_escaping_names_and_link_ancestors(self):
        for name in ['/absolute', 'root/../escape', 'root/dir/../../escape', 'root\\escape']:
            with self.subTest(name=name):
                self.make_archive(self.contents + [(name, b'bad', None)])
                with self.assertRaisesRegex(ValueError, 'Unsafe archive'):
                    self.run_materializer()
                self.assert_sources_absent()
        self.make_archive([('root', b'', tarfile.SYMTYPE)] + self.contents)
        with self.assertRaisesRegex(ValueError, 'Link traversal'):
            self.run_materializer()
        self.assert_sources_absent()
        self.p['sources'][0]['upstreamPath'] = 'dir/a.sol'
        self.make_archive([('root/./dir', b'', tarfile.SYMTYPE),
                           ('root/dir/a.sol', b'a.sol', None), self.contents[1]])
        with self.assertRaisesRegex(ValueError, 'Link traversal'):
            self.run_materializer()
        self.assert_sources_absent()

    def test_wrong_source_bytes_stage_nothing(self):
        self.make_archive([self.contents[0], ('root/b.sol', b'wrong', None)])
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            self.run_materializer()
        self.assert_sources_absent()
        self.assert_authored()

    def test_corrupt_warm_source_and_archive_fail_closed(self):
        self.run_materializer()
        (self.source / 'a.sol').write_bytes(b'corrupted source')
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            self.run_materializer()
        self.assertEqual((self.source / 'a.sol').read_bytes(), b'corrupted source')
        (self.source / 'a.sol').write_bytes(b'a.sol')
        archive = next((self.root / 'tooling/reference-cache').glob('*.tar.gz'))
        archive.write_bytes(b'corrupted archive')
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            self.run_materializer()
        self.assert_authored()

    def test_license_integrity_on_cold_and_warm_runs(self):
        self.license.write_bytes(b'bad')
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            self.run_materializer()
        self.assert_sources_absent()
        self.license.write_bytes(b'license')
        self.run_materializer()
        self.license.write_bytes(b'bad')
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            self.run_materializer(offline=True)

    def test_interrupted_source_install_is_verified_and_recoverable(self):
        publish = b.publish
        calls = []
        def interrupt(path, data):
            calls.append(path)
            if len(calls) == 2:
                raise OSError('interrupted install')
            publish(path, data)
        with patch.object(b, 'publish', side_effect=interrupt):
            with self.assertRaisesRegex(OSError, 'interrupted install'):
                self.run_materializer()
        self.assertEqual((self.source / 'a.sol').read_bytes(), b'a.sol')
        self.assertFalse((self.source / 'b.sol').exists())
        self.run_materializer(offline=True)
        self.assertEqual((self.source / 'b.sol').read_bytes(), b'b.sol')
        self.assert_authored()

    def test_destinations_are_confined_and_never_follow_symlinks(self):
        for name in ['reference/../escape.sol', '/escape.sol', 'other/a.sol']:
            with self.subTest(name=name):
                p = copy.deepcopy(self.p)
                p['sources'][0]['path'] = name
                with self.assertRaises(ValueError):
                    b.materialize(self.root, p)
                self.assert_sources_absent()
        outside = self.root / 'outside'
        outside.mkdir()
        self.source.rename(self.root / 'saved-src')
        self.source.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'outside owned|Symlink destination'):
            self.run_materializer()
        self.assertEqual(list(outside.iterdir()), [])

    def test_owned_subroots_reject_symlinked_ancestors(self):
        outside = self.root / 'outside'
        outside.mkdir()
        for parent, name in [('modules', 'modules/dependency/src/file.sol'),
                             ('tooling', 'tooling/reference-cache/archive.tar.gz')]:
            with self.subTest(parent=parent):
                (self.root / parent).symlink_to(outside, target_is_directory=True)
                with self.assertRaisesRegex(ValueError, 'outside owned|Symlink destination'):
                    b.destination(self.root, name)
                (self.root / parent).unlink()
                self.assertEqual(list(outside.iterdir()), [])

    def test_main_rejects_symlinked_modules_before_tool_execution(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (self.root / 'modules').symlink_to(outside, target_is_directory=True)
        (self.root / 'reference/PROVENANCE.json').write_text(json.dumps(self.p))
        tools = {'forge': b'forge', 'anvil': b'anvil'}
        lock = {'arcFoundry': {'binarySha256': {k: b.digest(v) for k, v in tools.items()}},
                'openzeppelin': {'commit': 'tiny'}}
        (self.root / 'DEPENDENCIES.lock.json').write_text(json.dumps(lock))
        with patch.object(b, 'ROOT', self.root), patch('sys.argv', ['bootstrap']), \
                patch.object(b.platform, 'system', return_value='Darwin'), \
                patch.object(b.platform, 'machine', return_value='arm64'), \
                patch.object(b, 'archive'), patch.object(b, 'materialize'), \
                patch.object(b, 'members', side_effect=[tools, {'src/file.sol': b'module'}]), \
                patch.object(b.subprocess, 'run') as run, \
                patch.object(b.subprocess, 'check_output') as version:
            with self.assertRaisesRegex(ValueError, 'outside owned|Symlink destination'):
                b.main()
            run.assert_not_called()
            version.assert_not_called()
        self.assertEqual(list(outside.iterdir()), [])

    def test_integrity_failure_precedes_all_tool_execution(self):
        (self.root / 'DEPENDENCIES.lock.json').write_text('{}')
        self.make_archive([self.contents[0], ('root/b.sol', b'wrong', None)])
        (self.root / 'reference/PROVENANCE.json').write_text(json.dumps(self.p))
        with patch.object(b, 'ROOT', self.root), patch('sys.argv', ['bootstrap']), \
                patch.object(b.platform, 'system', return_value='Darwin'), \
                patch.object(b.platform, 'machine', return_value='arm64'), \
                patch.object(b.subprocess, 'run') as run, \
                patch.object(b.subprocess, 'check_output') as version:
            with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
                b.main()
            run.assert_not_called()
            version.assert_not_called()
        self.assert_sources_absent()

    def test_duplicate_destinations_and_unknown_upstreams(self):
        self.p['sources'].append(dict(self.p['sources'][0]))
        with self.assertRaisesRegex(ValueError, 'Duplicate destination'):
            self.run_materializer()
        self.p['sources'].pop()
        self.p['sources'][0]['upstream'] = 'unknown'
        with self.assertRaisesRegex(ValueError, 'Unmapped reference'):
            self.run_materializer()
        self.assert_sources_absent()


if __name__ == '__main__':
    unittest.main()
