"""Tiny Git repositories test the source boundary; tiny archives test Arc tools."""
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import bootstrap as b
import dependencies as d


def fixture_git(directory, *arguments):
    return subprocess.check_output(['git', '-C', str(directory), '-c', 'commit.gpgsign=false',
                                    '-c', 'core.hooksPath=/dev/null', '-c', 'user.name=Fixture',
                                    '-c', 'user.email=fixture@example.invalid', *arguments],
                                   stderr=subprocess.DEVNULL).decode().strip()


class GitDependencies(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.workspace = Path(temporary.name).resolve()
        self.parent = self.workspace / 'parent'
        upstream = self.workspace / 'upstream'
        for directory in [self.parent, upstream]:
            directory.mkdir()
            fixture_git(directory, 'init', '--initial-branch=main')
        (upstream / 'Input.sol').write_text('contract Input {}\n')
        (upstream / 'LICENSE').write_text('retained fixture license\n')
        (upstream / '.gitignore').write_text('ignored.sol\n')
        fixture_git(upstream, 'add', '.')
        fixture_git(upstream, 'commit', '-m', 'fixture source')
        self.root = self.parent / 'contracts/cctp-deposit-helper'
        for version, files in [('cctp', ['CodecProbe.sol', 'ReferenceRoots.sol']),
                               ('xreserve', ['ReferenceRoots.sol'])]:
            directory = self.root / 'reference' / version / 'inputs'
            directory.mkdir(parents=True)
            for name in files:
                (directory / name).write_text('pragma solidity 0.8.29;\n')
        for name in ['contracts', 'tests', 'scripts']:
            (self.root / name).mkdir()
        (self.root / 'tests/Existing.t.sol').write_text('contract Existing {}\n')
        (self.root / '.gitignore').write_text('tests/Ignored.sol\n')
        fixture_git(self.parent, '-c', 'protocol.file.allow=always', 'submodule', 'add',
                    '--name', 'tiny', str(upstream), 'contracts/cctp-deposit-helper/modules/tiny')
        self.module = self.root / 'modules/tiny'
        self.cache = self.parent / '.git/modules/tiny'
        self.commit = fixture_git(self.module, 'rev-parse', 'HEAD')
        fixture_git(self.parent, 'config', '-f', '.gitmodules', 'submodule.tiny.url',
                    'https://github.com/fixture/source.git')
        fixture_git(self.parent, 'config', 'submodule.tiny.url', 'https://github.com/fixture/source.git')
        fixture_git(self.parent, 'add', '.')
        fixture_git(self.parent, 'commit', '-m', 'fixture parent')

    def verify(self, **options):
        return d.prepare(self.root, **options)

    def test_warm_and_offline_cached_reconstruction(self):
        self.verify()
        self.verify(offline=True)
        shutil.rmtree(self.module)
        with patch.dict(os.environ, {'GIT_CONFIG_COUNT': '1',
                                     'GIT_CONFIG_KEY_0': 'protocol.https.allow',
                                     'GIT_CONFIG_VALUE_0': 'never'}):
            self.verify(offline=True, initialize=True)
        self.assertEqual((self.module / 'LICENSE').read_text(), 'retained fixture license\n')

    def test_offline_needs_current_tree_not_obsolete_history(self):
        old_blob = fixture_git(self.module, 'rev-parse', 'HEAD:Input.sol')
        (self.module / 'Input.sol').write_text('contract CurrentInput {}\n')
        fixture_git(self.module, 'add', 'Input.sol')
        fixture_git(self.module, 'commit', '-m', 'fixture current snapshot')
        fixture_git(self.parent, 'add', 'contracts/cctp-deposit-helper/modules/tiny')
        (self.cache / 'objects' / old_blob[:2] / old_blob[2:]).unlink()
        with patch.object(d, 'verify_module', wraps=d.verify_module) as verify:
            self.verify(offline=True)
            self.assertEqual(verify.call_count, 1)
        shutil.rmtree(self.module)
        with patch.dict(os.environ, {'GIT_CONFIG_COUNT': '1',
                                     'GIT_CONFIG_KEY_0': 'protocol.https.allow',
                                     'GIT_CONFIG_VALUE_0': 'never'}):
            self.verify(offline=True, initialize=True)
        self.assertEqual((self.module / 'Input.sol').read_text(), 'contract CurrentInput {}\n')

    def test_offline_missing_cache_precedes_acquisition(self):
        shutil.rmtree(self.module)
        shutil.rmtree(self.cache)
        real_run = subprocess.run
        def no_acquisition(command, *args, **kwargs):
            if 'submodule' in command or 'clone' in command:
                self.fail('offline missing cache attempted acquisition')
            return real_run(command, *args, **kwargs)
        with patch.object(d.subprocess, 'run', side_effect=no_acquisition):
            with self.assertRaisesRegex(ValueError, 'Offline dependency cache missing'):
                self.verify(offline=True, initialize=True)

    def test_offline_missing_blob_precedes_acquisition(self):
        blob = fixture_git(self.module, 'rev-parse', 'HEAD:Input.sol')
        shutil.rmtree(self.module)
        (self.cache / 'objects' / blob[:2] / blob[2:]).unlink()
        real_run = subprocess.run
        def no_acquisition(command, *args, **kwargs):
            if 'submodule' in command or 'clone' in command:
                self.fail('offline missing object attempted acquisition')
            return real_run(command, *args, **kwargs)
        with patch.object(d.subprocess, 'run', side_effect=no_acquisition):
            with self.assertRaisesRegex(ValueError, 'Offline pinned objects missing'):
                self.verify(offline=True, initialize=True)

    def test_actual_bytes_defeat_restored_stat_cache(self):
        target = self.module / 'Input.sol'
        fixture_git(self.module, 'config', 'core.trustctime', 'false')
        fixture_git(self.module, 'config', 'core.checkStat', 'minimal')
        stamp = target.stat().st_mtime_ns - 20_000_000_000
        os.utime(target, ns=(stamp, stamp))
        fixture_git(self.module, 'update-index', '--refresh')
        fixture_git(self.module, 'status', '--porcelain')
        before = target.stat()
        target.write_bytes(target.read_bytes().replace(b'Input', b'Other'))
        os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(target.stat().st_size, before.st_size)
        self.assertEqual(fixture_git(self.module, 'status', '--porcelain'), '')
        with self.assertRaisesRegex(ValueError, 'bytes differ'):
            self.verify()

    def test_replacement_tree_cannot_substitute_the_pin(self):
        (self.module / 'Input.sol').write_text('contract ReplacedInput {}\n')
        fixture_git(self.module, 'add', 'Input.sol')
        fixture_git(self.module, 'commit', '-m', 'fixture replacement')
        replacement = fixture_git(self.module, 'rev-parse', 'HEAD')
        fixture_git(self.module, 'replace', self.commit, replacement)
        fixture_git(self.module, 'checkout', self.commit)
        self.assertEqual(fixture_git(self.module, 'rev-parse', 'HEAD'), self.commit)
        self.assertEqual((self.module / 'Input.sol').read_text(), 'contract ReplacedInput {}\n')
        with self.assertRaisesRegex(ValueError, 'Staged dependency changes: .*modules/tiny'):
            self.verify()
        with self.assertRaisesRegex(ValueError, 'Git check failed in .*modules/tiny: diff --cached'):
            d.git(self.module, 'diff', '--cached', '--quiet', self.commit, '--')
        # A benign replacement ref may remain; original objects still govern verification/checkout.
        fixture_git(self.module, '--no-replace-objects', 'read-tree', '--reset', '-u', self.commit)
        self.verify()
        shutil.rmtree(self.module)
        with patch.dict(os.environ, {'GIT_CONFIG_COUNT': '1',
                                     'GIT_CONFIG_KEY_0': 'protocol.https.allow',
                                     'GIT_CONFIG_VALUE_0': 'never'}):
            self.verify(offline=True, initialize=True)
        self.assertEqual((self.module / 'Input.sol').read_text(), 'contract Input {}\n')

    def test_replacement_tree_cannot_hide_missing_offline_objects(self):
        blob = fixture_git(self.module, 'rev-parse', 'HEAD:Input.sol')
        (self.module / 'Input.sol').write_text('contract ReplacedInput {}\n')
        fixture_git(self.module, 'add', 'Input.sol')
        fixture_git(self.module, 'commit', '-m', 'fixture replacement')
        replacement = fixture_git(self.module, 'rev-parse', 'HEAD')
        fixture_git(self.module, 'replace', self.commit, replacement)
        shutil.rmtree(self.module)
        (self.cache / 'objects' / blob[:2] / blob[2:]).unlink()
        real_run = subprocess.run
        def no_acquisition(command, *args, **kwargs):
            if 'submodule' in command or 'clone' in command:
                self.fail('replacement hid missing pinned object before acquisition')
            return real_run(command, *args, **kwargs)
        with patch.object(d.subprocess, 'run', side_effect=no_acquisition):
            with self.assertRaisesRegex(ValueError, 'Offline pinned objects missing'):
                self.verify(offline=True, initialize=True)

    def test_wrong_commit_and_staged_changes(self):
        (self.module / 'Input.sol').write_text('contract Changed {}\n')
        fixture_git(self.module, 'add', 'Input.sol')
        with self.assertRaisesRegex(ValueError, 'Staged dependency changes'):
            self.verify()
        fixture_git(self.module, 'commit', '-m', 'fixture wrong head')
        with self.assertRaisesRegex(ValueError, 'Wrong pinned commit'):
            self.verify()

    def test_untracked_and_ignored_module_shadows(self):
        for name in ['Extra.sol', 'ignored.sol']:
            with self.subTest(name=name):
                path = self.module / name
                path.write_text('contract Shadow {}\n')
                with self.assertRaisesRegex(ValueError, 'Unexpected/nonregular'):
                    self.verify()
                path.unlink()

    def test_missing_file_and_mode_changes(self):
        path = self.module / 'Input.sol'
        path.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'mode differs'):
            self.verify()
        path.chmod(0o644)
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'Missing pinned'):
            self.verify()

    def test_symlink_file_and_module_ancestor(self):
        path = self.module / 'Input.sol'
        path.unlink()
        path.symlink_to(self.module / 'LICENSE')
        with self.assertRaisesRegex(ValueError, 'Symlink dependency path'):
            self.verify()
        path.unlink()
        path.write_text('contract Input {}\n')
        modules = self.root / 'modules'
        saved = self.root / 'saved-modules'
        modules.rename(saved)
        modules.symlink_to(saved, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'Symlink dependency path'):
            self.verify()

    def test_sparse_and_assume_unchanged_rejected(self):
        fixture_git(self.module, 'update-index', '--assume-unchanged', 'Input.sol')
        with self.assertRaisesRegex(ValueError, 'assume-unchanged'):
            self.verify()
        fixture_git(self.module, 'update-index', '--no-assume-unchanged', 'Input.sol')
        fixture_git(self.module, 'update-index', '--skip-worktree', 'Input.sol')
        with self.assertRaisesRegex(ValueError, 'sparse/assume-unchanged'):
            self.verify()
        fixture_git(self.module, 'update-index', '--no-skip-worktree', 'Input.sol')
        fixture_git(self.module, 'config', 'core.sparseCheckout', 'true')
        with self.assertRaisesRegex(ValueError, 'Sparse/partial'):
            self.verify()

    def test_foreign_shared_metadata_and_alternates(self):
        marker = self.module / '.git'
        original = marker.read_text()
        marker.write_text('gitdir: ' + str(self.workspace / 'upstream/.git') + '\n')
        with self.assertRaisesRegex(ValueError, 'Foreign/shared'):
            self.verify()
        marker.write_text(original)
        (self.cache / 'commondir').write_text(str(self.workspace / 'upstream/.git') + '\n')
        with self.assertRaisesRegex(ValueError, 'Foreign/shared'):
            self.verify()
        (self.cache / 'commondir').unlink()
        (self.cache / 'objects/info/alternates').write_text(str(self.workspace / 'upstream/.git/objects') + '\n')
        with self.assertRaisesRegex(ValueError, 'External Git object alternates'):
            self.verify()

    def test_pin_configuration_mismatch_and_unsafe_path(self):
        with (self.parent / '.gitmodules').open('a') as output:
            output.write('\n# unstaged pin change\n')
        with self.assertRaisesRegex(ValueError, '.gitmodules must match'):
            self.verify()
        fixture_git(self.parent, 'config', '-f', '.gitmodules', 'submodule.tiny.path', '../escape')
        fixture_git(self.parent, 'add', '.gitmodules')
        with self.assertRaisesRegex(ValueError, 'Unsafe dependency path'):
            self.verify()

    def test_nested_gitlinks_remain_empty(self):
        fixture_git(self.module, 'update-index', '--add', '--cacheinfo',
                    '160000,' + self.commit + ',nested')
        fixture_git(self.module, 'commit', '-m', 'fixture nested pin')
        fixture_git(self.parent, 'add', 'contracts/cctp-deposit-helper/modules/tiny')
        nested = self.module / 'nested'
        nested.mkdir()
        self.verify()
        (nested / 'Hidden.sol').write_text('contract Hidden {}\n')
        with self.assertRaisesRegex(ValueError, 'Nested dependencies'):
            self.verify()

    def test_missing_pin_and_duplicate_configuration(self):
        fixture_git(self.parent, 'update-index', '--force-remove',
                    'contracts/cctp-deposit-helper/modules/tiny')
        with self.assertRaisesRegex(ValueError, 'Missing staged Gitlink'):
            self.verify()
        fixture_git(self.parent, 'add', 'contracts/cctp-deposit-helper/modules/tiny')
        fixture_git(self.parent, 'config', '-f', '.gitmodules', 'submodule.alias.path',
                    'contracts/cctp-deposit-helper/modules/tiny')
        fixture_git(self.parent, 'config', '-f', '.gitmodules', 'submodule.alias.url',
                    'https://github.com/fixture/source.git')
        fixture_git(self.parent, 'add', '.gitmodules')
        with self.assertRaisesRegex(ValueError, 'Duplicate or unexpected'):
            self.verify()

    def test_authored_edit_and_new_test_need_no_staging(self):
        (self.root / 'tests/Existing.t.sol').write_text('contract ChangedTest {}\n')
        (self.root / 'tests/NewCase.t.sol').write_text('contract NewCase {}\n')
        with patch.object(b, 'ROOT', self.root), patch('sys.argv', ['bootstrap', '--verify-only']):
            b.main()
        self.assertIn('NewCase.t.sol', fixture_git(self.parent, 'status', '--short'))

    def test_controlled_roots_and_actual_import_shadows(self):
        for path in [self.root / 'reference/cctp/inputs/Extra.sol',
                     self.root / 'reference/xreserve/inputs/Extra.sol',
                     self.root / 'tests/Ignored.sol']:
            with self.subTest(path=path):
                path.write_text('contract Shadow {}\n')
                with self.assertRaisesRegex(ValueError, 'Unexpected reference|Ignored Solidity'):
                    self.verify()
                path.unlink()
        alias = self.root / 'tests/@openzeppelin'
        alias.mkdir()
        with self.assertRaisesRegex(ValueError, 'alias shadow'):
            self.verify()
        alias.rmdir()
        (self.root / 'tests/Escape.sol').symlink_to(self.module / 'Input.sol')
        with self.assertRaisesRegex(ValueError, 'Symlink/dependency'):
            self.verify()

    def test_integrity_failure_precedes_tool_install_or_compile(self):
        (self.module / 'Input.sol').write_text('corrupt\n')
        with patch.object(b, 'ROOT', self.root), patch('sys.argv', ['bootstrap']), \
             patch.object(b, 'archive', side_effect=AssertionError('tool acquisition reached')) as acquisition:
            with self.assertRaisesRegex(ValueError, 'bytes differ'):
                b.main()
            acquisition.assert_not_called()


class ArcArchive(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / 'archive.tar.gz'
        self.cache = self.root / 'cache'

    def archive(self, entries):
        with tarfile.open(self.path, 'w:gz') as archive:
            for name, data, kind in entries:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                if kind:
                    member.type = kind
                    member.linkname = 'elsewhere'
                archive.addfile(member, io.BytesIO(data))
        return {'archiveUrl': self.path.as_uri(), 'archiveSha256': b.digest(self.path.read_bytes())}

    def test_verified_archive_and_offline_cache(self):
        pin = self.archive([('forge', b'pinned binary', None)])
        cached = b.archive(pin, self.cache)
        with patch.object(b.urllib.request, 'urlopen', side_effect=AssertionError('offline network')):
            self.assertEqual(b.archive(pin, self.cache, offline=True), cached)
        cached.write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            b.archive(pin, self.cache, offline=True)

    def test_missing_cache_and_wrong_hash_publish_nothing(self):
        pin = self.archive([('forge', b'binary', None)])
        with self.assertRaisesRegex(ValueError, 'cache missing'):
            b.archive(pin, self.cache, offline=True)
        pin['archiveSha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            b.archive(pin, self.cache)
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_duplicate_nonregular_and_escaping_members(self):
        for entries in [[('forge', b'a', None), ('forge', b'b', None)],
                        [('forge', b'', tarfile.SYMTYPE)],
                        [('../forge', b'a', None)],
                        [('parent', b'', tarfile.SYMTYPE), ('parent/forge', b'a', None)]]:
            with self.subTest(entries=entries):
                self.archive(entries)
                with self.assertRaisesRegex(ValueError, 'Duplicate|Unsafe|Link traversal'):
                    b.members(self.path, lambda name: name.endswith('forge'), False)

    def test_interrupted_download_and_atomic_publication(self):
        pin = self.archive([('forge', b'binary', None)])
        with patch.object(b.os, 'replace', side_effect=OSError('interrupted replace')):
            with self.assertRaisesRegex(OSError, 'interrupted replace'):
                b.archive(pin, self.cache)
        self.assertEqual(list(self.cache.iterdir()), [])
        target = self.root / 'forge'
        target.write_bytes(b'previous')
        with patch.object(b.os, 'replace', side_effect=OSError('interrupted replace')):
            with self.assertRaises(OSError):
                b.publish(target, b'new')
        self.assertEqual(target.read_bytes(), b'previous')
        self.assertEqual(list(self.root.glob('.bootstrap-*')), [])


if __name__ == '__main__':
    unittest.main()
