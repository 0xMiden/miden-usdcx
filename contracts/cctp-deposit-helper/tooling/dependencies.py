"""Verify the reviewed Gitlinks and actual dependency bytes before compiling."""
import configparser
import os
import re
from pathlib import Path, PurePosixPath
import stat
import subprocess


def git(directory, *arguments):
    result = subprocess.run(['git', '--no-replace-objects', '-C', str(directory), *arguments],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise ValueError(result.stderr.decode(errors='replace').strip() or
                         f'Git check failed in {directory}: {" ".join(arguments)} (exit {result.returncode})')
    return result.stdout


def confined(root, name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or '..' in path.parts or '\\' in name or str(path) != name:
        raise ValueError(f'Unsafe dependency path: {name}')
    target = root
    for part in path.parts:
        target = target / part
        if target.is_symlink():
            raise ValueError(f'Symlink dependency path: {target}')
    return target


def repository_metadata(directory, expected):
    """A matching checkout must not borrow another checkout's mutable metadata."""
    if directory.is_symlink() or expected.is_symlink():
        raise ValueError(f'Symlink Git metadata: {directory}')
    for option in ['--git-dir', '--git-common-dir']:
        actual = Path(git(directory, 'rev-parse', '--path-format=absolute', option).decode().strip())
        if actual != expected:
            raise ValueError(f'Foreign/shared Git metadata: {directory}: {actual}')
    if (expected / 'objects/info/alternates').exists():
        raise ValueError(f'External Git object alternates: {expected}')
    if git(directory, 'rev-parse', '--show-toplevel').decode().strip() != str(directory):
        raise ValueError(f'Wrong repository root: {directory}')
    options = git(directory, 'config', '--local', '--list').decode().lower().splitlines()
    if any(line.startswith(('core.sparsecheckout=', 'extensions.partialclone=')) and
           line != 'core.sparsecheckout=false' for line in options):
        raise ValueError(f'Sparse/partial dependency checkout is unsupported: {directory}')
    if any('.promisor=true' in line for line in options):
        raise ValueError(f'Partial dependency checkout is unsupported: {directory}')


def parent_pins(root):
    for key in ['GIT_DIR', 'GIT_COMMON_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE',
                'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES']:
        if os.environ.get(key):
            raise ValueError(f'Git environment override is unsupported: {key}')
    parent = Path(git(root, 'rev-parse', '--show-toplevel').decode().strip())
    metadata = parent / '.git'
    if not metadata.is_dir() or metadata.is_symlink():
        raise ValueError('Use an independent clone with its own .git directory')
    repository_metadata(parent, metadata)
    prefix = root.relative_to(parent).as_posix() + '/modules/'
    entries = {}
    for row in git(parent, 'ls-files', '--stage', '-z', '--', prefix).split(b'\0'):
        if not row:
            continue
        fields, name = row.split(b'\t', 1)
        mode, oid, stage = fields.decode().split()
        if mode != '160000' or stage != '0':
            raise ValueError('Dependencies must be unconflicted stage-0 Gitlinks')
        entries[name.decode()] = oid
    configuration = git(parent, 'ls-files', '--stage', '--', '.gitmodules').decode().split()
    if len(configuration) != 4 or configuration[0] != '100644' or configuration[2] != '0':
        raise ValueError('.gitmodules must be a regular stage-0 file')
    content = git(parent, 'show', ':.gitmodules')
    path = confined(parent, '.gitmodules')
    if not path.is_file() or path.read_bytes() != content:
        raise ValueError('.gitmodules must match its staged pin configuration')
    config = configparser.ConfigParser(interpolation=None, strict=True)
    config.read_string(content.decode())
    pins = []
    names = set()
    for section in config.sections():
        if not section.startswith('submodule "') or not section.endswith('"'):
            raise ValueError('Unexpected .gitmodules section')
        name = section[len('submodule "'):-1]
        values = dict(config[section])
        if set(values) != {'path', 'url'}:
            raise ValueError('Submodules require only path and public HTTPS URL')
        path, url = values['path'], values['url']
        confined(metadata, 'modules/' + name)
        confined(parent, path)
        if not path.startswith(prefix) or '/' in path[len(prefix):] or path in names:
            raise ValueError(f'Duplicate or unexpected module path: {path}')
        if not re.fullmatch(r'https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git', url):
            raise ValueError(f'Expected public GitHub HTTPS dependency: {url}')
        if path not in entries:
            raise ValueError(f'Missing staged Gitlink: {path}')
        names.add(path)
        pins.append({'path': path, 'name': name, 'url': url, 'commit': entries[path]})
    if names != set(entries) or not pins:
        raise ValueError('Gitlinks and .gitmodules paths differ')
    return parent, metadata, pins


def verify_module(parent, metadata, pin):
    directory = confined(parent, pin['path'])
    expected = confined(metadata, 'modules/' + pin['name'])
    marker = directory / '.git'
    if not marker.is_file() or marker.is_symlink():
        raise ValueError(f'Missing standard submodule metadata: {directory}')
    pointer = marker.read_text().strip()
    if not pointer.startswith('gitdir: ') or (directory / pointer[8:]).resolve() != expected:
        raise ValueError(f'Foreign/shared submodule metadata: {directory}')
    repository_metadata(directory, expected)
    commit = pin['commit']
    if git(directory, 'rev-parse', 'HEAD').decode().strip() != commit:
        raise ValueError(f'Wrong pinned commit: {directory}')
    flags = git(directory, 'ls-files', '-v', '-z').split(b'\0')
    if any(row and row[:1] != b'H' for row in flags):
        raise ValueError(f'Unsupported sparse/assume-unchanged index: {directory}')
    changed = subprocess.run(['git', '--no-replace-objects', '-C', str(directory),
                              'diff', '--cached', '--quiet', commit, '--'])
    if changed.returncode:
        raise ValueError(f'Staged dependency changes: {directory}')
    files, nested = {}, set()
    for row in git(directory, 'ls-tree', '-r', '-z', commit).split(b'\0'):
        if not row:
            continue
        header, name = row.split(b'\t', 1)
        mode, kind, oid = header.decode().split()
        name = name.decode()
        confined(directory, name)
        if mode == '160000':
            nested.add(name)
        elif kind != 'blob' or mode not in {'100644', '100755'}:
            raise ValueError(f'Nonregular pinned dependency input: {name}')
        else:
            files[name] = (mode, oid)
    allowed_dirs = {'.'} | nested
    for name in [*files, *nested]:
        allowed_dirs.update(str(path) for path in PurePosixPath(name).parents)
    actual = set()
    for current, directories, names in os.walk(directory, followlinks=False):
        relative = Path(current).relative_to(directory)
        for name in list(directories):
            path = Path(current) / name
            key = (relative / name).as_posix()
            if path.is_symlink() or key not in allowed_dirs:
                raise ValueError(f'Unexpected dependency directory: {path}')
            if key in nested:
                if any(path.iterdir()):
                    raise ValueError(f'Nested dependencies must remain uninitialized: {path}')
                directories.remove(name)
        for name in names:
            key = (relative / name).as_posix()
            if key == '.git':
                continue
            path = Path(current) / name
            if key not in files or not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError(f'Unexpected/nonregular dependency input: {path}')
            executable = bool(path.stat().st_mode & 0o111)
            if executable != (files[key][0] == '100755'):
                raise ValueError(f'Dependency mode differs: {path}')
            actual.add(key)
    if actual != set(files):
        raise ValueError(f'Missing pinned dependency files: {directory}')
    # Read actual bytes, bypassing Git status and its size/mtime cache and filters.
    names = sorted(files)
    for start in range(0, len(names), 100):
        batch = names[start:start + 100]
        hashes = git(directory, 'hash-object', '--no-filters', '--', *batch).decode().splitlines()
        if hashes != [files[name][1] for name in batch]:
            raise ValueError(f'Dependency bytes differ from pinned Git objects: {directory}')
    return len(files)


def verify_authored_roots(root):
    for version, expected in [('cctp', {'CodecProbe.sol', 'ReferenceRoots.sol'}),
                              ('xreserve', {'ReferenceRoots.sol'})]:
        directory = confined(root, f'reference/{version}/inputs')
        if not directory.is_dir() or {path.name for path in directory.iterdir()} != expected:
            raise ValueError(f'Unexpected reference input files: {directory}')
        for name in expected:
            path = confined(directory, name)
            if not path.is_file():
                raise ValueError(f'Missing reference entrypoint: {path}')
    aliases = {'@openzeppelin', 'forge-std', '@memview-sol', '@gateway'}
    for name in ['contracts', 'tests', 'scripts']:
        directory = confined(root, name)
        for current, directories, files in os.walk(directory, followlinks=False):
            for child in [*directories, *files]:
                path = Path(current) / child
                if path.is_symlink() or child in aliases:
                    raise ValueError(f'Symlink/dependency alias shadow: {path}')
        ignored = subprocess.run(['git', '--no-replace-objects', '-C', str(root), 'ls-files', '--others', '--ignored',
                                  '--exclude-standard', '-z', '--', name], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, check=True).stdout.split(b'\0')
        if any(path.endswith(b'.sol') for path in ignored):
            raise ValueError(f'Ignored Solidity compiler input in {directory}')


def offline_cache(metadata, pin):
    cache = confined(metadata, 'modules/' + pin['name'])
    if not cache.is_dir() or (cache / 'commondir').exists() or (cache / 'objects/info/alternates').exists():
        raise ValueError(f'Offline dependency cache missing or shared: {pin["path"]}; initialize it online first')
    environment = os.environ.copy()
    environment['GIT_NO_LAZY_FETCH'] = '1'
    environment['GIT_NO_REPLACE_OBJECTS'] = '1'
    # The cached checkout may be absent; object inspection needs an existing work tree.
    result = subprocess.run(['git', '--no-replace-objects', '--git-dir=' + str(cache),
                             '--work-tree=' + str(metadata.parent),
                             'rev-list', '--no-walk', '--objects',
                             '--missing=print', '--no-object-names', pin['commit']],
                            env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode or any(line.startswith(b'?') for line in result.stdout.splitlines()):
        raise ValueError(f'Offline pinned objects missing: {pin["path"]}; initialize it online first. '
                         + result.stderr.decode(errors='replace').strip())


def prepare(root, offline=False, initialize=False):
    parent, metadata, pins = parent_pins(root)
    verify_authored_roots(root)
    missing = []
    for pin in pins:
        directory = confined(parent, pin['path'])
        if directory.exists() and any(directory.iterdir()):
            count = verify_module(parent, metadata, pin)
            print(f'Verified {pin["path"]} at {pin["commit"]}: {count} pinned files')
        else:
            missing.append(pin)
    if missing and not initialize:
        raise ValueError('Missing dependencies; run python3 tooling/bootstrap.py first')
    # --no-fetch alone can still clone. Reject absent caches/objects before update.
    if offline:
        for pin in pins:
            offline_cache(metadata, pin)
    if missing:
        command = ['git', '--no-replace-objects', '-C', str(parent), '-c', 'credential.helper=',
                   '-c', 'core.useReplaceRefs=false',
                   'submodule', 'update', '--init', '--checkout']
        if offline:
            command.append('--no-fetch')
        # Git clears local repository environment in submodules; -c propagates to checkout children.
        environment = {**os.environ, 'GIT_NO_REPLACE_OBJECTS': '1'}
        subprocess.run([*command, '--', *[pin['path'] for pin in missing]], env=environment, check=True)
    for pin in missing:
        count = verify_module(parent, metadata, pin)
        print(f'Verified {pin["path"]} at {pin["commit"]}: {count} pinned files')
    return pins
