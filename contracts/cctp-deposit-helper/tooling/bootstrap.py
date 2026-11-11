#!/usr/bin/env python3
"""Project-local pinned tools and reference sources; no global installation.

Run integrity tests with: python3 -m unittest discover -s tooling -p test_bootstrap.py
--offline reconstructs reference sources from verified cache; npm/tools must already exist.
"""
import argparse
import hashlib
import json
import os
import platform
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checked(data, expected, label):
    if digest(data) != expected:
        raise ValueError(f'SHA256 mismatch: {label}')
    return data


def relative(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or '..' in path.parts or '\\' in name:
        raise ValueError(f'Unsafe archive/destination path: {name}')
    return path


def destination(root, name):
    path = root / relative(name)
    if root.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f'Destination outside owned tree: {name}')
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError(f'Symlink destination: {part}')
        if part == root:
            break
    return path


def publish(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.bootstrap-', delete=False) as out:
            temporary = Path(out.name)
            out.write(data)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def archive(pin, cache, offline=False):
    path = destination(cache, pin['archiveSha256'] + '.tar.gz')
    if path.exists():
        checked(path.read_bytes(), pin['archiveSha256'], path)
        return path
    if offline:
        raise ValueError(f'Verified archive cache missing: {path}')
    cache.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=cache, prefix='.download-', delete=False) as out:
            temporary = Path(out.name)
            with urllib.request.urlopen(pin['archiveUrl'], timeout=60) as response:
                size = 0
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > 256 * 1024 * 1024:
                        raise ValueError('Pinned archive exceeds 256MiB download limit')
                    out.write(chunk)
        checked(temporary.read_bytes(), pin['archiveSha256'], pin['archiveUrl'])
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return path


def members(path, select, strip_root=True, skip_directories=False):
    """Read selected regular members only; never extract archive paths to disk."""
    found = {}
    with tarfile.open(path) as tar:
        entries = tar.getmembers()
        links = {str(relative(m.name)) for m in entries if m.issym() or m.islnk()}
        for member in entries:
            parts = relative(member.name).parts
            name = str(PurePosixPath(*parts[1:])) if strip_root else str(PurePosixPath(*parts))
            if (skip_directories and member.isdir()) or not select(name):
                continue
            if name in found or not member.isfile():
                raise ValueError(f'Duplicate or nonregular mapped member: {member.name}')
            if any(str(parent) in links for parent in PurePosixPath(member.name).parents):
                raise ValueError(f'Link traversal in mapped member: {member.name}')
            found[name] = tar.extractfile(member).read()
    return found


def load_provenance(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f'Duplicate provenance key: {key}')
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=unique)


def source_entries(provenance):
    entries = []
    paths = set()
    for group in provenance['sources']:
        destination_root = relative(group['destination'])
        destination_root.relative_to('reference')
        source_root = relative(group['upstreamRoot']) if group['upstreamRoot'] else PurePosixPath()
        if group['upstream'] not in provenance['upstreams']:
            raise ValueError('Unmapped reference upstream')
        for name, sha256 in group['files'].items():
            name = relative(name)
            path = str(destination_root / name)
            if path in paths:
                raise ValueError(f'Duplicate destination: {path}')
            paths.add(path)
            entries.append({'path': path, 'upstream': group['upstream'],
                            'upstreamPath': str(source_root / name), 'sha256': sha256})
    return entries


def materialize(root, provenance, offline=False):
    reference = destination(root, 'reference')
    cache = destination(root, 'tooling/reference-cache')
    sources = source_entries(provenance)
    paths = set()
    for entry in sources + provenance['licenses']:
        name = str(relative(entry['path']).relative_to('reference'))
        path = destination(reference, name)
        if entry['path'] in paths:
            raise ValueError(f'Duplicate destination: {entry["path"]}')
        paths.add(entry['path'])
        if path.exists() or entry in provenance['licenses']:
            checked(path.read_bytes(), entry['sha256'], path)
    staged = []
    for key, pin in provenance['upstreams'].items():
        mapped = {str(relative(e['upstreamPath'])) for e in sources if e['upstream'] == key}
        data = members(archive(pin, cache, offline), mapped.__contains__)
        if data.keys() != mapped:
            raise ValueError(f'Missing mapped members in {key}: {sorted(mapped - data.keys())}')
        for entry in sources:
            if entry['upstream'] == key:
                staged.append((entry, checked(data[entry['upstreamPath']], entry['sha256'], entry['path'])))
    if len(staged) != len(sources):
        raise ValueError('Unmapped reference upstream')
    # Validate the entire set before publishing any source, including on warm runs.
    for entry, data in staged:
        path = destination(reference, str(relative(entry['path']).relative_to('reference')))
        if not path.exists():
            publish(path, data)
    for entry in sources + provenance['licenses']:
        path = destination(reference, str(relative(entry['path']).relative_to('reference')))
        checked(path.read_bytes(), entry['sha256'], path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline', action='store_true', help='require verified cache and existing tools/npm')
    args = parser.parse_args()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        raise SystemExit('This verified bootstrap supports macOS ARM64 only; qualify the official archive for your platform explicitly.')
    lock = json.loads((ROOT / 'DEPENDENCIES.lock.json').read_text())
    materialize(ROOT, load_provenance(ROOT / 'reference/PROVENANCE.json'), args.offline)
    cache = destination(ROOT, 'tooling/reference-cache')
    pin = dict(lock['arcFoundry'], archiveUrl='https://github.com/circlefin/arc-foundry/releases/download/v0.8.0-2/arc-foundry-v0.8.0-2-aarch64-apple-darwin.tar.gz')
    data = members(archive(pin, cache, args.offline), {'forge', 'anvil'}.__contains__, False)
    if data.keys() != {'forge', 'anvil'}:
        raise ValueError('Missing pinned Arc tools')
    for name, value in data.items():
        publish(destination(ROOT / 'tooling', name), checked(value, pin['binarySha256'][name], name))
        (ROOT / 'tooling' / name).chmod(0o755)
    for key, repo, directory, source, licenses in [
        ('openzeppelin', 'OpenZeppelin/openzeppelin-contracts', 'openzeppelin-contracts', 'contracts', ['LICENSE']),
        ('forgeStd', 'foundry-rs/forge-std', 'forge-std', 'src', ['LICENSE-APACHE', 'LICENSE-MIT']),
    ]:
        pin = dict(lock[key], archiveUrl=f'https://codeload.github.com/{repo}/tar.gz/{lock[key]["commit"]}')
        data = members(archive(pin, cache, args.offline), lambda n: n.startswith(source + '/') or n in licenses, skip_directories=True)
        for name, value in data.items():
            publish(destination(ROOT, f'modules/{directory}/{name}'), value)
    checked((ROOT / 'tooling/package-lock.json').read_bytes(), lock['npmLockSha256'], 'npm lock')
    if not args.offline:
        subprocess.run(['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund'], cwd=ROOT / 'tooling', check=True)
    for compiler, version in [('076', '0.7.6+commit.7338295f'), ('0829', '0.8.29+commit.ab55807c')]:
        output = subprocess.check_output([str(ROOT / 'tooling' / ('solc-' + compiler)), '--version'], text=True)
        if version not in output:
            raise ValueError(f'Compiler version mismatch: {compiler}')
        print(output.strip())
    print('Pinned local tools, all 97 reference sources and 9 retained licenses verified. No global installation.')


if __name__ == '__main__':
    main()
