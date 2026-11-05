#!/usr/bin/env python3
"""Project-local pinned tools. Downloads only the selected official macOS ARM64 release."""
import hashlib,json,platform,subprocess,tarfile,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
lock=json.loads((ROOT/'DEPENDENCIES.lock.json').read_text())
if platform.system()!='Darwin' or platform.machine()!='arm64':
 raise SystemExit('This verified bootstrap supports macOS ARM64 only; qualify the official archive for your platform explicitly.')
url='https://github.com/circlefin/arc-foundry/releases/download/v0.8.0-2/arc-foundry-v0.8.0-2-aarch64-apple-darwin.tar.gz'
archive=ROOT/'tooling/arc-release.tar.gz'
if not archive.exists():urllib.request.urlretrieve(url,archive)
assert hashlib.sha256(archive.read_bytes()).hexdigest()==lock['arcFoundry']['archiveSha256']
with tarfile.open(archive) as tar:
 for name in ['forge','anvil']:
  data=tar.extractfile(name).read()
  assert hashlib.sha256(data).hexdigest()==lock['arcFoundry']['binarySha256'][name]
  dest=ROOT/'tooling'/name;dest.write_bytes(data);dest.chmod(0o755)
for key,repo,directory,source,licenses in [
 ('openzeppelin','OpenZeppelin/openzeppelin-contracts','openzeppelin-contracts','contracts',['LICENSE']),
 ('forgeStd','foundry-rs/forge-std','forge-std','src',['LICENSE-APACHE','LICENSE-MIT'])]:
 pin=lock[key]
 archive=ROOT/'tooling'/(directory+'.tar.gz')
 if not archive.exists():
  urllib.request.urlretrieve(f"https://codeload.github.com/{repo}/tar.gz/{pin['commit']}",archive)
 assert hashlib.sha256(archive.read_bytes()).hexdigest()==pin['archiveSha256'],key
 with tarfile.open(archive) as tar:
  for member in tar:
   relative=Path(*Path(member.name).parts[1:])
   if not member.isfile() or not relative.parts or '..' in relative.parts:continue
   if relative.parts[0]!=source and str(relative) not in licenses:continue
   dest=ROOT/'modules'/directory/relative
   dest.parent.mkdir(parents=True,exist_ok=True)
   dest.write_bytes(tar.extractfile(member).read())
assert hashlib.sha256((ROOT/'tooling/package-lock.json').read_bytes()).hexdigest()==lock['npmLockSha256']
subprocess.run(['npm','ci','--ignore-scripts','--no-audit','--no-fund'],cwd=ROOT/'tooling',check=True)
for compiler,version in [('076','0.7.6+commit.7338295f'),('0829','0.8.29+commit.ab55807c')]:
 output=subprocess.check_output([str(ROOT/'tooling'/('solc-'+compiler)),'--version'],text=True)
 assert version in output
 print(output.strip())
for report in json.loads((ROOT/'fixtures/reference-sources.json').read_text()):
 for name,entry in report['sourceManifest'].items():
  assert hashlib.sha256((ROOT/'reference'/report['kind']/name).read_bytes()).hexdigest()==entry['sha256'],name
print('Pinned local tools and all97 unmodified reference sources verified. No global installation.')
