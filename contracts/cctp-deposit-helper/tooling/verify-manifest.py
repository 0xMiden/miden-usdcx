#!/usr/bin/env python3
"""Check retained source identities and explicitly keep live deployment unqualified."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
for report in json.loads((ROOT/'fixtures/reference-sources.json').read_text()):
 for name,entry in report['sourceManifest'].items():
  assert hashlib.sha256((ROOT/'reference'/report['kind']/name).read_bytes()).hexdigest()==entry['sha256'],name
m=json.loads((ROOT/'fixtures/deployment-manifest.dry-run.json').read_text())
assert m['status']=='UNQUALIFIED_NO_DEPLOYMENT'
assert m['helper']['address'] is None and m['helper']['deployedRuntimeKeccak256'] is None
assert m['chainId'] is None and m['constructor']['expectedMidenFaucet'] is None
assert not m['circleHelperDepositorAcceptance'] and not m['zeroFeeAttestationPolicyConfirmed']
print('97 source hashes verified. Live deployment manifest intentionally incomplete and unqualified.')
