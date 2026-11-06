const fs = require('node:fs'), path = require('node:path'), assert = require('node:assert/strict'), crypto = require('node:crypto');
const E = require('ethers');
const root = path.resolve(__dirname, '..');
const artifact = JSON.parse(fs.readFileSync(path.join(root, 'reference/cctp/artifacts/CodecProbe.sol/CodecProbe.json')));
const inputPath = path.join(root, 'fixtures/codec-vectors.json');
const golden = JSON.parse(fs.readFileSync(inputPath));
const provider = new E.JsonRpcProvider('http://127.0.0.1:18549');
const iface = new E.Interface(artifact.abi), target = '0x0000000000000000000000000000000000010011';
const call = async (fn, args) => iface.decodeFunctionResult(fn, await provider.send('eth_call', [{ to: target, data: iface.encodeFunctionData(fn, args) }, 'latest', { [target]: { code: artifact.deployedBytecode.object } }]));
(async () => {
 try {
  const rows = [];
  for (const row of golden.vectors) {
   const hook = (await call('hook', [row.recipient]))[0];
   const body = (await call('body', [1, row.sourceToken, row.helper, row.grossAmount, row.sourceMessageSender, row.maxFee, hook]))[0];
   const sender = '0x' + row.sourceMessage.slice(2 + 44 * 2, 2 + 76 * 2);
   const message = (await call('message', [1, row.sourceDomain, 26, sender, row.messenger, row.helper, 2000, body]))[0];
   assert.equal(message, row.sourceMessage); assert.equal(hook, row.hook);
   assert.equal(E.getBytes(message).length, 440); assert.equal(E.getBytes(hook).length, 64);
   const fields = await call('decodeBody', ['0x' + row.syntheticAttestedMessage.slice(2 + 148 * 2)]);
   assert.equal(fields[0], BigInt(row.grossAmount)); assert.equal(fields[1], BigInt(row.maxFee)); assert.equal(fields[2], BigInt(row.feeExecuted)); assert.equal(fields[4], row.hook);
   const source = E.getBytes(message), attested = E.getBytes(row.syntheticAttestedMessage);
   const permitted = i => (i >= 12 && i < 44) || (i >= 144 && i < 148) || (i >= 312 && i < 344) || (i >= 344 && i < 376);
   for (let i=0; i<440; i++) if (!permitted(i)) assert.equal(source[i],attested[i]);
   rows.push({id:row.id,sourceMessageKeccak256:E.keccak256(message),hookKeccak256:E.keccak256(hook),matchesCanonical:true});
  }
  fs.writeFileSync(path.join(root,'fixtures/vector-regeneration.json'),JSON.stringify({status:'PASS',scope:'actual pinned Circle 0.7.6 formatter via localhost eth_call, synthetic attestation fields only; no source burn or Circle-issued signature',canonicalFileSha256:crypto.createHash('sha256').update(fs.readFileSync(inputPath)).digest('hex'),compiler:artifact.metadata?.compiler??artifact.rawMetadata,rows},null,2)+'\n');
  console.log(`${rows.length} golden vectors regenerated with the actual Circle formatter; exact matches.`);
 } finally { provider.destroy(); }
})().catch(e=>{console.error(e);process.exitCode=1});
