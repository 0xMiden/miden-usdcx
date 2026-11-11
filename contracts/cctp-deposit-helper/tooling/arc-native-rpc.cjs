// Localhost-only real Arc token/runtime test. Funding receiver and reserve are explicitly test stubs.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const E = require('ethers');
const root = path.resolve(__dirname, '..');
const provider = new E.JsonRpcProvider('http://127.0.0.1:18549');
provider.pollingInterval = 20;
const usdc = '0x3600000000000000000000000000000000000000';
const recipient = '0x000000000000000000000000000000008110548cc41852010140bd1325ff0800';
const faucet = '0x000000000000000000000000000000008110548cc41852110140bd1325ff0800';
const txopts = { gasLimit: 12_000_000, maxFeePerGas: 20_000_000_000n, maxPriorityFeePerGas: 0 };
const report = { scope: 'local Arc native USDC; exact product helper; funding receiver and reserve stubs; no Circle/Gateway/Miden/full-route qualification', checks: [] };
const artifact = (file, name) => JSON.parse(fs.readFileSync(path.join(root, 'artifacts', file + '.sol', name + '.json')));
const balance = async a => BigInt(await provider.send('eth_getBalance', [a, 'latest']));
(async () => {
 try {
  assert.equal(await provider.send('eth_chainId', []), '0x7a69');
  const signer = await provider.getSigner(0);
  const caller = await signer.getAddress();
  async function deploy(file, name, args) {
   const a = artifact(file, name);
   const c = await new E.ContractFactory(a.abi, a.bytecode.object, signer).deploy(...args, txopts);
   await c.waitForDeployment(); return c;
  }
  const token = new E.Contract(usdc, ['function balanceOf(address) view returns(uint256)', 'function allowance(address,address) view returns(uint256)', 'function decimals() view returns(uint8)', 'function blacklister() view returns(address)', 'function blacklist(address)', 'function unBlacklist(address)', 'function isBlacklisted(address) view returns(bool)'], signer);
  assert.equal(await token.decimals(), 6n);
  const reserve = await deploy('FaultDependencies', 'FaultReserve', [faucet]);
  const receiver = await deploy('ArcUsdc.t', 'NativeReceiptStub', [usdc]);
  const helper = await deploy('MidenCctpDepositHelper', 'MidenCctpDepositHelper', [receiver.target, '0x0000000000000000000000000000000000002222', usdc, reserve.target, 10007, faucet]);
  const scale = 10n ** 12n, dust = 123456789n, donation = 41n * scale + dust;
  await provider.send('anvil_setBalance', [receiver.target, E.toQuantity(200n * scale)]);
  await provider.send('anvil_setBalance', [helper.target, E.toQuantity(donation)]);
  const w = n => E.toBeHex(n, 32);
  const message = E.solidityPacked(['uint32','uint32','uint32','bytes32','bytes32','bytes32','bytes32','uint32','uint32','uint32','bytes32','bytes32','uint256','bytes32','uint256','uint256','uint256','bytes'], [1,0,26,w(1),w(0x1234),w(0x2222),E.zeroPadValue(helper.target,32),2000,2000,1,w(0xabcd),E.zeroPadValue(helper.target,32),100,w(0x3333),50,3,0,E.AbiCoder.defaultAbiCoder().encode(['uint32','bytes32'],[1,recipient])]);
  const callerBefore = await balance(caller);
  const tx = await helper.receiveAndDeposit(message, '0x', txopts);
  const receipt = await tx.wait();
  const cost = receipt.gasUsed * receipt.gasPrice;
  assert.equal(callerBefore - await balance(caller), cost);
  assert(cost > 0n);
  assert.equal(await balance(helper.target), donation);
  assert.equal(await token.balanceOf(helper.target), 41n);
  assert.equal(await balance(reserve.target), 97n * scale);
  assert.equal(await token.balanceOf(reserve.target), 97n);
  assert.equal(await token.allowance(helper.target, reserve.target), 0n);
  const transfer = E.id('Transfer(address,address,uint256)');
  const tokenEvents = receipt.logs.filter(l => l.address.toLowerCase() === usdc.toLowerCase() && l.topics[0] === transfer && l.topics[2].toLowerCase() === E.zeroPadValue(reserve.target,32).toLowerCase());
  assert.equal(tokenEvents.length, 1); assert.equal(BigInt(tokenEvents[0].data), 97n);
  const systemEvents = receipt.logs.filter(l => l.address.toLowerCase() === '0xfffffffffffffffffffffffffffffffffffffffe' && l.topics[0] === transfer && l.topics[2].toLowerCase() === E.zeroPadValue(reserve.target,32).toLowerCase());
  assert.equal(systemEvents.length, 1); assert.equal(BigInt(systemEvents[0].data), 97n * scale);
  report.checks.push({ check: 'native accounting, SafeERC20 exact approval/pull/reset and caller-only gas', helperNativeBefore: String(donation), helperNativeAfter: String(await balance(helper.target)), dust: String(dust), principal: '97', callerGasCost: String(cost), gasUsed: String(receipt.gasUsed), tokenTransferBaseUnits: '97', systemTransferNativeUnits: String(97n * scale), sameMovementNotAdded: true });
  const authority = await token.blacklister();
  await provider.send('anvil_impersonateAccount', [authority]);
  await provider.send('anvil_setBalance', [authority, E.toQuantity(E.parseEther('100'))]);
  const blacklister = await provider.getSigner(authority);
  await (await token.connect(blacklister).blacklist(reserve.target, txopts)).wait();
  assert(await token.isBlacklisted(reserve.target));
  const beforeFailure = await balance(caller);
  let failedReceipt;
  try { await (await helper.receiveAndDeposit(message, '0x', txopts)).wait(); }
  catch (error) { failedReceipt = error.receipt; }
  assert(failedReceipt, 'Expected a mined local ERC20-blocklist revert with receipt');
  assert.equal(failedReceipt.status, 0);
  assert.equal(failedReceipt.logs.length, 0);
  assert.equal(beforeFailure - await balance(caller), failedReceipt.gasUsed * failedReceipt.gasPrice);
  assert.equal(await balance(helper.target), donation);
  assert.equal(await balance(reserve.target), 97n * scale);
  assert.equal(await receiver.received(), 1n);
  assert.equal(await token.allowance(helper.target, reserve.target), 0n);
  await (await token.connect(blacklister).unBlacklist(reserve.target, txopts)).wait();
  await (await helper.receiveAndDeposit(message, '0x', txopts)).wait();
  assert.equal(await balance(reserve.target), 194n * scale);
  assert.equal(await balance(helper.target), donation);
  await provider.send('anvil_stopImpersonatingAccount', [authority]);
  report.checks.push({ check: 'actual native token blocklist failure, no committed logs/principal/allowance and same calldata retry', failureStatus: 0, failureLogs: 0, successfulCalls: 2 });
  report.status = 'PASS';
 } finally {
  fs.writeFileSync(path.join(root, 'fixtures/arc-native-rpc-result.json'), JSON.stringify(report, null, 2) + '\n');
  provider.destroy();
 }
})().catch(e => { console.error(e); process.exitCode = 1; });
