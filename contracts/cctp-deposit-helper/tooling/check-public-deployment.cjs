// Read-only, fixed-block check of the disabled candidate. This does not activate a route.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const assert = require("node:assert/strict");
const E = require("ethers");
const { readHelperArtifact, serializeAbi } = require("./generate-abi.cjs");
const root = path.resolve(__dirname, "..");
const candidate = JSON.parse(fs.readFileSync(path.join(root, "deployments/arc-testnet.candidate.json")));
const artifact = readHelperArtifact();
const output = process.argv[2];
if (!output) throw Error("Pass the output JSON path");
const endpoint = new URL(process.env.CCTP_ARC_RPC_URL || "https://rpc.testnet.arc.network");
assert(endpoint.protocol === "https:" || (endpoint.protocol === "http:" && ["127.0.0.1", "localhost"].includes(endpoint.hostname)));
const request = new E.FetchRequest(endpoint.href);
request.timeout = 10000;
const provider = new E.JsonRpcProvider(request, undefined, { batchMaxCount: 1 });
const report = { schemaVersion: 1, checkedAt: new Date().toISOString(), qualification: "partial-read-only", checks: [] };
const same = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();
async function check(name, read, expected) {
  const actual = await read();
  const passed = same(actual, expected);
  report.checks.push({ name, expected: String(expected), actual: String(actual), passed });
  assert(passed, name + " differs from candidate");
  return actual;
}
(async () => {
  await check("helper source SHA256", async () => crypto.createHash("sha256").update(fs.readFileSync(path.join(root, "contracts/MidenCctpDepositHelper.sol"))).digest("hex"), candidate.helper.sourceSha256);
  await check("Arc chain", () => provider.send("eth_chainId", []), E.toQuantity(candidate.arc.chainId));
  const head = await provider.send("eth_getBlockByNumber", ["finalized", false]);
  assert(head && head.hash && head.number);
  report.block = { number: BigInt(head.number).toString(), hash: head.hash };
  const at = head.number;
  const read = async (address, signature, args = []) => {
    const iface = new E.Interface([signature]);
    const fn = iface.fragments[0];
    const bytes = await provider.send("eth_call", [{ to: address, data: iface.encodeFunctionData(fn, args) }, at]);
    return iface.decodeFunctionResult(fn, bytes)[0];
  };
  const values = {};
  for (const [name, expected] of Object.entries(candidate.immutables)) {
    const item = artifact.abi.find((entry) => entry.type === "function" && entry.name === name);
    const signature = E.FunctionFragment.from(item).format("full");
    values[name] = await check("helper." + name, () => read(candidate.helper.address, signature), expected);
  }
  assert(artifact.ast, "Run tooling/forge build --ast before this check");
  const declarations = artifact.ast.nodes.flatMap((node) => node.nodeType === "ContractDefinition" ? node.nodes : []).filter((node) => node.mutability === "immutable");
  const runtime = Buffer.from(artifact.deployedBytecode.object.replace(/^0x/, ""), "hex");
  for (const [id, references] of Object.entries(artifact.deployedBytecode.immutableReferences)) {
    const declaration = declarations.find((node) => String(node.id) === id);
    assert(declaration && Object.hasOwn(values, declaration.name));
    const value = values[declaration.name];
    const encoded = E.getBytes(typeof value === "bigint" ? E.toBeHex(value, 32) : E.zeroPadValue(value, 32));
    for (const { start, length } of references) {
      assert.equal(length, 32);
      Buffer.from(encoded).copy(runtime, start);
    }
  }
  await check("helper exact compiler runtime with immutables", () => provider.send("eth_getCode", [candidate.helper.address, at]), E.hexlify(runtime));
  // Keep the large bytecode out of the compact public report.
  report.checks.at(-1).expected = E.keccak256(runtime);
  report.checks.at(-1).actual = E.keccak256(runtime);
  await check("helper runtime hash", async () => E.keccak256(runtime), candidate.helper.runtimeHash);
  const abi = serializeAbi(artifact.abi);
  await check("generated ABI SHA256", async () => crypto.createHash("sha256").update(abi).digest("hex"), candidate.helper.abiSha256);
  for (const dependency of candidate.dependencies) {
    await check(dependency.name + " runtime", async () => E.keccak256(await provider.send("eth_getCode", [dependency.address, at])), dependency.runtimeHash);
    if (dependency.implementation) {
      await check(dependency.name + " implementation", async () => E.getAddress(E.dataSlice(await provider.send("eth_getStorageAt", [dependency.address, dependency.implementationSlot, at]), 12)), dependency.implementation);
      await check(dependency.name + " implementation runtime", async () => E.keccak256(await provider.send("eth_getCode", [dependency.implementation, at])), dependency.implementationRuntimeHash);
    }
  }
  for (const item of candidate.views) {
    const dependency = candidate.dependencies.find((entry) => entry.name === item.name);
    await check(item.name + "." + item.signature + JSON.stringify(item.args), () => read(dependency.address, item.signature, item.args), item.result);
  }
  const depositor = await read(candidate.immutables.xReserve, "function getRemoteDomainDepositor(uint32) view returns(address)", [candidate.immutables.midenDomain]);
  report.remoteDomainDepositor = { address: depositor, codeHash: E.keccak256(await provider.send("eth_getCode", [depositor, at])) };
  report.existingAttesters = [];
  for (const address of ["0x54c42c6e58cf55aca80cda2b058caca135c58dd2", "0x12d4a3a683f016e12e110c3e818dc36e8342674e"]) {
    report.existingAttesters.push({ address, enabled: await read(depositor, "function isAttesterEnabled(address) view returns(bool)", [address]) });
  }
  const again = await provider.send("eth_getBlockByNumber", [at, false]);
  assert.equal(again.hash, head.hash);
  report.status = "PASS_ARC_FIXED_BLOCK_COMPONENT_CHECKS";
})().catch(() => {
  report.status = "FAIL_OR_PROVIDER_UNAVAILABLE";
  process.exitCode = 1;
}).finally(() => {
  provider.destroy();
  fs.writeFileSync(output, JSON.stringify(report, (_, value) => typeof value === "bigint" ? value.toString() : value, 2) + "\n");
  console.log(report.status);
});
