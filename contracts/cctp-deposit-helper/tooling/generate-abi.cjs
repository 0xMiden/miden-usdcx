// Run after the pinned helper build. --check validates release parity without an ABI export file.
const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");
const solc = require("solc0829");
const root = path.resolve(__dirname, "..");
const source = "interfaces/IMidenCctpDepositHelper.sol";

function readHelperArtifact() {
  try {
    return JSON.parse(fs.readFileSync(path.join(root, "artifacts/MidenCctpDepositHelper.sol/MidenCctpDepositHelper.json")));
  } catch (error) {
    if (error.code === "ENOENT") throw Error("Helper artifact missing; run python3 tooling/run-local-gates.py first.");
    throw error;
  }
}

function compileWorkerInterface() {
  const input = {
    language: "Solidity",
    sources: { [source]: { content: fs.readFileSync(path.join(root, source), "utf8") } },
    settings: { outputSelection: { "*": { "*": ["abi"] } } },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter((item) => item.severity === "error");
  assert.equal(errors.length, 0, errors.map((item) => item.formattedMessage).join("\n"));
  assert.deepEqual(Object.keys(output.contracts?.[source] || {}), ["IMidenCctpDepositHelper"],
    "standalone source must compile exactly the worker interface");
  return output.contracts[source].IMidenCctpDepositHelper.abi;
}

function checkWorkerInterface(helper, worker) {
  assert.equal(worker.length, 3, "worker interface must contain exactly three methods");
  for (const name of ["receiveAndDeposit", "messageTransmitter", "tokenMessenger"]) {
    const expected = worker.filter((item) => item.type === "function" && item.name === name);
    const actual = helper.filter((item) => item.type === "function" && item.name === name);
    assert.equal(expected.length, 1, "worker method missing or duplicated: " + name);
    assert.equal(actual.length, 1, "helper method missing or duplicated: " + name);
    assert.deepEqual(actual[0], expected[0], "worker/helper ABI differs: " + name);
  }
}

function serializeAbi(abi) {
  return JSON.stringify(abi, null, 2) + "\n";
}

function checkRelease() {
  const artifact = readHelperArtifact();
  const lock = JSON.parse(fs.readFileSync(path.join(root, "DEPENDENCIES.lock.json")));
  const metadata = typeof artifact.metadata === "string" ? JSON.parse(artifact.metadata) : artifact.metadata;
  assert.equal(solc.version(), lock.helperCompiler.version);
  assert.equal(metadata.compiler.version, lock.helperCompiler.version.replace(".Emscripten.clang", ""));
  assert.equal(metadata.settings.evmVersion, lock.helperCompiler.evmVersion);
  assert.deepEqual(metadata.settings.optimizer, { enabled: true, runs: lock.helperCompiler.optimizerRuns });
  assert.equal(metadata.settings.viaIR ?? false, lock.helperCompiler.viaIR);
  checkWorkerInterface(artifact.abi, compileWorkerInterface());
  return artifact;
}

if (require.main === module) {
  try {
    const artifact = checkRelease();
    if (!process.argv.includes("--check")) {
      fs.mkdirSync(path.join(root, "abi"), { recursive: true });
      fs.writeFileSync(path.join(root, "abi/MidenCctpDepositHelper.json"), serializeAbi(artifact.abi));
    }
    console.log("HELPER_COMPILER_ABI_MATCH");
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

module.exports = { readHelperArtifact, compileWorkerInterface, checkWorkerInterface, serializeAbi };
