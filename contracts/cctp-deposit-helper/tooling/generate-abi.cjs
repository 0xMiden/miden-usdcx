// Run after the pinned helper build. --check verifies the committed compiler output.
const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");
const root = path.resolve(__dirname, "..");
const artifact = JSON.parse(
  fs.readFileSync(path.join(root, "artifacts/MidenCctpDepositHelper.sol/MidenCctpDepositHelper.json")),
);
const lock = JSON.parse(fs.readFileSync(path.join(root, "DEPENDENCIES.lock.json")));
const metadata = typeof artifact.metadata === "string" ? JSON.parse(artifact.metadata) : artifact.metadata;
assert.equal(require("solc0829").version(), lock.helperCompiler.version);
assert.equal(metadata.compiler.version, lock.helperCompiler.version.replace(".Emscripten.clang", ""));
assert.equal(metadata.settings.evmVersion, lock.helperCompiler.evmVersion);
assert.deepEqual(metadata.settings.optimizer, { enabled: true, runs: lock.helperCompiler.optimizerRuns });
assert.equal(metadata.settings.viaIR ?? false, lock.helperCompiler.viaIR);
const destination = path.join(root, "abi/MidenCctpDepositHelper.json");
const content = JSON.stringify(artifact.abi, null, 2) + "\n";
if (process.argv.includes("--check")) {
  assert.equal(
    fs.readFileSync(destination, "utf8"),
    content,
    "committed ABI differs from pinned compiler output",
  );
} else {
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.writeFileSync(destination, content);
}
console.log("HELPER_COMPILER_ABI_MATCH");
