// Exercise our release boundary against real compiler-derived ABI entries.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const candidate = require("../deployments/arc-testnet.candidate.json");
const { readHelperArtifact, compileWorkerInterface, checkWorkerInterface, serializeAbi } = require("./generate-abi.cjs");
const helper = readHelperArtifact().abi;
const worker = compileWorkerInterface();
const copy = (value) => JSON.parse(JSON.stringify(value));

test("the standalone compiler interface matches the actual helper", () => checkWorkerInterface(helper, worker));
test("a missing helper method fails", () => {
  assert.throws(() => checkWorkerInterface(helper.filter((item) => item.name !== "receiveAndDeposit"), worker));
});
test("a duplicated helper method fails", () => {
  assert.throws(() => checkWorkerInterface([...helper, helper.find((item) => item.name === "tokenMessenger")], worker));
});
test("a renamed worker method fails", () => {
  const changed = copy(worker);
  changed.find((item) => item.name === "receiveAndDeposit").name = "deposit";
  assert.throws(() => checkWorkerInterface(helper, changed));
});
test("changed argument types and names fail", () => {
  for (const [field, value] of [["type", "bytes32"], ["internalType", "bytes32"], ["name", "differentMessage"]]) {
    const changed = copy(worker);
    changed.find((item) => item.name === "receiveAndDeposit").inputs[0][field] = value;
    assert.throws(() => checkWorkerInterface(helper, changed));
  }
});
test("changed return type and missing outputs fail", () => {
  const changed = copy(worker);
  changed.find((item) => item.name === "messageTransmitter").outputs[0].type = "uint256";
  assert.throws(() => checkWorkerInterface(helper, changed));
  changed.find((item) => item.name === "messageTransmitter").outputs = [];
  assert.throws(() => checkWorkerInterface(helper, changed));
});
test("an extra return value fails", () => {
  const changed = copy(worker);
  changed.find((item) => item.name === "messageTransmitter").outputs.push({ name: "extra", type: "address", internalType: "address" });
  assert.throws(() => checkWorkerInterface(helper, changed));
});
test("changed mutability fails", () => {
  const changed = copy(worker);
  changed.find((item) => item.name === "tokenMessenger").stateMutability = "pure";
  assert.throws(() => checkWorkerInterface(helper, changed));
});
test("extra interface entries fail", () => {
  assert.throws(() => checkWorkerInterface(helper, [...worker, { type: "event", name: "Extra" }]));
});
test("the full ABI export retains the historical candidate hash", () => {
  const digest = crypto.createHash("sha256").update(serializeAbi(helper)).digest("hex");
  assert.equal(digest, candidate.helper.abiSha256);
});
