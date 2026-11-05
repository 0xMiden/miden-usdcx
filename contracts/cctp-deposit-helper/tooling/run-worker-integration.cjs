// Local-only executing fixture. Every key is generated in memory for this loopback run.
const fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  http = require("node:http"),
  net = require("node:net"),
  os = require("node:os"),
  assert = require("node:assert/strict");
const { spawn, spawnSync } = require("child_process");
const H = path.resolve(__dirname, "..");
const W = path.resolve(H, "../..");
const E = require("ethers");
const outputRoot = process.argv[2] ? path.resolve(process.argv[2]) : os.tmpdir();
fs.mkdirSync(outputRoot, { recursive: true });
const run = fs.mkdtempSync(path.join(outputRoot, "cctp-worker-integration-"));
const safeEnv = { ...process.env, AWS_EC2_METADATA_DISABLED: "true" };
for (const name of Object.keys(safeEnv))
  if (name.startsWith("AWS_") && name !== "AWS_EC2_METADATA_DISABLED") delete safeEnv[name];
const awsConfig = path.join(run, "empty-aws-config"),
  awsCredentials = path.join(run, "empty-aws-credentials");
fs.writeFileSync(awsConfig, "");
fs.writeFileSync(awsCredentials, "");
Object.assign(safeEnv, {
  AWS_CONFIG_FILE: awsConfig,
  AWS_SHARED_CREDENTIALS_FILE: awsCredentials,
});
const report = {
  category:
    "Ethereum-compatible genuine Circle reference/helper/xReserve execution; local TestToken and GatewayPullStub; no Arc-native/public/Miden qualification",
  run,
  started: new Date().toISOString(),
  artifacts: [],
  phases: [],
};
let anvil, provider, control, iris, transport, test;
async function waitChild(child, timeout) {
  let timer;
  try {
    return await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", resolve);
      timer = setTimeout(() => child.kill("SIGKILL"), timeout);
    });
  } finally {
    clearTimeout(timer);
  }
}
async function stopChild(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const stopped = waitChild(child, 5000);
  child.kill("SIGTERM");
  await stopped;
}
const sendChecks = {
  preSendCalls: 0,
  preSendViolations: 0,
  fixedTargetValuePayloadChecks: 0,
  rejections: [],
};
function save(name, value) {
  fs.writeFileSync(path.join(run, name), JSON.stringify(value, null, 2) + "\n");
}
function stage(name) {
  report.phases.push({ name, at: new Date().toISOString() });
  save("progress.json", report);
  process.stdout.write(name + "\n");
}
async function port() {
  const server = net.createServer();
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const p = server.address().port;
  await new Promise((r) => server.close(r));
  return p;
}
async function rpc(url, method, params = []) {
  if (new URL(url).hostname !== "127.0.0.1") throw Error("nonloopback RPC refused");
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(10000),
  });
  const value = await response.json();
  if (value.error) throw Error(value.error.message);
  return value.result;
}
function artifact(file) {
  const full = path.join(H, file),
    bytes = fs.readFileSync(full),
    a = JSON.parse(bytes);
  report.artifacts.push({
    path: full,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    compiler: a.metadata?.compiler?.version,
  });
  return a;
}
function bytecode(a) {
  return a.bytecode.object.startsWith("0x") ? a.bytecode.object : "0x" + a.bytecode.object;
}
async function command(name, executable, args, cwd) {
  const child = spawn(executable, args, {
    cwd,
    env: safeEnv,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "",
    stderr = "";
  child.stdout.on("data", (b) => (stdout += b));
  child.stderr.on("data", (b) => (stderr += b));
  const code = await waitChild(child, 600000);
  fs.writeFileSync(path.join(run, name + ".log"), stdout + stderr);
  report.phases.push({
    name,
    command: [executable, ...args],
    cwd: path.relative(W, cwd),
    exit: code,
  });
  if (code !== 0) throw Error(name + " failed; inspect " + path.join(run, name + ".log"));
  return stdout;
}
(async () => {
  for (const [name, cwd] of [
    ["cctp-reference", path.join(H, "reference/cctp")],
    ["xreserve-reference", path.join(H, "reference/xreserve")],
    ["helper", H],
  ])
    await command(name, path.join(H, "tooling/forge"), ["build"], cwd);
  const messages = await command(
    "cargo-test-build",
    "cargo",
    ["test", "--locked", "-p", "cctp-deposit-relayer", "--lib", "--no-run", "--message-format=json"],
    W,
  );
  const executables = messages
    .split("\n")
    .filter(Boolean)
    .flatMap((line) => {
      try {
        const row = JSON.parse(line);
        return row.reason === "compiler-artifact" &&
          row.profile?.test &&
          row.target?.name === "cctp_deposit_relayer" &&
          row.executable
          ? [row.executable]
          : [];
      } catch {
        return [];
      }
    });
  assert.equal(executables.length, 1, "Cargo must resolve exactly one library test executable");
  const executable = executables[0];
  report.testExecutable = {
    path: executable,
    sha256: crypto.createHash("sha256").update(fs.readFileSync(executable)).digest("hex"),
  };
  const p = await port(),
    url = `http://127.0.0.1:${p}`;
  const log = fs.openSync(path.join(run, "anvil.log"), "w");
  anvil = spawn(
    path.join(H, "tooling/anvil"),
    [
      "--quiet",
      "--network",
      "ethereum",
      "--accounts",
      "0",
      "--host",
      "127.0.0.1",
      "--port",
      String(p),
      "--chain-id",
      "31337",
    ],
    { cwd: run, stdio: ["ignore", log, log] },
  );
  save("OWNED-PROCESSES.json", {
    anvilPid: anvil.pid,
    anvilCwd: run,
    loopbackRpc: url,
    owner: "run-worker-integration.cjs",
    noWalletFiles: true,
  });
  for (let i = 0; i < 100; i++) {
    try {
      if ((await rpc(url, "eth_chainId")) === "0x7a69") break;
    } catch {}
    await new Promise((r) => setTimeout(r, 30));
    if (i === 99) throw Error("local Anvil did not start");
  }
  provider = new E.JsonRpcProvider(url, 31337, {
    staticNetwork: true,
    batchMaxCount: 1,
  });
  provider.pollingInterval = 40;
  const owner = new E.Wallet(E.hexlify(crypto.randomBytes(32)), provider),
    gas = new E.Wallet(E.hexlify(crypto.randomBytes(32))),
    attester = new E.Wallet(E.hexlify(crypto.randomBytes(32)));
  await rpc(url, "anvil_setBalance", [owner.address, "0x100000000000000000000"]);
  await rpc(url, "anvil_setBalance", [gas.address, "0x100000000000000000000"]);
  const signer = new E.NonceManager(owner),
    oa = owner.address,
    pad = (a) => E.zeroPadValue(a, 32);
  const tokenA = artifact("artifacts/FaultDependencies.sol/TestToken.json"),
    gatewayA = artifact("artifacts/FaultDependencies.sol/GatewayPullStub.json");
  const mtA = artifact("reference/cctp/artifacts/MessageTransmitterV2.sol/MessageTransmitterV2.json"),
    tmA = artifact("reference/cctp/artifacts/TokenMessengerV2.sol/TokenMessengerV2.json"),
    minterA = artifact("reference/cctp/artifacts/TokenMinterV2.sol/TokenMinterV2.json"),
    proxyA = artifact("reference/cctp/artifacts/AdminUpgradableProxy.sol/AdminUpgradableProxy.json");
  const reserveA = artifact("reference/xreserve/artifacts/xReserve.sol/xReserve.json"),
    domainA = artifact("reference/xreserve/artifacts/RemoteDomainDepositor.sol/RemoteDomainDepositor.json"),
    placeholderA = artifact(
      "reference/xreserve/artifacts/UpgradeablePlaceholder.sol/UpgradeablePlaceholder.json",
    ),
    ercA = artifact("reference/xreserve/artifacts/ERC1967Proxy.sol/ERC1967Proxy.json"),
    helperA = artifact("artifacts/MidenCctpDepositHelper.sol/MidenCctpDepositHelper.json");
  async function deploy(a, args = []) {
    const c = await new E.ContractFactory(a.abi, bytecode(a), signer).deploy(...args);
    const receipt = await c.deploymentTransaction().wait();
    return { contract: c, address: await c.getAddress(), receipt };
  }
  async function tx(promise) {
    return (await promise).wait();
  }
  async function finalize() {
    await rpc(url, "anvil_mine", ["0x40"]);
  }
  async function cctp(domain) {
    const minter = await deploy(minterA, [oa]);
    const mtImpl = await deploy(mtA, [domain, 1]);
    const mtInit = new E.Interface(mtA.abi).encodeFunctionData("initialize", [
      oa,
      oa,
      oa,
      oa,
      [attester.address],
      1,
      8192,
    ]);
    const mt = await deploy(proxyA, [mtImpl.address, oa, mtInit]);
    const mtC = new E.Contract(mt.address, mtA.abi, signer);
    const tmImpl = await deploy(tmA, [mt.address, 1]);
    const feeRecipient = E.Wallet.createRandom().address;
    const tmInit = new E.Interface(tmA.abi).encodeFunctionData("initialize", [
      [oa, oa, feeRecipient, oa, minter.address, oa],
      0,
      [],
      [],
    ]);
    const tm = await deploy(proxyA, [tmImpl.address, oa, tmInit]);
    const tmC = new E.Contract(tm.address, tmA.abi, signer);
    await tx(minter.contract.addLocalTokenMessenger(tm.address));
    return { minter, mt, mtC, mtImpl, tm, tmC, tmImpl };
  }
  stage("deploying real source/destination CCTP reference contracts");
  const srcToken = await deploy(tokenA),
    dstToken = await deploy(tokenA),
    source = await cctp(0),
    destination = await cctp(26);
  await tx(source.tmC.addRemoteTokenMessenger(26, pad(destination.tm.address)));
  await tx(destination.tmC.addRemoteTokenMessenger(0, pad(source.tm.address)));
  await tx(source.minter.contract.setMaxBurnAmountPerMessage(srcToken.address, 1000000000000n));
  await tx(destination.minter.contract.linkTokenPair(dstToken.address, 0, pad(srcToken.address)));
  stage("deploying genuine xReserve proxy/domain and immutable helper");
  const gateway = await deploy(gatewayA),
    placeholder = await deploy(placeholderA),
    proxy = await deploy(ercA, [
      placeholder.address,
      new E.Interface(placeholderA.abi).encodeFunctionData("initialize", [oa]),
    ]),
    domain = await deploy(domainA),
    reserveImpl = await deploy(reserveA, [
      gateway.address,
      gateway.address,
      destination.tm.address,
      destination.tm.address,
    ]);
  const reserve = new E.Contract(proxy.address, reserveA.abi, signer);
  const init = new E.Interface(reserveA.abi).encodeFunctionData("initialize", [
    26,
    oa,
    oa,
    oa,
    [dstToken.address],
    domain.address,
  ]);
  await tx(reserve.upgradeToAndCall(reserveImpl.address, init));
  const remoteAttesters = [E.Wallet.createRandom().address, E.Wallet.createRandom().address].sort((a, b) =>
    BigInt(a) < BigInt(b) ? -1 : 1,
  );
  await tx(reserve.registerRemoteDomain(10007, oa, oa, remoteAttesters, 2, 1, E.ZeroAddress));
  const recipient = "0x000000000000000000000000000000008110548cc41852010140bd1325ff0800",
    faucet = "0x000000000000000000000000000000008110548cc41852110140bd1325ff0800";
  await tx(reserve.registerRemoteToken(dstToken.address, 10007, faucet));
  const helper = await deploy(helperA, [
    destination.mt.address,
    destination.tm.address,
    dstToken.address,
    proxy.address,
    10007,
    faucet,
  ]);
  const hook = E.AbiCoder.defaultAbiCoder().encode(["uint32", "bytes32"], [1, recipient]);
  const records = new Map(),
    captures = [];
  async function bind(receipt) {
    const messages = receipt.logs
      .filter((l) => l.address.toLowerCase() === source.mt.address.toLowerCase())
      .map((l) => {
        try {
          return source.mtC.interface.parseLog(l);
        } catch {
          return null;
        }
      })
      .filter((l) => l?.name === "MessageSent")
      .map((l) => {
        const bytes = Buffer.from(l.args.message.slice(2), "hex");
        if (bytes.length !== 440) throw Error("genuine source message length mismatch");
        const nonce = crypto.randomBytes(32);
        nonce.copy(bytes, 12);
        bytes.writeUInt32BE(2000, 144);
        const message = "0x" + bytes.toString("hex");
        return {
          status: "complete",
          cctpVersion: 2,
          message,
          attestation: attester.signingKey.sign(E.keccak256(message)).serialized,
          eventNonce: "0x" + nonce.toString("hex"),
        };
      });
    const response = { sourceTxHash: receipt.hash, messages };
    records.set(receipt.hash.toLowerCase(), response);
    captures.push({
      sourceTxHash: receipt.hash,
      receipt: await rpc(url, "eth_getTransactionReceipt", [receipt.hash]),
      sourceMessages: receipt.logs
        .filter((l) => l.address.toLowerCase() === source.mt.address.toLowerCase())
        .map((l) => {
          try {
            return source.mtC.interface.parseLog(l)?.args.message;
          } catch {
            return null;
          }
        })
        .filter(Boolean),
      iris: response,
    });
    save("source-captures.json", captures);
    return response;
  }
  async function burn() {
    await tx(srcToken.contract.mint(oa, 1000000n));
    await tx(srcToken.contract.approve(source.tm.address, 1000000n));
    const receipt = await tx(
      source.tmC.depositForBurnWithHook(
        1000000n,
        26,
        pad(helper.address),
        srcToken.address,
        pad(helper.address),
        0,
        2000,
        hook,
      ),
    );
    await finalize();
    return bind(receipt);
  }
  const first = await burn();
  const irisCalls = [];
  iris = http.createServer((req, res) => {
    const u = new URL(req.url, "http://127.0.0.1");
    irisCalls.push({
      path: u.pathname,
      hash: u.searchParams.get("transactionHash"),
    });
    const value = records.get((u.searchParams.get("transactionHash") || "").toLowerCase());
    res.setHeader("content-type", "application/json");
    if (u.pathname != "/v2/messages/0" || !value) {
      res.writeHead(404);
      res.end("{}");
    } else res.end(JSON.stringify(value));
  });
  await new Promise((r) => iris.listen(0, "127.0.0.1", r));
  let batch;
  async function batchBurn() {
    if (!batch) {
      const code = `// SPDX-License-Identifier: MIT\npragma solidity 0.8.29; interface T {function approve(address,uint256) external returns(bool);} interface M {function depositForBurnWithHook(uint256,uint32,bytes32,address,bytes32,uint256,uint32,bytes calldata) external;} contract LocalBatch {function burnTwice(address token,address messenger,bytes32 helper,bytes calldata hook) external {require(T(token).approve(messenger,2000000)); M(messenger).depositForBurnWithHook(1000000,26,helper,token,helper,0,2000,hook); M(messenger).depositForBurnWithHook(1000000,26,helper,token,helper,0,2000,hook);}}`;
      fs.writeFileSync(path.join(run, "LocalBatch.sol"), code);
      const input = {
        language: "Solidity",
        sources: { "LocalBatch.sol": { content: code } },
        settings: {
          optimizer: { enabled: true, runs: 200 },
          outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
        },
      };
      const compiler = spawn(path.join(H, "tooling/solc-0829"), ["--standard-json"], {
        cwd: run,
        stdio: ["pipe", "pipe", "pipe"],
      });
      let stdout = "",
        stderr = "";
      compiler.stdout.on("data", (b) => (stdout += b));
      compiler.stderr.on("data", (b) => (stderr += b));
      compiler.stdin.end(JSON.stringify(input));
      const exit = await waitChild(compiler, 30000);
      fs.writeFileSync(path.join(run, "batch-solc.stderr"), stderr);
      if (exit !== 0) throw Error("local batch fixture compile failed");
      const output = JSON.parse(stdout);
      if (output.errors?.some((e) => e.severity === "error"))
        throw Error("local batch fixture Solidity error");
      const a = output.contracts["LocalBatch.sol"].LocalBatch;
      batch = await deploy({
        abi: a.abi,
        bytecode: { object: a.evm.bytecode.object },
      });
      save("LocalBatch.artifact.json", a);
    }
    await tx(srcToken.contract.mint(batch.address, 2000000n));
    const receipt = await tx(
      batch.contract.burnTwice(srcToken.address, source.tm.address, pad(helper.address), hook),
    );
    await finalize();
    return bind(receipt);
  }
  async function state() {
    const used = {};
    for (const value of records.values())
      for (const m of value.messages)
        used[m.eventNonce] = (await destination.mtC.usedNonces(m.eventNonce)).toString();
    const helperEvents = (
      await provider.getLogs({
        address: helper.address,
        fromBlock: helper.receipt.blockNumber,
        toBlock: "latest",
      })
    )
      .map((l) => {
        try {
          return helper.contract.interface.parseLog(l);
        } catch {
          return null;
        }
      })
      .filter((l) => l?.name === "DepositedToMiden");
    return {
      recipientEvents: helperEvents.map((l) => l.args.midenRecipient),
      gatewayTotal: (await gateway.contract.total()).toString(),
      helperBalance: (await dstToken.contract.balanceOf(helper.address)).toString(),
      helperAllowance: (await dstToken.contract.allowance(helper.address, proxy.address)).toString(),
      used,
      ...sendChecks,
    };
  }
  control = http.createServer(async (req, res) => {
    try {
      let body = "";
      for await (const c of req) {
        body += c;
        if (body.length > 4096) throw Error("fixture control body too large");
      }
      const value = body ? JSON.parse(body) : {};
      let result;
      if (req.url === "/new-burn") result = value.batch ? await batchBurn() : await burn();
      else if (req.url === "/state") result = await state();
      else throw Error("unknown fixture action");
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(result));
    } catch (error) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          error: error.shortMessage || error.code || "fixture control failure",
        }),
      );
    }
  });
  await new Promise((r) => control.listen(0, "127.0.0.1", r));
  async function hash(address) {
    return E.keccak256(await provider.getCode(address));
  }
  const start = source.tm.receipt.blockNumber,
    anchor = await rpc(url, "eth_getBlockByNumber", [E.toQuantity(start), false]);
  const helperCodeHash = await hash(helper.address);
  save("local-finality-probe.json", {
    latest: await rpc(url, "eth_getBlockByNumber", ["latest", false]),
    finalized: await rpc(url, "eth_getBlockByNumber", ["finalized", false]),
    helperExpected: helperCodeHash,
    helperFinalized: E.keccak256(await rpc(url, "eth_getCode", [helper.address, "finalized"])),
    policy: "fixture explicitly mines64empty blocks after each write; no Arc/public finality inference",
  });
  const observer = `import json,sqlite3,sys
v=json.load(sys.stdin)
try:
 c=sqlite3.connect('file:'+v['path']+'?mode=ro',uri=True)
 r=c.execute('SELECT raw FROM pending WHERE hash=?',(v['hash'],)).fetchone()
 print(1 if r is not None and bytes(r[0]).hex()==v['raw'][2:].lower() else 0)
except Exception:
 print(0)
`;
  transport = http.createServer(async (req, res) => {
    try {
      let text = "";
      for await (const chunk of req) {
        text += chunk;
        if (text.length > 16777216) throw Error("fixture RPC body too large");
      }
      const body = JSON.parse(text);
      if (body.method === "eth_sendRawTransaction") {
        sendChecks.preSendCalls++;
        const raw = body.params[0],
          hash = E.keccak256(raw);
        const signed = E.Transaction.from(raw),
          call = helper.contract.interface.parseTransaction({
            data: signed.data,
            value: signed.value,
          });
        const exact = [...records.values()]
          .flatMap((r) => r.messages)
          .some(
            (m) =>
              m.message.toLowerCase() === call.args.message.toLowerCase() &&
              m.attestation.toLowerCase() === call.args.attestation.toLowerCase(),
          );
        if (
          signed.value !== 0n ||
          signed.to.toLowerCase() !== helper.address.toLowerCase() ||
          signed.chainId !== 31337n ||
          call.name !== "receiveAndDeposit" ||
          !exact
        )
          throw Error("fixed target/value/original payload check failed");
        sendChecks.fixedTargetValuePayloadChecks++;
        const checked = spawnSync("python3", ["-c", observer], {
          input: JSON.stringify({
            path: path.join(run, "worker.sqlite"),
            hash,
            raw,
          }),
          encoding: "utf8",
          timeout: 5000,
        });
        if (checked.status !== 0 || checked.stdout.trim() !== "1") {
          sendChecks.preSendViolations++;
          res.setHeader("content-type", "application/json");
          res.end(
            JSON.stringify({
              jsonrpc: "2.0",
              id: body.id,
              error: {
                code: -32000,
                message: "fixture observed send before durable exact bytes",
              },
            }),
          );
          return;
        }
      }
      const reply = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10000),
      });
      const value = await reply.json();
      if (body.method === "eth_sendRawTransaction") {
        let receipt = null;
        if (!value.error) {
          for (let i = 0; i < 100 && !receipt; i++) {
            receipt = await rpc(url, "eth_getTransactionReceipt", [E.keccak256(body.params[0])]);
            if (!receipt) await new Promise((r) => setTimeout(r, 20));
          }
        }
        if (receipt) await finalize();
      }
      if (value.error) {
        sendChecks.rejections.push({
          method: body.method,
          code: value.error.code,
          kind: String(value.error.message).toLowerCase().includes("underpriced")
            ? "underpriced"
            : "remote_rejection",
        });
      }
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(value));
    } catch {
      res.writeHead(500);
      res.end();
    }
  });
  await new Promise((r) => transport.listen(0, "127.0.0.1", r));
  const profile = {
    journal: path.join(run, "worker.sqlite"),
    arc_rpc: `http://127.0.0.1:${transport.address().port}/`,
    circle_url: `http://127.0.0.1:${iris.address().port}/`,
    chain_id: 31337,
    arc_domain: 26,
    helper: helper.address,
    helper_code_hash: helperCodeHash,
    messenger: destination.tm.address,
    signer: gas.address,
    kms: {
      region: "ephemeral-loopback",
      key_arn: "unused-injected-test-signer",
    },
    max_gas: 2000000,
    max_fee_per_gas: 100000000000,
    priority_fee_per_gas: 1000000000,
    pending_timeout_secs: 3600,
    queue_capacity: 2000,
    sources: [
      {
        domain: 0,
        rpc: url,
        runtime: "evm",
        chain_id: 31337,
        messenger: source.tm.address,
        transmitter: source.mt.address,
        usdc: srcToken.address,
        start_block: start,
        start_hash: anchor.hash,
      },
    ],
  };
  save("profile.json", profile);
  save("fixture.json", {
    firstSourceTransaction: first.sourceTxHash,
    controller: `http://127.0.0.1:${control.address().port}`,
    gateway: gateway.address,
    sourceToken: srcToken.address,
  });
  stage("running small serial relay with genuine source burns and helper execution");
  const out = fs.openSync(path.join(run, "worker-test.log"), "w");
  test = spawn(executable, ["tests::local_evm::genuine_helper_flow", "--ignored", "--exact", "--nocapture"], {
    cwd: W,
    env: {
      ...safeEnv,
      CCTP_LOCAL_FIXTURE_PROFILE: path.join(run, "profile.json"),
      CCTP_LOCAL_FIXTURE_KEY: gas.privateKey,
      CCTP_LOCAL_FIXTURE_CONTROL: `http://127.0.0.1:${control.address().port}`,
      CCTP_LOCAL_FIXTURE_RESULT: path.join(run, "worker-result.json"),
      AWS_CONFIG_FILE: awsConfig,
      AWS_SHARED_CREDENTIALS_FILE: awsCredentials,
      AWS_EC2_METADATA_DISABLED: "true",
    },
    stdio: ["ignore", out, out],
  });
  save("OWNED-PROCESSES.json", {
    anvilPid: anvil.pid,
    anvilCwd: run,
    testPid: test.pid,
    testCwd: W,
    loopbackRpc: url,
    owner: "run-worker-integration.cjs",
    noWalletFiles: true,
  });
  const exit = await waitChild(test, 180000);
  report.testExit = exit;
  save("iris-requests.json", irisCalls);
  if (exit !== 0) throw Error("actual local worker test failed");
  const result = JSON.parse(fs.readFileSync(path.join(run, "worker-result.json")));
  if (result.bodyExecuted !== true) throw Error("exact child selected no executing body");
  assert.equal(result.actualBurnsAndDistinctNonces, 3);
  assert.equal(result.successfulHelperCalls, 3);
  assert(
    fs
      .readFileSync(path.join(run, "worker-test.log"), "utf8")
      .includes("GENUINE_SMALL_RELAY_HELPER_FLOW_EXECUTED"),
  );
  assert.equal(captures.length, 2);
  assert.equal(captures[1].sourceMessages.length, 2);
  assert.equal(
    captures[1].sourceMessages[0],
    captures[1].sourceMessages[1],
    "batch must contain identical original nonce-zero messages",
  );
  const nonces = [...records.values()].flatMap((r) => r.messages.map((m) => m.eventNonce));
  assert.equal(new Set(nonces).size, 3);
  report.result = result;
  report.finalState = await state();
  assert.equal(Object.keys(report.finalState.used).length, 3);
  assert(Object.values(report.finalState.used).every((v) => v === "1"));
  report.status = "PASS_LOCAL_ETHEREUM_REFERENCE_WORKER";
  stage("completed executing local fixture");
  save("REPORT.json", report);
  process.stdout.write(JSON.stringify({ status: report.status, run, testExit: exit }) + "\n");
})()
  .catch((error) => {
    report.status = "FAIL";
    report.failure = {
      code: error.code || null,
      message: error.shortMessage || "local fixture failed",
    };
    save("REPORT.json", report);
    process.stderr.write(JSON.stringify({ status: "FAIL", run, error: report.failure }) + "\n");
    process.exitCode = 1;
  })
  .finally(async () => {
    await stopChild(test);
    if (control) await new Promise((r) => control.close(r));
    if (iris) await new Promise((r) => iris.close(r));
    if (transport) await new Promise((r) => transport.close(r));
    if (provider) provider.destroy();
    await stopChild(anvil);
    save("OWNED-PROCESSES.json", {
      owner: "run-worker-integration.cjs",
      stopped: true,
      noWalletFiles: true,
    });
  });
