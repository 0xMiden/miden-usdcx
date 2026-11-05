#!/usr/bin/env python3
"""Exercise the ordinary worker's SIGTERM and intact-journal restart on empty local feeds."""
import argparse
import base64
import collections
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, build_opener, ProxyHandler
from urllib.error import HTTPError
import uuid


# Public SPKI from usdcx-kms-signer/src/kms/tests.rs, paired only with a dummy ARN.
SPKI = bytes.fromhex(
    "3056301006072a8648ce3d020106052b8104000a03420004"
    "cd6031d5cb4d64291980e1041f691ae56e64419775be42f06a5a8d6433363103"
    "812a9a572e47457b0b1a0f15b732280b5da8e68115e6e3aa667c53dc51821aa0"
)
ARN = "arn:aws:kms:us-east-1:000000000000:key/offline-lifecycle-fixture"
SIGNER = "0x54c42c6e58cf55aca80cda2b058caca135c58dd2"
HELPER, MESSENGER, TRANSMITTER = ["0x" + byte * 20 for byte in ("21", "23", "24")]
# The same 0x6000 helper runtime used by the existing worker RPC unit fixture.
CODE_HASH = "0x07ad118d6cc8642c86c03827f276d8b791a65e5c99a3845faf186be720a1455d"


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def word(number):
    return "0x" + f"{number:064x}"


class Fixture:
    def __init__(self):
        self.requests, self.errors, self.ranges = [], [], []
        self.advance(12)
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                fixture.errors.append("unexpected GET, including any Circle lookup")
                self.send_error(400)

            def do_POST(self):
                try:
                    body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    path = self.path.rstrip("/")
                    method = self.headers.get("X-Amz-Target", "").split(".")[-1] if path == "/kms" else body["method"]
                    fixture.requests.append({"path": path, "method": method, "phase": fixture.head})
                    result = fixture.reply(path, method, body)
                    value = result if path == "/kms" else {"jsonrpc": "2.0", "id": body["id"], "result": result}
                    status = 200
                except Exception as error:
                    fixture.errors.append(str(error))
                    status, value = 400, {"error": "unexpected fixture request"}
                encoded = json.dumps(value).encode()
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/x-amz-json-1.1" if self.path.startswith("/kms") else "application/json")
                    self.send_header("Content-Length", str(len(encoded)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(encoded)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # Cancellation closes the deliberately held source RPC.

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def advance(self, head):
        self.head, self.source_calls = head, 0
        self.barrier, self.release = threading.Event(), threading.Event()

    def reply(self, path, method, body):
        if path == "/kms":
            check(body == {"KeyId": ARN}, "unexpected KMS input")
            metadata = {"KeyId": ARN, "KeySpec": "ECC_SECG_P256K1", "KeyUsage": "SIGN_VERIFY"}
            if method == "DescribeKey":
                return {"KeyMetadata": {**metadata, "Arn": ARN, "Enabled": True, "KeyState": "Enabled"}}
            if method == "GetPublicKey":
                return {**metadata, "PublicKey": base64.b64encode(SPKI).decode(), "SigningAlgorithms": ["ECDSA_SHA_256"]}
            raise RuntimeError(f"forbidden KMS operation: {method}")
        params = body["params"]
        if path == "/arc":
            if method == "eth_chainId" and params == []:
                return "0x7a69"
            if method == "eth_getCode" and params == [HELPER, "finalized"]:
                return "0x6000"
            if method == "eth_getTransactionCount" and params in ([SIGNER, "finalized"], [SIGNER, "pending"]):
                return "0x0"
            if method == "eth_call" and params[1] == "finalized" and params[0]["to"] == HELPER:
                address = {"0x7b04c181": TRANSMITTER, "0x46117830": MESSENGER}.get(params[0]["data"])
                check(address is not None, "unexpected Arc view")
                return "0x" + "00" * 12 + address[2:]
            raise RuntimeError(f"forbidden or unexpected Arc operation: {method}")
        check(path == "/source", f"unexpected request path: {path}")
        if method == "eth_chainId" and params == []:
            self.source_calls += 1
            if self.source_calls == 2:
                # A second scan starts only after the previous page was committed.
                release = self.release
                self.barrier.set()
                check(release.wait(20), "in-flight source request was not released")
            return "0x7a69"
        if method == "eth_getBlockByNumber" and params[1] is False:
            number = self.head if params[0] == "finalized" else int(params[0], 16)
            check(10 <= number <= self.head, "unexpected source block")
            return {"number": hex(number), "hash": word(number)}
        if method == "eth_getLogs":
            page = params[0]
            span = [int(page["fromBlock"], 16), int(page["toBlock"], 16)]
            check(span == ([10, 12] if self.head == 12 else [13, 14]), f"source replay or skipped cursor: {span}")
            self.ranges.append(span)
            return []
        raise RuntimeError(f"forbidden or unexpected source operation: {method}")

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def wait_clean(process, timeout):
    try:
        code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("process ignored SIGTERM or exceeded the bounded exit deadline") from error
    check(code == 0, f"process did not handle shutdown cleanly: exit {code}")


class Worker:
    def __init__(self, args, root, evidence, environment):
        self.args, self.root, self.evidence, self.environment = args, root, evidence, environment
        self.containers, self.processes, self.commands = [], [], []
        self.volume = "cctp-lifecycle-" + uuid.uuid4().hex
        self.process, self.container = None, None
        self.config = root / "config.json"
        self.journal = root / "relay.sqlite"
        if args.image:
            check(sys.platform == "linux", "container mode is supported only on an existing Linux CI Docker host")
            (root / "docker-config").mkdir()
            image = json.loads(self.docker("image", "inspect", args.image))[0]
            check(image["Config"]["Entrypoint"] == ["/usr/local/bin/cctp-deposit-relayer"], "image entrypoint changed")
            self.image = {"id": image["Id"], "architecture": image["Architecture"], "labels": image["Config"]["Labels"]}
            check(self.image["architecture"] == "amd64", "expected qualified Linux amd64 image")
            self.docker("volume", "create", self.volume)

    def docker(self, *arguments):
        command = ["docker", "--config", str(self.root / "docker-config"), *arguments]
        result = subprocess.run(command, text=True, capture_output=True, timeout=15, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
        self.commands.append({"command": command, "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        check(result.returncode == 0, "owned Docker command failed: " + " ".join(arguments[:2]))
        return result.stdout.strip()

    def start(self, name, initialize=False):
        self.name = name
        arguments = ["--config", "/run/cctp/config.json" if self.args.image else str(self.config)] + (["--init"] if initialize else [])
        if self.args.image:
            self.container = self.volume + "-" + name
            self.containers.append(self.container)
            env_args = [item for key, value in self.environment.items() for item in ("--env", f"{key}={value}")]
            self.docker("run", "--detach", "--pull=never", "--name", self.container, "--network", "host", *env_args,
                        "--mount", f"type=bind,src={self.config},dst=/run/cctp/config.json,readonly",
                        "--mount", f"type=volume,src={self.volume},dst=/data", self.args.image, *arguments)
        else:
            log = (self.evidence / f"{name}.log").open("wb")
            self.process = subprocess.Popen([str(self.args.binary), *arguments], env=self.environment, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            self.processes.append((self.process, log))
            self.commands.append({"command": [str(self.args.binary), *arguments], "pid": self.process.pid})

    def running(self):
        return self.docker("inspect", "--format", "{{.State.Running}}", self.container) == "true" if self.args.image else self.process.poll() is None

    def finish(self, terminate):
        start = time.monotonic()
        check(not terminate or self.running(), "worker exited before SIGTERM")
        if self.args.image:
            if terminate:
                status = self.docker("exec", self.container, "cat", "/proc/1/status")
                check("Uid:\t10002\t10002\t10002\t10002" in status and "Gid:\t10002\t10002\t10002\t10002" in status, "actual entrypoint is not UID/GID10002")
                self.docker("kill", "--signal=TERM", self.container)
            deadline = time.monotonic() + 8
            while self.running():
                check(time.monotonic() < deadline, "container ignored SIGTERM or exceeded exit deadline")
                time.sleep(0.05)
            state = json.loads(self.docker("inspect", "--format", "{{json .State}}", self.container))
            check(state["ExitCode"] == 0 and not state["OOMKilled"] and not state["Error"], "container did not exit cleanly")
            elapsed = time.monotonic() - start
            text = self.docker("logs", self.container)
            # Docker returns ordinary logs on both stdout and stderr.
            text += self.commands[-1]["stderr"]
            (self.evidence / f"{self.name}.log").write_text(text)
        else:
            if terminate:
                self.process.send_signal(signal.SIGTERM)
            wait_clean(self.process, 8)
            elapsed = time.monotonic() - start
            self.processes[-1][1].flush()
            text = (self.evidence / f"{self.name}.log").read_text()
        check(not terminate or "shutdown requested" in text, "actual signal handler was not observed")
        check(elapsed < 8, "clean exit exceeded the bounded deadline")
        return {"name": self.name, "signal": "SIGTERM" if terminate else None, "exit": 0, "seconds": elapsed}

    def snapshot(self, name):
        path = self.evidence / f"{name}.sqlite"
        if self.args.image:
            mounts = json.loads(self.docker("inspect", "--format", "{{json .Mounts}}", self.container))
            check(any(m["Destination"] == "/data" and m["Name"] == self.volume for m in mounts), "journal volume changed")
            directory = self.evidence / f"{name}-data"
            directory.mkdir()
            self.docker("cp", f"{self.container}:/data/.", str(directory))
            path = directory / "relay.sqlite"
            wal = directory / "relay.sqlite-wal"
        else:
            wal = Path(str(self.journal) + "-wal")
        wal_bytes = wal.stat().st_size if wal.exists() else 0
        check(wal_bytes == 0, "cleanly stopped journal still has uncheckpointed WAL content")
        if not self.args.image:
            shutil.copyfile(self.journal, path)
        # Immutable reads are safe only after proving the stopped WAL is absent/empty.
        with sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True) as db:
            check(db.execute("PRAGMA user_version").fetchone() == (10,), "journal schema changed")
            check(db.execute("PRAGMA quick_check").fetchone() == ("ok",), "stopped journal is corrupt")
            meta = db.execute("SELECT identity,next_nonce,halt,iris_after FROM meta").fetchone()
            cursor, halt = db.execute("SELECT cursor,halt FROM sources WHERE domain=0").fetchone()
            counts = {table: db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] for table in ("source_txs", "messages", "pending")}
        check(meta[1:] == (0, None, 0) and halt is None and not any(counts.values()), "unexpected nonce, halt, pending/raw or candidate work")
        return {"identity": meta[0], "nextNonce": meta[1], "cursor": json.loads(cursor), "counts": counts, "walPresent": wal.exists(), "walBytes": wal_bytes, "sha256": digest(path)}

    def close(self):
        for process, log in self.processes:
            if process.poll() is None:
                process.kill()  # Failure cleanup only, never counted as a successful stop.
                process.wait()
            log.close()
        for name in self.containers:
            if self.docker("ps", "--all", "--quiet", "--filter", f"name=^{name}$"):
                try:
                    logs = self.docker("logs", name) + self.commands[-1]["stderr"]
                    (self.evidence / f"{name}.log").write_text(logs)
                finally:
                    self.docker("rm", "--force", name)
        if self.args.image:
            self.docker("volume", "rm", self.volume)


def self_test():
    process = subprocess.Popen([sys.executable, "-u", "-c", "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print('ready'); time.sleep(30)"], stdout=subprocess.PIPE)
    try:
        check(process.stdout.readline() == b"ready\n", "negative child did not start")
        process.send_signal(signal.SIGTERM)
        try:
            wait_clean(process, 0.2)
        except RuntimeError:
            check(process.poll() is None, "negative child exited instead of ignoring SIGTERM")
        else:
            raise RuntimeError("swallowed signal was accepted")
    finally:
        process.kill()
        process.wait()
        process.stdout.close()
    fixture = Fixture()
    try:
        request = Request(fixture.url + "/kms", json.dumps({"KeyId": ARN}).encode(), {"X-Amz-Target": "TrentService.Sign"})
        try:
            build_opener(ProxyHandler({})).open(request, timeout=2)
        except HTTPError as error:
            check(error.code == 400 and fixture.errors == ["forbidden KMS operation: Sign"], "Sign was not rejected")
            error.close()
        else:
            raise RuntimeError("forbidden signing was accepted")
    finally:
        fixture.close()
    return {"swallowedSignalRejected": True, "forbiddenSignRejected": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--binary", type=Path)
    mode.add_argument("--image")
    mode.add_argument("--self-test", action="store_true")
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=False)
    args.evidence = args.evidence.resolve()
    if args.binary:
        args.binary = args.binary.resolve(strict=True)
    result = {"status": "FAIL", "scriptSha256": digest(__file__), "mode": "image" if args.image else "self-test" if args.self_test else "native"}
    worker, fixture, runtime = None, None, None
    try:
        if args.self_test:
            result["negativeChecks"] = self_test()
        else:
            runtime = tempfile.TemporaryDirectory(prefix="cctp-lifecycle-")
            root = Path(runtime.name)
            try:
                fixture = Fixture()
                environment = {
                    "AWS_ENDPOINT_URL": fixture.url + "/kms", "AWS_ENDPOINT_URL_KMS": fixture.url + "/kms",
                    "AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test",
                    "AWS_CONFIG_FILE": "/dev/null", "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
                    "AWS_EC2_METADATA_DISABLED": "true", "RUST_LOG": "info",
                }
                worker = Worker(args, root, args.evidence, environment)
                config = {
                    "journal": "/data/relay.sqlite" if args.image else str(worker.journal),
                    "arc_rpc": fixture.url + "/arc", "circle_url": fixture.url + "/circle",
                    "chain_id": 31337, "arc_domain": 26,
                    "helper": HELPER, "helper_code_hash": CODE_HASH,
                    "messenger": MESSENGER, "signer": SIGNER,
                    "kms": {"region": "us-east-1", "key_arn": ARN},
                    "max_gas": 500000, "max_fee_per_gas": 30000000000,
                    "priority_fee_per_gas": 1000000000, "pending_timeout_secs": 3600,
                    "queue_capacity": 100,
                    "sources": [{
                        "domain": 0, "rpc": fixture.url + "/source", "runtime": "evm", "chain_id": 31337,
                        "messenger": "0x" + "11" * 20, "transmitter": "0x" + "12" * 20,
                        "usdc": "0x" + "13" * 20, "start_block": 10, "start_hash": word(10),
                    }],
                }
                worker.config.write_text(json.dumps(config))
                worker.config.chmod(0o644)  # Synthetic public inputs must be readable by container UID10002.
                shutil.copyfile(worker.config, args.evidence / "config.synthetic.json")
                result["configSha256"] = digest(worker.config)
                result["environment"] = environment  # Explicit dummy inputs only; no inherited credentials.
                result["image" if args.image else "binary"] = worker.image if args.image else {"path": str(args.binary), "sha256": digest(args.binary)}
                result["runs"], result["snapshots"] = [], []
                worker.start("initialize", True)
                result["runs"].append(worker.finish(False))
                initial = worker.snapshot("initialized")
                result["initialized"] = initial
                check(initial["cursor"] is None, "initialization discovered source history")
                inode = None if args.image else worker.journal.stat().st_ino
                for name, head in (("first", 12), ("restart", 14)):
                    fixture.advance(head)
                    worker.start(name)  # Deliberately no --init, including restart.
                    deadline = time.monotonic() + 15
                    while not fixture.barrier.wait(0.05):
                        check(worker.running() and time.monotonic() < deadline and not fixture.errors, "discovery barrier failed")
                    result["runs"].append(worker.finish(True))
                    fixture.release.set()
                    snapshot = worker.snapshot(name)
                    check(snapshot["identity"] == initial["identity"] and snapshot["cursor"] == {"end": head, "hash": word(head)}, "persisted journal identity/cursor changed")
                    check(args.image or worker.journal.stat().st_ino == inode, "journal was replaced")
                    result["snapshots"].append(snapshot)
                check(fixture.ranges == [[10, 12], [13, 14]] and not fixture.errors, "source replay or unexpected upstream call")
                operations = collections.Counter(r["method"] for r in fixture.requests if r["path"] == "/kms")
                check(operations == {"DescribeKey": 3, "GetPublicKey": 3}, "unexpected KMS startup/sign activity")
                result["ranges"], result["kmsOperations"] = fixture.ranges, dict(operations)
            finally:
                if worker:
                    try:
                        worker.close()
                        result["cleanupVerified"] = True
                    finally:
                        result["commands"] = worker.commands
                        worker = None
                if fixture:
                    try:
                        fixture.close()
                    finally:
                        result["requests"], result["violations"] = fixture.requests, fixture.errors
                        fixture = None
        result["status"] = "PASS"
    except Exception as error:
        result["error"] = str(error)
        raise
    finally:
        try:
            if worker:
                worker.close()
            if fixture:
                fixture.close()
        finally:
            if fixture:
                result["requests"], result["violations"] = fixture.requests, fixture.errors
            if runtime:
                runtime.cleanup()
            (args.evidence / "result.json").write_text(json.dumps(result, indent=2) + "\n")
            print(json.dumps(result))


if __name__ == "__main__":
    main()
