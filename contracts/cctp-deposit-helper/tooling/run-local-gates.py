#!/usr/bin/env python3
"""Reproduce local gates, owning a localhost Arc process for runtime checks. No public endpoints."""
import datetime,json,os,socket,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
LOGS=ROOT/'tooling/local-gates'/datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
LOGS.mkdir(parents=True)
FORGE=str(ROOT/'tooling/forge'); ANVIL=str(ROOT/'tooling/anvil')
ledger=[]
def run(name,args,profile=None,directory=None):
 env=os.environ.copy()
 if profile:env['FOUNDRY_PROFILE']=profile
 elif 'FOUNDRY_PROFILE' in env:del env['FOUNDRY_PROFILE']
 start=time.monotonic()
 directory=directory or ROOT
 p=subprocess.run(args,cwd=directory,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 log=LOGS/(name+'.log');log.write_text(p.stdout)
 row={'gate':name,'command':args,'cwd':str(directory),'profile':profile or 'default','exit':p.returncode,'seconds':round(time.monotonic()-start,3),'log':str(log)}
 ledger.append(row);print(json.dumps(row),flush=True)
 (ROOT/'fixtures/local-gate-results.json').write_text(json.dumps(ledger,indent=2)+'\n')
 if p.returncode:raise RuntimeError(p.stdout[-3000:])
run('reference-cctp',[FORGE,'build'],directory=ROOT/'reference/cctp')
run('reference-xreserve',[FORGE,'build'],directory=ROOT/'reference/xreserve')
run('format',[FORGE,'fmt','--check'])
run('build-sizes',[FORGE,'build','--sizes'])
run('concrete',[FORGE,'test','--match-path','tests/unit/concrete/**','-vv'])
run('circle-integration-and-local-preflight',[FORGE,'test','--match-path','tests/integration/**','-vv'])
run('fuzz-ci',[FORGE,'test','--match-path','tests/unit/fuzz/**','-vv'],'ci')
run('invariants',[FORGE,'test','--match-path','tests/invariant/**','-vv'])
run('post-mint-rollback-trace',[FORGE,'test','--match-test','test_RollsBackActualMintForGatewayFailureThenRetriesSameBytes','-vvvv'])
with socket.socket() as s:
 if s.connect_ex(('127.0.0.1',18549))==0:raise RuntimeError('localhost18549 is already owned by another process; refusing to reset or stop it')
nodeLog=(LOGS/'arc-anvil.log').open('w')
node=subprocess.Popen([ANVIL,'--network','arc','--chain-id','31337','--host','127.0.0.1','--port','18549','--silent'],cwd=ROOT,stdout=nodeLog,stderr=subprocess.STDOUT)
try:
 for _ in range(100):
  if node.poll() is not None:raise RuntimeError('Arc Anvil exited during startup')
  with socket.socket() as s:
   if s.connect_ex(('127.0.0.1',18549))==0:break
  time.sleep(0.05)
 else:raise RuntimeError('Local Arc startup timeout')
 run('arc-runtime',[FORGE,'test','--network','arc','--match-path','tests/runtime/**','--fork-url','http://127.0.0.1:18549','-vv'])
 run('arc-native-rpc',['node','tooling/arc-native-rpc.cjs'])
 run('circle-vector-regeneration',['node','tooling/regenerate-circle-vectors.cjs'])
finally:
 node.terminate()
 try:node.wait(timeout=10)
 except subprocess.TimeoutExpired:node.kill();node.wait()
 nodeLog.close()
print('All local gates passed; owned Arc process stopped.',flush=True)
