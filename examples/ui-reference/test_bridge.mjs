import test from 'node:test';
import assert from 'node:assert/strict';
import {BridgeClient, parseMetadata, safeJson} from './public/bridge.js';

const id = '00000000-0000-4000-8000-000000000001', skill = '00000000-0000-4000-8000-000000000002', digest = 'sha256:' + 'a'.repeat(64);
const metadata = parseMetadata(new URLSearchParams({protocol: 'xelab.ui/1', view_id: id, channel_nonce: 'b'.repeat(64), parent_origin: 'https://shell.example'}).toString(), 'https://plugin.example');
const tokens = {accent:'#4F7CFF', desktop:'#E9EEF7', surface:'#FFFFFF', text:'#18202C', muted_text:'#526074', border:'#CBD5E1', danger:'#B42318', radius_px:12, blur_px:16, panel_opacity:.92, font:'system'};
const init = {theme_tokens:tokens, reduce_motion:false, reduce_transparency:false, visible:true, viewport:{width:640,height:400}, locale:'en', contribution_digest:digest, bindings:[{alias:'echo',skill_id:skill,definition_digest:digest,modes:['call']}]};

function fixture() {
  const sent = [], callbacks = new Set(), states = [];
  const target = {postMessage(message, origin) { sent.push({message,origin}); }};
  const listen = {addEventListener(_, fn) { callbacks.add(fn); }, removeEventListener(_, fn) { callbacks.delete(fn); }};
  const client = new BridgeClient({metadata,target,listen,onState:(...value)=>states.push(value)});
  const emit = (body, overrides={}) => { const value={protocol:metadata.protocol,view_id:id,channel_nonce:metadata.channel_nonce,...body}; for(const fn of callbacks) fn({data:value,origin:metadata.parent_origin,source:target,ports:[],...overrides}); };
  return {sent,target,client,states,emit,initialize() { emit({seq:1,type:'host.init',params:init}); }};
}

test('metadata rejects duplicate, unexpected, non-HTTPS and same-origin routes', () => {
  const valid = new URLSearchParams(metadata).toString();
  for (const value of [valid+'&view_id='+id,valid+'&credential=secret',valid.replace('https%3A%2F%2Fshell.example','http%3A%2F%2Fshell.example'),valid.replace('https%3A%2F%2Fshell.example','https%3A%2F%2Fplugin.example'),valid.replace('https%3A%2F%2Fshell.example','https%3A%2F%2Fshell.example%2Fpath')]) assert.throws(()=>parseMetadata(value,'https://plugin.example'));
});

test('strict init rejects wrong source, origin, nonce, replay and extra fields', async () => {
  const f=fixture();
  try {
    assert.equal(f.sent[0].origin,'https://shell.example'); assert.equal(f.sent[0].message.seq,1); assert.equal(f.sent[0].message.type,'ready'); assert.equal('parent_origin' in f.sent[0].message,false);
    await assert.rejects(f.client.callEcho('x','key'),{code:'BINDING_UNAVAILABLE'});
    f.emit({seq:1,type:'host.init',params:init},{origin:'https://attacker.example'});
    f.emit({seq:1,type:'host.init',params:init},{source:{}});
    f.emit({seq:1,type:'host.init',params:init,channel_nonce:'c'.repeat(64)});
    f.emit({seq:1,type:'host.init',params:init,credential:'forged'});
    assert.equal(f.client.ready,false);
    f.initialize(); assert.equal(f.client.canCall,true);
    f.emit({seq:1,type:'event',event:'host.dispose',params:{reason:'logout'}});
    assert.equal(f.client.ready,true);
  } finally { f.client.close(); }
});

test('only fixed echo alias and same-plugin window requests are emitted', async () => {
  const f=fixture();
  try {
    f.initialize(); const pending=f.client.callEcho('<script>data</script>','stable-intent');
    const request=f.sent.at(-1).message;
    assert.equal(request.seq,2); assert.equal(request.request_id,1); assert.equal(request.method,'skill.call');
    assert.deepEqual(request.params,{binding_alias:'echo',input:{message:'<script>data</script>'},idempotency_key:'stable-intent',timeout_ms:10000});
    f.emit({seq:2,type:'response',request_id:1,method:'skill.call',ok:true,result:{skill_id:skill,skill_version:'1.0.0',definition_digest:digest,call:{call_id:id,output:{message:'actual output'}}}});
    assert.equal((await pending).call.output.message,'actual output');
    const opened=f.client.openWindow(); assert.deepEqual(f.sent.at(-1).message.params,{contribution_id:'echo_window'});
    f.emit({seq:3,type:'response',request_id:2,method:'window.open',ok:true,result:{view_id:id}}); assert.deepEqual(await opened,{view_id:id});
  } finally { f.client.close(); }
});

test('echo response waiting includes the host checks and still expires', async context => {
  const schedule = context.mock.method(globalThis, 'setTimeout', () => 0);
  const f = fixture();
  try {
    f.initialize();
    const echo = f.client.callEcho('x', 'stable-intent').catch(error => error);
    assert.equal(f.sent.at(-1).message.params.timeout_ms, 10_000);
    const window = f.client.openWindow().catch(error => error);
    const [, echoTimer, windowTimer] = schedule.mock.calls.map(call => call.arguments);
    assert.equal(echoTimer[1], 40_000);
    assert.equal(windowTimer[1], 10_000);
    windowTimer[0]();
    assert.equal((await window).code, 'DEADLINE_EXCEEDED');
    echoTimer[0]();
    assert.equal((await echo).code, 'DEADLINE_EXCEEDED');
  } finally { f.client.close(); }
});

test('binding absence, mismatched response, inflight cap and disposal fail closed', async () => {
  const f=fixture();
  try {
    f.emit({seq:1,type:'host.init',params:{...init,bindings:[]}});
    assert.equal(f.client.ready,true); assert.equal(f.client.canCall,false);
    await assert.rejects(f.client.callEcho('x','key'),{code:'BINDING_UNAVAILABLE'});
  } finally { f.client.close(); }
  const h=fixture();
  try {
    h.initialize(); const pending=h.client.callEcho('x','key');
    h.emit({seq:2,type:'response',request_id:1,method:'skill.call',ok:true,result:{skill_id:id,skill_version:'1.0.0',definition_digest:digest,call:{call_id:id,output:{message:'wrong binding'}}}});
    await assert.rejects(pending,{code:'PROTOCOL_ERROR'});
  } finally { h.client.close(); }
  const g=fixture();
  try {
    g.initialize(); const pending=Array.from({length:4},(_,index)=>g.client.callEcho('x','key-'+index));
    const results=pending.map(promise=>assert.rejects(promise,{code:'CHANNEL_CLOSED'}));
    await assert.rejects(g.client.openWindow(),{code:'RATE_LIMITED'});
    g.emit({seq:2,type:'event',event:'host.dispose',params:{reason:'upgrade'}}); await Promise.all(results);
    assert.equal(g.client.ready,false);
  } finally { g.client.close(); }
});

test('expanded byte/depth/Unicode/prototype limits reject unsafe postMessage data', () => {
  assert.throws(()=>safeJson({a:'x'.repeat(1025)},1024),{code:'PAYLOAD_TOO_LARGE'});
  assert.throws(()=>safeJson({a:NaN}),{code:'PROTOCOL_ERROR'});
  assert.throws(()=>safeJson({a:'\ud800'}),{code:'PROTOCOL_ERROR'});
  assert.throws(()=>safeJson(new Date()),{code:'PROTOCOL_ERROR'});
  let depth={}; for(let index=0;index<65;index++) depth={a:depth};
  assert.throws(()=>safeJson(depth),{code:'PROTOCOL_ERROR'});
  const cycle={}; cycle.a=cycle; assert.throws(()=>safeJson(cycle),{code:'PROTOCOL_ERROR'});
  let dag={x:'a'.repeat(16)}; for(let index=0;index<20;index++) dag={a:dag,b:dag};
  assert.throws(()=>safeJson(dag,1024),{code:'PAYLOAD_TOO_LARGE'});
  assert.throws(()=>safeJson({get a(){throw Error('not invoked');}}),{code:'PROTOCOL_ERROR'});
});
