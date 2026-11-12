import {ApiError} from './api.js';

const PROTOCOL = 'xelab.ui/1';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const ALIAS = /^[a-z][a-z0-9_-]{0,63}$/;
const METHODS = new Set(['skill.call','window.open','batch.create','batch.get','batch.items','batch.result','batch.cancel']);
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const validText = (value, max) => typeof value === 'string' && [...value].length > 0 && [...value].length <= max;
const integer = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;
function fields(value, required, optional = []) {
  return plain(value) && required.every(key => Object.hasOwn(value,key)) && Object.keys(value).every(key => required.includes(key)||optional.includes(key));
}
function fail(code, message) {return {code,message,retryable:false};}
function problem(code,message) {return Object.assign(new Error(message),{bridge:fail(code,message)});}
function unicode(value) {
  for (let index=0;index<value.length;index++) {
    const code=value.charCodeAt(index);
    if(code>=0xd800&&code<=0xdbff) {const next=value.charCodeAt(++index);if(!(next>=0xdc00&&next<=0xdfff))throw problem('PROTOCOL_ERROR','无效的 Unicode。');}
    else if(code>=0xdc00&&code<=0xdfff)throw problem('PROTOCOL_ERROR','无效的 Unicode。');
  }
}
function canonical(value, maximum=16*1024*1024+65536) {
  const parts=[],seen=new Set(),encoder=new TextEncoder();let bytes=0;
  const emit=value=>{bytes+=encoder.encode(value).byteLength;if(bytes>maximum)throw problem('PAYLOAD_TOO_LARGE','消息超过字节限制。');parts.push(value);};
  const string=value=>{if(value.length>maximum)throw problem('PAYLOAD_TOO_LARGE','字符串超过消息限制。');unicode(value);emit(JSON.stringify(value));};
  function walk(current,depth){
    if(depth>64)throw problem('PROTOCOL_ERROR','JSON 嵌套超过64层。');
    if(typeof current==='string'){string(current);return;}
    if(current===null||typeof current==='boolean'||(typeof current==='number'&&Number.isFinite(current))){emit(JSON.stringify(current));return;}
    if((!Array.isArray(current)&&!plain(current))||seen.has(current))throw problem('PROTOCOL_ERROR','消息必须是无循环的普通 JSON。');
    seen.add(current);
    if(Array.isArray(current)){emit('[');for(let index=0;index<current.length;index++){if(index)emit(',');walk(current[index],depth+1);}emit(']');}
    else{const keys=Object.keys(current);if(keys.length>maximum/3)throw problem('PAYLOAD_TOO_LARGE','对象字段过多。');emit('{');for(const[index,key]of keys.sort().entries()){if(index)emit(',');string(key);emit(':');walk(current[key],depth+1);}emit('}');}
    seen.delete(current);
  }
  walk(value,0);return parts.join('');
}
async function sha256(value){return[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value)))].map(byte=>byte.toString(16).padStart(2,'0')).join('');}
function path(value) {return typeof value==='string'&&value.length<=256&&/^\/[A-Za-z0-9_./-]*$/.test(value)&&!value.includes('//')&&!value.split('/').some(part=>part==='.'||part==='..');}
function modes(value) {return Array.isArray(value)&&value.length>=1&&value.length<=2&&new Set(value).size===value.length&&value.every(mode=>['call','batch'].includes(mode));}
function base64Bytes(value,maximum) {
  if(!/^[A-Za-z0-9_-]+$/.test(value)||value.length>maximum||value.length%4===1)throw new Error('Invalid framing encoding');
  const binary=atob(value.replaceAll('-','+').replaceAll('_','/').padEnd(Math.ceil(value.length/4)*4,'='));
  if(btoa(binary).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'')!==value)throw new Error('Noncanonical framing encoding');
  return Uint8Array.from(binary,char=>char.charCodeAt(0));
}
function framingQuery(query,contributionId) {
  if(query==='')return true;
  const prefix='?xelab_frame=';
  if(!query.startsWith(prefix))return false;
  const value=query.slice(prefix.length),parts=/^v1\.([A-Za-z0-9_-]{1,768})\.([A-Za-z0-9_-]{43})$/.exec(value);
  if(value.length>1024||!parts)return false;
  try{
    const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(base64Bytes(parts[1],768));
    const selector=JSON.parse(text);
    return fields(selector,['client_id','contribution_id','origin_index'])&&validText(selector.client_id,128)&&!/[\u0000-\u001f\u007f-\u009f]/.test(selector.client_id)
      &&selector.contribution_id===contributionId&&integer(selector.origin_index,0,7)
      &&canonical(selector,1024)===text&&base64Bytes(parts[2],43).byteLength===32;
  }catch{return false;}
}
function dimensions(value,kind) {
  if(kind==='window') {
    if(!fields(value,['width','height','min_width','min_height','max_width','max_height','resizable'])||typeof value.resizable!=='boolean')return false;
    return ['width','height'].every(axis=>integer(value[axis],axis==='width'?320:200,axis==='width'?4096:2160)&&integer(value[`min_${axis}`],axis==='width'?320:200,value[axis])&&integer(value[`max_${axis}`],value[axis],axis==='width'?4096:2160));
  }
  return fields(value,['columns','rows','min_columns','min_rows','max_columns','max_rows'])&&['columns','rows'].every(axis=>integer(value[axis],1,8)&&integer(value[`min_${axis}`],1,value[axis])&&integer(value[`max_${axis}`],value[axis],8));
}
export function validateContribution(value, {parentOrigin,coreOrigin}) {
  const copy=JSON.parse(canonical(value));
  if(!fields(copy,['deployment_id','installation_id','plugin_id','manifest_digest','contribution_digest','spec','frame_url','frame_origin','availability','reason_codes','bindings'])
      ||!UUID.test(copy.deployment_id)||!UUID.test(copy.installation_id)||!DIGEST.test(copy.manifest_digest)||!DIGEST.test(copy.contribution_digest)
      ||!validText(copy.plugin_id,128)||! /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$/.test(copy.plugin_id)
      ||copy.availability!=='ready'||!Array.isArray(copy.reason_codes)||copy.reason_codes.length>32||!copy.reason_codes.every(code=>validText(code,80)))throw problem('BINDING_UNAVAILABLE','核心贡献当前不可用。');
  const spec=copy.spec;
  if(!fields(spec,['id','kind','title','description','entry_path','skill_bindings'],['icon_path','window','widget','refresh_interval_seconds'])
      ||!ALIAS.test(spec.id)||!['window','widget'].includes(spec.kind)||!validText(spec.title,80)||!validText(spec.description,512)||!path(spec.entry_path)
      ||(spec.icon_path!==undefined&&!path(spec.icon_path))||!dimensions(spec[spec.kind],spec.kind)||Object.hasOwn(spec,spec.kind==='window'?'widget':'window')
      ||!integer(spec.refresh_interval_seconds??0,0,3600)||(spec.kind==='window'&&(spec.refresh_interval_seconds??0)!==0)
      ||((spec.refresh_interval_seconds??0)>0&&spec.refresh_interval_seconds<30)
      ||!Array.isArray(spec.skill_bindings)||spec.skill_bindings.length>32)throw problem('PROTOCOL_ERROR','贡献声明结构无效。');
  const aliases=new Map();
  for(const binding of spec.skill_bindings) {
    if(!fields(binding,['alias','name','version','modes'])||!ALIAS.test(binding.alias)||aliases.has(binding.alias)||!validText(binding.name,160)
        ||!binding.name.startsWith(copy.plugin_id+'.')||!/^[a-z][a-z0-9.-]+$/.test(binding.name)||!validText(binding.version,128)
        ||!/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.test(binding.version)
        ||!modes(binding.modes))throw problem('PROTOCOL_ERROR','贡献的签名绑定无效。');
    aliases.set(binding.alias,binding);
  }
  if(!Array.isArray(copy.bindings)||copy.bindings.length>32)throw problem('PROTOCOL_ERROR','解析绑定无效。');
  const resolved=new Set();
  for(const binding of copy.bindings) {
    const declared=aliases.get(binding.alias);
    if(!fields(binding,['alias','skill_id','definition_digest','modes'])||!ALIAS.test(binding.alias)||resolved.has(binding.alias)||!declared||!UUID.test(binding.skill_id)||!DIGEST.test(binding.definition_digest)||!modes(binding.modes)||binding.modes.some(mode=>!declared.modes.includes(mode)))throw problem('PROTOCOL_ERROR','核心绑定不符合签名贡献。');
    resolved.add(binding.alias);
  }
  let url,origin;
  try{url=new URL(copy.frame_url);origin=new URL(copy.frame_origin);}catch{throw problem('BINDING_UNAVAILABLE','缺少独立 HTTPS 页面来源。');}
  if(url.protocol!=='https:'||origin.protocol!=='https:'||origin.origin!==copy.frame_origin||url.href!==copy.frame_url||url.origin!==copy.frame_origin
      ||url.username||url.password||!framingQuery(url.search||(copy.frame_url.includes('?')?'?':''),spec.id)||url.hash||url.origin===parentOrigin||url.origin===coreOrigin
      ||url.pathname!==`/ui/${copy.plugin_id}${spec.entry_path}`)throw problem('PERMISSION_DENIED','插件页面必须具有核心分配的独立来源和固定路径。');
  return copy;
}
export function sameContribution(left,right){return canonical(left)===canonical(right);}
export async function deriveBridgeKey(subject,contribution,method,callerKey) {
  if(!UUID.test(subject)||!validText(callerKey,128))throw problem('PERMISSION_DENIED','无法固定当前账户或请求键。');
  const bytes=new TextEncoder().encode(canonical({subject_id:subject,installation_id:contribution.installation_id,deployment_id:contribution.deployment_id,contribution_id:contribution.spec.id,contribution_digest:contribution.contribution_digest,method,idempotency_key:callerKey}));
  return 'ui-'+[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(value=>value.toString(16).padStart(2,'0')).join('');
}
function checkParams(method,params) {
  if(method==='skill.call')return fields(params,['binding_alias','input','idempotency_key'],['timeout_ms'])&&ALIAS.test(params.binding_alias)&&validText(params.idempotency_key,128)&&(params.timeout_ms===undefined||integer(params.timeout_ms,100,300000));
  if(method==='window.open')return fields(params,['contribution_id'])&&ALIAS.test(params.contribution_id);
  const definitions={
    'batch.create':[['binding_alias','request','idempotency_key'],[]],
    'batch.get':[['binding_alias','batch_id'],[]],
    'batch.items':[['binding_alias','batch_id'],['limit','cursor']],
    'batch.result':[['binding_alias','batch_id','item_id'],[]],
    'batch.cancel':[['binding_alias','batch_id','if_match','idempotency_key'],['reason']],
  };
  const declaration=definitions[method];
  return declaration&&fields(params,...declaration)&&ALIAS.test(params.binding_alias);
}
function backendError(error) {
  if(error instanceof ApiError&&integer(error.status,400,599)&&UUID.test(error.requestId||'')&&fields(error.detail,['code','message','retryable','violations','retry_after_ms','resource_id']))return {code:'BACKEND_ERROR',message:'核心拒绝此请求。',retryable:error.detail.retryable===true,http_status:error.status,backend_error:error.detail,core_request_id:error.requestId};
  if(error?.bridge)return error.bridge;
  if(error?.code==='DEADLINE_EXCEEDED')return fail('DEADLINE_EXCEEDED','核心等待超时；保留原请求键核实结果。');
  if(error?.status===401||error?.status===403)return fail('PERMISSION_DENIED','当前授权已失效。');
  return fail('BINDING_UNAVAILABLE','核心或固定绑定当前不可用。');
}

export class BridgeHost {
  #iframe;#api;#fixed;#signature;#subject;#current;#open;#onState;#parent;#core;#theme;
  #id;#nonce;#incoming=0;#outgoing=0;#initialized=false;#closed=false;#inflight=0;#queued=0;#highest=0;#cache=new Map();#cachedBytes=0;#acceptQueue=Promise.resolve();#events=new Map();#animation;#rate=[];#listener;#loadListener;#loaded=false;#loading;#handshake;#poll;#controller=new AbortController();#visible=true;
  constructor({iframe,api,contribution,subjectId,isCurrent,openWindow,onState=()=>{},theme,parentOrigin=location.origin,coreOrigin,viewId=crypto.randomUUID()}) {
    if(!UUID.test(subjectId)||typeof isCurrent!=='function'||parentOrigin!==location.origin||new URL(parentOrigin).protocol!=='https:'||new URL(coreOrigin).protocol!=='https:'||new URL(coreOrigin).origin!==coreOrigin||parentOrigin===coreOrigin)throw problem('PERMISSION_DENIED','当前账户或宿主来源不可用。');
    this.#fixed=validateContribution(contribution,{parentOrigin,coreOrigin});this.#signature=canonical(this.#fixed);
    this.#iframe=iframe;this.#api=api;this.#subject=subjectId;this.#current=isCurrent;this.#open=openWindow;this.#onState=onState;this.#parent=parentOrigin;this.#core=coreOrigin;this.#theme=theme;
    if(!UUID.test(viewId))throw problem('PROTOCOL_ERROR','窗口视图标识无效。');
    this.#id=viewId;this.#nonce=[...crypto.getRandomValues(new Uint8Array(32))].map(value=>value.toString(16).padStart(2,'0')).join('');
    iframe.setAttribute('sandbox','allow-scripts allow-same-origin');iframe.setAttribute('referrerpolicy','no-referrer');iframe.setAttribute('title',this.#fixed.spec.title);
    this.#listener=event=>{this.#receive(event).catch(()=>this.close('unavailable'));};
    window.addEventListener('message',this.#listener);
  }
  get viewId(){return this.#id;}
  async mount(){
    try{
      await this.#verify();
      const url=new URL(this.#fixed.frame_url);
      url.hash=new URLSearchParams({protocol:PROTOCOL,view_id:this.#id,channel_nonce:this.#nonce,parent_origin:this.#parent}).toString();
      this.#loadListener=()=>{
        if(this.#closed)return;
        if(this.#loaded){this.close('unavailable');return;}
        this.#loaded=true;clearTimeout(this.#loading);
        // The protocol grants ten seconds after document load. Fetching the
        // page has its own unchanged ten-second bound and consumes no handshake
        // budget; an already verified early ready needs no second timer.
        if(!this.#initialized)this.#handshake=setTimeout(()=>this.close('unavailable'),10000);
      };
      this.#iframe.addEventListener('load',this.#loadListener);
      this.#loading=setTimeout(()=>this.close('unavailable'),10000);
      this.#iframe.src=url.href;
      this.#poll=setInterval(()=>{this.#verify().catch(()=>this.close('unavailable'));},5000);
      this.#onState('loading');
    }catch(error){this.close('unavailable');throw error;}
  }
  async #verify(){
    if(this.#closed||!this.#current(this.#subject))throw problem('CHANNEL_CLOSED','账户或页面通道已结束。');
    let current;
    try{current=await this.#api.invoke('getUiContribution',{params:{deployment_id:this.#fixed.deployment_id,contribution_id:this.#fixed.spec.id},signal:this.#controller.signal});}
    catch(error){this.close(error?.status===401?'logout':'unavailable');throw error;}
    if(this.#closed||!this.#current(this.#subject))throw problem('CHANNEL_CLOSED','账户或页面通道已结束。');
    const checked=validateContribution(current.data,{parentOrigin:this.#parent,coreOrigin:this.#core});
    if(canonical(checked)!==this.#signature){this.close('upgrade');throw problem('CHANNEL_CLOSED','固定贡献、权限或部署已改变，必须重新打开。');}
  }
  #send(type,body={}){
    if(this.#closed||!this.#iframe.contentWindow)return;
    if(this.#outgoing>=Number.MAX_SAFE_INTEGER){this.close('unavailable');return;}
    const message={protocol:PROTOCOL,view_id:this.#id,channel_nonce:this.#nonce,seq:++this.#outgoing,type,...body};
    canonical(message);
    this.#iframe.contentWindow.postMessage(message,this.#fixed.frame_origin);
  }
  async #receive(event){
    if(this.#closed||event.source!==this.#iframe.contentWindow||event.origin!==this.#fixed.frame_origin||event.origin==='null'||event.ports.length)return;
    const message=event.data;
    if(!plain(message)||message.protocol!==PROTOCOL||message.view_id!==this.#id||message.channel_nonce!==this.#nonce)return;
    if(!integer(message.seq,1,Number.MAX_SAFE_INTEGER)||message.seq<=this.#incoming)return;
    if(message.type==='ready'&&(this.#initialized||message.seq!==1||this.#incoming>0))return;
    if(this.#initialized&&message.type==='request'){
      if(!integer(message.request_id,1,Number.MAX_SAFE_INTEGER)||!METHODS.has(message.method)){this.close('unavailable');return;}
      // Rate admission precedes traversal/encoding of untrusted business input.
      // Rejected floods cannot repeatedly expand a large shared-reference tree.
      const now=performance.now();this.#rate=this.#rate.filter(time=>now-time<60000);
      if(this.#rate.length>=120){this.#respond(message,{ok:false,error:fail('RATE_LIMITED','页面请求速率达到上限。')});return;}
      this.#rate.push(now);
    }
    try{canonical(message,1024*1024);}catch{this.close('unavailable');return;}
    this.#incoming=message.seq;
    if(message.type==='ready'){
      if(this.#initialized||message.seq!==1||!fields(message,['protocol','view_id','channel_nonce','seq','type']))return;
      await this.#verify();if(this.#closed)return;
      this.#initialized=true;clearTimeout(this.#handshake);
      this.#send('host.init',{params:{...this.#theme(),visible:this.#visible,viewport:this.#viewport(),locale:(navigator.language||'en').slice(0,35),contribution_digest:this.#fixed.contribution_digest,bindings:this.#fixed.bindings}});
      this.#onState('active');return;
    }
    if(!this.#initialized||!fields(message,['protocol','view_id','channel_nonce','seq','type','request_id','method','params'])||message.type!=='request'||!integer(message.request_id,1,Number.MAX_SAFE_INTEGER)||!METHODS.has(message.method)){this.close('unavailable');return;}
    if(!checkParams(message.method,message.params)){this.#respond(message,{ok:false,error:fail('PROTOCOL_ERROR','桥方法参数不符合固定契约。')});return;}
    if(this.#queued>=4||(!this.#cache.has(message.request_id)&&this.#queued+this.#inflight>=4)){this.#respond(message,{ok:false,error:fail('RATE_LIMITED','页面最多4个在途请求。')});return;}
    // Preserve accepted request-id order while asynchronous SHA-256 is running.
    // Business calls themselves remain concurrent up to the four-request cap.
    this.#queued++;
    this.#acceptQueue=this.#acceptQueue.then(()=>this.#accept(message)).catch(()=>this.close('unavailable')).finally(()=>{this.#queued--;});
  }
  async #accept(message){
    if(this.#closed)return;
    const now=performance.now();
    for(const [id,entry]of this.#cache)if(entry.finished&&now-entry.at>15*60000){this.#cachedBytes-=entry.bytes;this.#cache.delete(id);}
    const fingerprint=await sha256(canonical({method:message.method,params:message.params},1024*1024));
    if(this.#closed)return;
    const cached=this.#cache.get(message.request_id);
    if(cached){
      if(cached.fingerprint!==fingerprint){this.#respond(message,{ok:false,error:fail('IDEMPOTENCY_CONFLICT','同一请求编号已用于不同内容。')});return;}
      // The original pending response already answers this request_id. Do not
      // create additional waiting callbacks for repeated messages.
      if(!cached.finished)return;
      if(!cached.promise){this.#respond(message,{ok:false,error:fail('CHANNEL_CLOSED','大结果缓存已淘汰，请按原请求键核实。')});this.close('unavailable');return;}
      this.#deliver(message,cached.promise).catch(()=>this.close('unavailable'));return;
    }
    if(message.request_id<=this.#highest){this.#respond(message,{ok:false,error:fail('CHANNEL_CLOSED','旧编号已淘汰，请按原核心请求键核实。')});this.close('unavailable');return;}
    if(this.#inflight>=4){this.#respond(message,{ok:false,error:fail('RATE_LIMITED','页面最多4个在途请求。')});return;}
    this.#highest=message.request_id;this.#inflight++;
    const entry={fingerprint,at:now,finished:false,promise:null,bytes:0};
    entry.promise=this.#execute(message).then(result=>({ok:true,result})).catch(error=>({ok:false,error:backendError(error)})).then(response=>{
      this.#inflight--;entry.finished=true;
      if(!this.#closed){entry.bytes=new TextEncoder().encode(canonical(response)).byteLength;this.#cachedBytes+=entry.bytes;this.#trimCache();}
      return response;
    });
    this.#cache.set(message.request_id,entry);
    this.#trimCache();
    this.#deliver(message,entry.promise).catch(()=>this.close('unavailable'));
  }
  async #deliver(message,promise){
    await this.#verify();const response=await promise;
    if(response.ok&&message.method==='skill.call'){
      const call=response.result.call;
      if(!UUID.test(call.call_id))throw problem('PROTOCOL_ERROR','核心调用标识无效。');
      // This is a read of the original Call, never a repeated business intent.
      // Core rechecks the original credential and frozen business/data proof.
      const proof=await this.#api.invoke('getCall',{params:{call_id:call.call_id},signal:this.#controller.signal});
      if(!fields(proof.data,['call_id','state','result','error'])||proof.data.call_id!==call.call_id||proof.data.state!=='succeeded'||canonical(proof.data.result)!==canonical(call))throw problem('BINDING_UNAVAILABLE','原调用结果或当前读取证明不可用。');
    }
    await this.#verify();this.#respond(message,response);
  }
  #trimCache(){
    while(this.#cache.size>256){const oldest=[...this.#cache].find(([,value])=>value.finished);if(!oldest)break;this.#cachedBytes-=oldest[1].bytes;this.#cache.delete(oldest[0]);}
    // Keep the required deduplication metadata, but bound retained business
    // payloads to 32MiB per view. Evicted results never become new executions.
    for(const entry of this.#cache.values())if(this.#cachedBytes>32*1024*1024&&entry.finished&&entry.promise){this.#cachedBytes-=entry.bytes;entry.bytes=0;entry.promise=null;}
  }
  #respond(message,response){this.#send('response',{request_id:message.request_id,method:message.method,...response});}
  async #execute(message){
    await this.#verify();
    if(message.method.startsWith('batch.'))throw problem('METHOD_NOT_ALLOWED','BatchEngine 尚未交付；此桥未提交或伪造批次。');
    if(message.method==='window.open'){
      const response=await this.#api.invoke('getUiContribution',{params:{deployment_id:this.#fixed.deployment_id,contribution_id:message.params.contribution_id},signal:this.#controller.signal});
      const contribution=validateContribution(response.data,{parentOrigin:this.#parent,coreOrigin:this.#core});
      if(contribution.deployment_id!==this.#fixed.deployment_id||contribution.installation_id!==this.#fixed.installation_id||contribution.manifest_digest!==this.#fixed.manifest_digest||contribution.plugin_id!==this.#fixed.plugin_id||contribution.frame_origin!==this.#fixed.frame_origin||contribution.spec.kind!=='window')throw problem('PERMISSION_DENIED','仅可打开同一固定部署的获准窗口。');
      const sourceCurrent=()=>!this.#closed&&this.#current(this.#subject);
      if(!sourceCurrent())throw problem('CHANNEL_CLOSED','账户或页面通道已结束。');
      const viewId=await this.#open(contribution,sourceCurrent);
      if(!sourceCurrent())throw problem('CHANNEL_CLOSED','账户或页面通道已结束。');
      if(!UUID.test(viewId||''))throw problem('RATE_LIMITED','窗口不可用或已达上限。');return{view_id:viewId};
    }
    const binding=this.#fixed.bindings.find(value=>value.alias===message.params.binding_alias&&value.modes.includes('call'));
    if(!binding)throw problem('BINDING_UNAVAILABLE','未获准此固定 Skill 调用绑定。');
    const key=await deriveBridgeKey(this.#subject,this.#fixed,message.method,message.params.idempotency_key);
    // This public narrowing constraint comes only from the core-attested UI
    // contribution. The frame cannot choose or overwrite another deployment.
    const body={input:message.params.input,idempotency_key:key,provider_deployment_id:this.#fixed.deployment_id};if(message.params.timeout_ms!==undefined)body.timeout_ms=message.params.timeout_ms;
    // The kernel answers this request only after its own authorization reads
    // and the business deadline, and the host still reads the original Call
    // and rechecks the contribution afterwards. The HTTP wait must outlive
    // the business deadline in the body; aborting there breaks the bridge
    // exactly at body.timeout_ms whenever the pipeline is slower (#82).
    const businessMs=(Number.isInteger(body.timeout_ms)&&body.timeout_ms>=100&&body.timeout_ms<=300000)?body.timeout_ms:120000;
    const response=await this.#api.invoke('invokeSkill',{params:{skill_id:binding.skill_id},body,idempotencyKey:key,signal:this.#controller.signal,waitBudgetMs:businessMs+3*10000+2000});
    const result=response.data;
    const declaration=this.#fixed.spec.skill_bindings.find(value=>value.alias===binding.alias);
    if(!fields(result,['skill_id','skill_version','definition_digest','call'])||result.skill_id!==binding.skill_id||result.definition_digest!==binding.definition_digest||result.skill_version!==declaration.version||!plain(result.call)||result.call.skill_id!==binding.skill_id||result.call.skill_definition_digest!==binding.definition_digest)throw problem('BINDING_UNAVAILABLE','核心结果的固定 Skill 身份不匹配。');
    if(new TextEncoder().encode(canonical(result.call.output)).byteLength>16*1024*1024)throw problem('PAYLOAD_TOO_LARGE','业务结果超过16MiB。');
    return result;
  }
  #viewport(){return{width:Math.max(1,Math.min(8192,this.#iframe.clientWidth)),height:Math.max(1,Math.min(8192,this.#iframe.clientHeight))};}
  #schedule(event,params){if(!this.#initialized||this.#closed)return;this.#events.set(event,params);if(this.#animation)return;this.#animation=requestAnimationFrame(()=>{this.#animation=null;for(const[event,params]of this.#events)this.#send('event',{event,params});this.#events.clear();});}
  themeChanged(){this.#schedule('theme.changed',this.#theme());}
  viewportChanged(){this.#schedule('viewport.changed',this.#viewport());}
  setVisible(visible){if(this.#visible===visible)return;this.#visible=visible;if(this.#initialized)this.#send('event',{event:'visibility.changed',params:{visible}});}
  async refresh(){if(this.#initialized&&this.#visible&&this.#fixed.spec.kind==='widget'){await this.#verify();if(!this.#closed)this.#send('event',{event:'widget.refresh',params:{}});}}
  close(reason='close'){
    if(this.#closed)return;
    if(this.#outgoing<Number.MAX_SAFE_INTEGER)this.#send('event',{event:'host.dispose',params:{reason}});this.#closed=true;this.#controller.abort();clearTimeout(this.#loading);clearTimeout(this.#handshake);clearInterval(this.#poll);cancelAnimationFrame(this.#animation);this.#events.clear();window.removeEventListener('message',this.#listener);this.#iframe.removeEventListener('load',this.#loadListener);this.#cache.clear();this.#cachedBytes=0;this.#nonce='';this.#iframe.remove();this.#onState('closed',reason);
  }
}
