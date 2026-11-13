// An iframe-side protocol client. It never receives a core credential or URL
// proxy and can request only this signed page's fixed echo/window operations.
const PROTOCOL = 'xelab.ui/1';
const MANAGEMENT_TIMEOUT_MS = 10_000;
const ECHO_TIMEOUT_MS = 10_000;
// The host checks the contribution before invocation, reads the original Call,
// and rechecks the contribution before delivery. Each read has its own budget.
const ECHO_RESPONSE_WAIT_MS = ECHO_TIMEOUT_MS + 3 * MANAGEMENT_TIMEOUT_MS;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const plain = value => value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;
const fields = (value, required, optional = []) => plain(value) && required.every(key => Object.hasOwn(value, key)) && Object.keys(value).every(key => required.includes(key) || optional.includes(key));
const integer = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;
const text = (value, max) => typeof value === 'string' && value.length > 0 && [...value].length <= max;

function failure(code, message) { return Object.assign(new Error(message), {code, retryable: false}); }

export function parseMetadata(hash, ownOrigin) {
  const parameters = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash);
  const required = ['protocol', 'view_id', 'channel_nonce', 'parent_origin'];
  if ([...parameters].length !== required.length || required.some(key => parameters.getAll(key).length !== 1)
      || [...parameters.keys()].some(key => !required.includes(key))) throw failure('PROTOCOL_ERROR', 'Invalid channel metadata.');
  const value = Object.fromEntries(parameters);
  let parent;
  try { parent = new URL(value.parent_origin); } catch { throw failure('PROTOCOL_ERROR', 'Invalid parent origin.'); }
  if (value.protocol !== PROTOCOL || !UUID.test(value.view_id) || !/^[a-f0-9]{64}$/.test(value.channel_nonce)
      || parent.protocol !== 'https:' || parent.origin !== value.parent_origin || parent.username || parent.password
      || parent.search || parent.hash || parent.origin === ownOrigin) throw failure('PROTOCOL_ERROR', 'A separate exact HTTPS parent is required.');
  return Object.freeze(value);
}

// Count the expanded JSON representation while visiting it. A repeated object
// graph must not bypass the byte limit or cause unbounded stringify expansion.
export function safeJson(value, maximum = 16 * 1024 * 1024 + 65536) {
  const encoder = new TextEncoder(), parts = [], seen = new Set();
  let bytes = 0;
  const emit = string => { bytes += encoder.encode(string).byteLength; if (bytes > maximum) throw failure('PAYLOAD_TOO_LARGE', 'Message byte limit exceeded.'); parts.push(string); };
  function string(current) {
    if (current.length > maximum) throw failure('PAYLOAD_TOO_LARGE', 'Message string is too large.');
    for (let index = 0; index < current.length; index++) {
      const code = current.charCodeAt(index);
      if (code >= 0xd800 && code <= 0xdbff) { const next = current.charCodeAt(++index); if (!(next >= 0xdc00 && next <= 0xdfff)) throw failure('PROTOCOL_ERROR', 'Invalid Unicode.'); }
      else if (code >= 0xdc00 && code <= 0xdfff) throw failure('PROTOCOL_ERROR', 'Invalid Unicode.');
    }
    emit(JSON.stringify(current));
  }
  function visit(current, depth) {
    if (depth > 64) throw failure('PROTOCOL_ERROR', 'Message nesting exceeds 64 levels.');
    if (typeof current === 'string') { string(current); return; }
    if (current === null || typeof current === 'boolean' || (typeof current === 'number' && Number.isFinite(current))) { emit(JSON.stringify(current)); return; }
    if ((!plain(current) && !Array.isArray(current)) || seen.has(current)) throw failure('PROTOCOL_ERROR', 'Message must contain plain acyclic JSON.');
    seen.add(current);
    const descriptors = Object.getOwnPropertyDescriptors(current);
    if (Object.values(descriptors).some(item => item.get || item.set)) throw failure('PROTOCOL_ERROR', 'Accessors are not JSON.');
    if (Array.isArray(current)) {
      emit('['); for (let index = 0; index < current.length; index++) { if (index) emit(','); visit(current[index], depth + 1); } emit(']');
    } else {
      const keys = Object.keys(current);
      if (keys.length > maximum / 3) throw failure('PAYLOAD_TOO_LARGE', 'Too many object members.');
      emit('{'); for (const [index, key] of keys.entries()) { if (index) emit(','); string(key); emit(':'); visit(current[key], depth + 1); } emit('}');
    }
    seen.delete(current);
  }
  visit(value, 0);
  return JSON.parse(parts.join(''));
}

function theme(value) {
  const colors = ['accent', 'desktop', 'surface', 'text', 'muted_text', 'border', 'danger'];
  return fields(value, [...colors, 'radius_px', 'blur_px', 'panel_opacity', 'font'])
    && colors.every(key => /^#[a-fA-F0-9]{6}$/.test(value[key]))
    && integer(value.radius_px, 0, 24) && integer(value.blur_px, 0, 32)
    && typeof value.panel_opacity === 'number' && Number.isFinite(value.panel_opacity) && value.panel_opacity >= 0.6 && value.panel_opacity <= 1
    && ['system', 'sans', 'serif', 'mono'].includes(value.font);
}
function viewport(value) { return fields(value, ['width', 'height']) && integer(value.width, 1, 8192) && integer(value.height, 1, 8192); }
function themeEvent(value) { return fields(value, ['theme_tokens', 'reduce_motion', 'reduce_transparency']) && theme(value.theme_tokens) && typeof value.reduce_motion === 'boolean' && typeof value.reduce_transparency === 'boolean'; }
function init(value) {
  return fields(value, ['theme_tokens', 'reduce_motion', 'reduce_transparency', 'visible', 'viewport', 'locale', 'contribution_digest', 'bindings'])
    && theme(value.theme_tokens) && typeof value.reduce_motion === 'boolean' && typeof value.reduce_transparency === 'boolean'
    && typeof value.visible === 'boolean' && viewport(value.viewport) && text(value.locale, 35) && DIGEST.test(value.contribution_digest)
    && Array.isArray(value.bindings) && value.bindings.length <= 1 && value.bindings.every(binding => fields(binding, ['alias', 'skill_id', 'definition_digest', 'modes'])
      && binding.alias === 'echo' && UUID.test(binding.skill_id) && DIGEST.test(binding.definition_digest)
      && Array.isArray(binding.modes) && binding.modes.length === 1 && binding.modes[0] === 'call');
}

export class BridgeClient {
  #metadata; #target; #listen; #listener; #outgoing = 0; #incoming = 0; #highest = 0; #initialized = false; #closed = false; #pending = new Map(); #timer; #notify; #binding;
  constructor({metadata = parseMetadata(location.hash, location.origin), target = window.parent, listen = window, onState = () => {}} = {}) {
    this.#metadata = metadata; this.#target = target; this.#listen = listen; this.#notify = onState;
    this.#listener = event => this.#receive(event);
    listen.addEventListener('message', this.#listener);
    this.#timer = setTimeout(() => this.close('The trusted host did not initialize this channel.'), 10000);
    this.#send('ready');
  }
  get ready() { return this.#initialized && !this.#closed; }
  get canCall() { return this.ready && Boolean(this.#binding); }
  #send(type, body = {}) {
    if (this.#closed || this.#outgoing >= Number.MAX_SAFE_INTEGER) throw failure('CHANNEL_CLOSED', 'The channel is closed.');
    const message = safeJson({...this.#metadata, seq: ++this.#outgoing, type, ...body}, 1024 * 1024);
    // parent_origin belongs to fragment routing metadata, not the wire envelope.
    delete message.parent_origin;
    this.#target.postMessage(message, this.#metadata.parent_origin);
  }
  #receive(event) {
    if (this.#closed || event.source !== this.#target || event.origin !== this.#metadata.parent_origin || event.ports?.length) return;
    let value;
    try { value = safeJson(event.data); } catch { this.close('The host sent invalid JSON.'); return; }
    if (!plain(value) || value.protocol !== PROTOCOL || value.view_id !== this.#metadata.view_id || value.channel_nonce !== this.#metadata.channel_nonce) return;
    if (!integer(value.seq, 1, Number.MAX_SAFE_INTEGER) || value.seq <= this.#incoming) return;
    if (value.type === 'host.init') {
      if (this.#initialized || value.seq !== 1 || !fields(value, ['protocol', 'view_id', 'channel_nonce', 'seq', 'type', 'params']) || !init(value.params)) return;
      this.#incoming = value.seq; this.#initialized = true; this.#binding = value.params.bindings[0]; clearTimeout(this.#timer);
      this.#notify('ready', value.params); return;
    }
    if (!this.#initialized) return;
    if (value.type === 'event' && fields(value, ['protocol', 'view_id', 'channel_nonce', 'seq', 'type', 'event', 'params'])) {
      const valid = value.event === 'theme.changed' ? themeEvent(value.params)
        : value.event === 'viewport.changed' ? viewport(value.params)
        : value.event === 'visibility.changed' ? fields(value.params, ['visible']) && typeof value.params.visible === 'boolean'
        : value.event === 'widget.refresh' ? fields(value.params, [])
        : value.event === 'host.dispose' ? fields(value.params, ['reason']) && ['close', 'logout', 'upgrade', 'unavailable'].includes(value.params.reason) : false;
      if (!valid) return;
      this.#incoming = value.seq;
      if (value.event === 'host.dispose') { this.close(`Host closed this channel (${value.params.reason}).`); return; }
      this.#notify(value.event, value.params); return;
    }
    if (value.type !== 'response' || !fields(value, ['protocol', 'view_id', 'channel_nonce', 'seq', 'type', 'request_id', 'method', 'ok'], value.ok ? ['result'] : ['error'])
        || typeof value.ok !== 'boolean' || !integer(value.request_id, 1, Number.MAX_SAFE_INTEGER) || !Object.hasOwn(value, value.ok ? 'result' : 'error')) return;
    const pending = this.#pending.get(value.request_id);
    if (!pending || pending.method !== value.method) return;
    this.#incoming = value.seq; clearTimeout(pending.timer); this.#pending.delete(value.request_id);
    if (value.ok) {
      const result = value.result;
      if (value.method === 'window.open' ? !fields(result, ['view_id']) || !UUID.test(result.view_id)
        : !fields(result, ['skill_id', 'skill_version', 'definition_digest', 'call']) || !text(result.skill_version, 128) || result.skill_id !== this.#binding?.skill_id
          || result.definition_digest !== this.#binding?.definition_digest || !plain(result.call) || !UUID.test(result.call.call_id)
          || !fields(result.call.output, ['message']) || typeof result.call.output.message !== 'string' || [...result.call.output.message].length > 1024) {
        pending.reject(failure('PROTOCOL_ERROR', 'The fixed binding result is invalid.')); return;
      }
      pending.resolve(result);
    } else {
      const error = value.error;
      if (!fields(error, ['code', 'message', 'retryable'], ['http_status', 'backend_error', 'core_request_id']) || !text(error.code, 80) || !text(error.message, 2048) || typeof error.retryable !== 'boolean') {
        pending.reject(failure('PROTOCOL_ERROR', 'Invalid bridge failure.')); return;
      }
      pending.reject(Object.assign(new Error(error.message), error));
    }
  }
  #request(method, params, responseWaitMs = MANAGEMENT_TIMEOUT_MS) {
    if (!this.ready) return Promise.reject(failure('CHANNEL_CLOSED', 'Open this page from an approved XeLab WebUI.'));
    if (this.#pending.size >= 4) return Promise.reject(failure('RATE_LIMITED', 'At most four requests may be pending.'));
    const request_id = ++this.#highest;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.#pending.delete(request_id); reject(failure('DEADLINE_EXCEEDED', 'Outcome is unknown. Keep the same intent key when checking it.')); }, responseWaitMs);
      this.#pending.set(request_id, {method, resolve, reject, timer});
      try { this.#send('request', {request_id, method, params}); }
      catch (error) { clearTimeout(timer); this.#pending.delete(request_id); reject(error); }
    });
  }
  callEcho(message, idempotencyKey) {
    if (!this.canCall) return Promise.reject(failure('BINDING_UNAVAILABLE', 'No approved echo Skill binding is available.'));
    if (typeof message !== 'string' || [...message].length > 1024 || !text(idempotencyKey, 128)) return Promise.reject(failure('PROTOCOL_ERROR', 'Message or stable intent key is invalid.'));
    return this.#request('skill.call', {binding_alias: 'echo', input: {message}, idempotency_key: idempotencyKey, timeout_ms: ECHO_TIMEOUT_MS}, ECHO_RESPONSE_WAIT_MS);
  }
  openWindow() { return this.#request('window.open', {contribution_id: 'echo_window'}); }
  close(message = 'Channel closed.') {
    if (this.#closed) return;
    this.#closed = true; this.#initialized = false; this.#binding = undefined; clearTimeout(this.#timer);
    this.#listen.removeEventListener('message', this.#listener);
    for (const pending of this.#pending.values()) { clearTimeout(pending.timer); pending.reject(failure('CHANNEL_CLOSED', message)); }
    this.#pending.clear(); this.#notify('closed', {message});
  }
}
