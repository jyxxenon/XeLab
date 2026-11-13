// The desktop may call only these public operations. This module is never
// exposed through the iframe bridge and accepts neither URLs nor custom headers.
export class ApiError extends Error {
  constructor(code, message, status = 0, requestId = null, detail = null) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.requestId = requestId;
    this.detail = detail;
  }
}

export function validateConfig(config) {
  if (!config || typeof config.core_origin !== 'string' || typeof config.client_id !== 'string') {
    throw new ApiError('CONFIGURATION_REQUIRED', 'WebUI 尚未配置可信核心与 Client。');
  }
  let origin;
  try { origin = new URL(config.core_origin); } catch { /* invalid below */ }
  if (!origin || origin.protocol !== 'https:' || origin.origin !== config.core_origin
      || origin.username || origin.password || origin.search || origin.hash
      || !/^[A-Za-z0-9._~-]{1,128}$/.test(config.client_id)) {
    throw new ApiError('INVALID_CONFIGURATION', '需要精确的 HTTPS 核心来源及公开 Client ID。');
  }
  return Object.freeze({ core_origin: origin.origin, client_id: config.client_id });
}

const BASE = '/api/platform/v1';
const page = Object.freeze({ limit: 'limit', cursor: 'cursor' });
const operation = (method, path, query = {}, body = false, revision = false) =>
  Object.freeze({ method, path: BASE + path, query: Object.freeze(query), body, revision });

// Names and paths match docs/contracts/openapi.json. Future Batch/Workflow/MPR
// operations are deliberately absent so a desktop cannot imply they succeeded.
export const OPERATIONS = Object.freeze({
  getNode: operation('GET', '/node'),
  listSessions: operation('GET', '/sessions', page),
  listAccounts: operation('GET', '/accounts', { ...page, parent_id: 'uuid' }),
  getAccount: operation('GET', '/accounts/{account_id}'),
  listApiKeys: operation('GET', '/accounts/{account_id}/api-keys', page),
  getApiKey: operation('GET', '/api-keys/{credential_id}'),
  updateAccount: operation('PATCH', '/accounts/{account_id}', {}, true, true),
  createChildAccount: operation('POST', '/accounts/{account_id}/children', {}, true),
  getEffectivePermissions: operation('GET', '/accounts/{account_id}/effective-permissions'),
  listRoles: operation('GET', '/roles', page),
  listPermissions: operation('GET', '/permission-definitions', page),
  listGrants: operation('GET', '/accounts/{account_id}/grants', page),
  getQuota: operation('GET', '/accounts/{account_id}/quota'),
  listPublishers: operation('GET', '/publishers', page),
  listInstallations: operation('GET', '/installations', { ...page, plugin_id: 'plugin' }),
  installPlugin: operation('POST', '/installations', {}, true),
  getInstallation: operation('GET', '/installations/{installation_id}'),
  uninstallPlugin: operation('DELETE', '/installations/{installation_id}', {}, false, true),
  listDeployments: operation('GET', '/deployments', page),
  createDeployment: operation('POST', '/deployments', {}, true),
  getDeployment: operation('GET', '/deployments/{deployment_id}'),
  updateDeployment: operation('PUT', '/deployments/{deployment_id}', {}, true, true),
  deleteDeployment: operation('DELETE', '/deployments/{deployment_id}', {}, false, true),
  setDeploymentEnabled: operation('PUT', '/deployments/{deployment_id}/enabled', {}, true, true),
  approvePlugin: operation('PUT', '/deployments/{deployment_id}/approval', {}, true, true),
  getPluginApproval: operation('GET', '/deployments/{deployment_id}/approval'),
  upgradeDeployment: operation('POST', '/deployments/{deployment_id}/upgrade', {}, true, true),
  rollbackDeployment: operation('POST', '/deployments/{deployment_id}/rollback', {}, true, true),
  listInstances: operation('GET', '/instances', { ...page, deployment_id: 'uuid' }),
  getInstance: operation('GET', '/instances/{instance_id}'),
  getOperation: operation('GET', '/operations/{operation_id}'),
  listSkills: operation('GET', '/skills', page),
  registerSkill: operation('POST', '/skills', {}, true),
  getSkill: operation('GET', '/skills/{skill_id}'),
  setSkillEnabled: operation('PUT', '/skills/{skill_id}/enabled', {}, true, true),
  archiveSkill: operation('DELETE', '/skills/{skill_id}', {}, false, true),
  invokeSkill: operation('POST', '/skills/{skill_id}/calls', {}, true),
  getCall: operation('GET', '/calls/{call_id}'),
  listClients: operation('GET', '/clients', page),
  createClient: operation('POST', '/clients', {}, true),
  getClient: operation('GET', '/clients/{client_id}'),
  updateClient: operation('PUT', '/clients/{client_id}', {}, true, true),
  disableClient: operation('DELETE', '/clients/{client_id}', {}, false, true),
  getDefaultUi: operation('GET', '/default-ui'),
  setDefaultUi: operation('PUT', '/default-ui', {}, true, true),
  getMyUiPreferences: operation('GET', '/me/ui-preferences'),
  setMyUiPreferences: operation('PUT', '/me/ui-preferences', {}, true, true),
  listUiContributions: operation('GET', '/ui/contributions', { ...page, kind: 'kind' }),
  getUiContribution: operation('GET', '/ui/contributions/{deployment_id}/{contribution_id}'),
});

function plain(value) {
  return value !== null && typeof value === 'object'
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

export function strictJson(value) {
  const seen = new Set();
  function check(current, depth) {
    if (depth > 64) throw new ApiError('INVALID_ARGUMENT', 'JSON 嵌套超过64层。');
    if (current === null || typeof current === 'string' || typeof current === 'boolean') return;
    if (typeof current === 'number' && Number.isFinite(current)) return;
    if ((!Array.isArray(current) && !plain(current)) || seen.has(current)) {
      throw new ApiError('INVALID_ARGUMENT', '请求必须是有限数字和普通 JSON 值。');
    }
    seen.add(current);
    for (const entry of Array.isArray(current) ? current : Object.values(current)) check(entry, depth + 1);
    seen.delete(current);
  }
  check(value, 0);
  return JSON.stringify(value);
}

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function parameter(value, type) {
  if (type === 'limit') {
    if (!Number.isInteger(value) || value < 1 || value > 200) throw new ApiError('INVALID_ARGUMENT', '页大小须为1至200。');
    return String(value);
  }
  if (typeof value !== 'string' || !value || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new ApiError('INVALID_ARGUMENT', '无效的请求参数。');
  }
  const valid = type === 'uuid' ? uuid.test(value)
    : type === 'plugin' ? value.length <= 128 && /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$/.test(value)
      : type === 'kind' ? ['window', 'widget'].includes(value)
        : type === 'contribution' ? value.length <= 80 && !/[/?#%\\]/.test(value) && value !== '.' && value !== '..'
          : type === 'cursor' ? value.length <= 2048 : false;
  if (!valid) throw new ApiError('INVALID_ARGUMENT', '无效的请求参数。');
  return value;
}

export async function readJson(response, maximum = 16 * 1024 * 1024 + 65536) {
  if (response.status === 204) return null;
  const declared = response.headers.get('content-length');
  if (declared && (!/^\d+$/.test(declared) || Number(declared) > maximum)) {
    await response.body?.cancel();
    throw new ApiError('PAYLOAD_TOO_LARGE', '核心响应超过显示限制。', response.status);
  }
  const type = response.headers.get('content-type') || '';
  if (!/^application\/json(?:\s*;|$)/i.test(type)) {
    await response.body?.cancel();
    throw new ApiError('INVALID_RESPONSE', '核心没有返回 JSON。', response.status);
  }
  let text;
  if (response.body?.getReader) {
    // Check the byte cap before native allocation while preserving the original
    // Response's native body consumer. Its tee branch retains the bounded body;
    // the counting branch does not keep a second JavaScript chunks array.
    const reader = response.clone().body.getReader();
    let bytes = 0;
    let all;
    const cancelBranches = () => Promise.allSettled([
      Promise.resolve().then(() => reader.cancel()),
      Promise.resolve().then(() => response.body.cancel()),
    ]);
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        bytes += value.byteLength;
        if (bytes > maximum) throw new ApiError('PAYLOAD_TOO_LARGE', '核心响应超过显示限制。', response.status);
      }
      all = new Uint8Array(await response.arrayBuffer());
      if (all.byteLength !== bytes) throw new ApiError('INVALID_RESPONSE', '核心响应字节计数不一致。', response.status);
    } catch (error) {
      // A tee cancellation waits for both branches; cancel them together.
      await cancelBranches();
      throw error;
    } finally { reader.releaseLock(); }
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(all); }
    catch { throw new ApiError('INVALID_RESPONSE', '核心响应不是有效 UTF-8。', response.status); }
  } else {
    text = await response.text();
    if (new TextEncoder().encode(text).byteLength > maximum) throw new ApiError('PAYLOAD_TOO_LARGE', '核心响应超过显示限制。', response.status);
  }
  try { return JSON.parse(text); }
  catch { throw new ApiError('INVALID_RESPONSE', '核心响应不是有效 JSON。', response.status); }
}

export class ApiClient {
  #config;
  #oauth;
  #fetch;

  constructor(config, oauth, { fetcher = globalThis.fetch } = {}) {
    this.#config = validateConfig(config);
    this.#oauth = oauth;
    // Window.fetch requires its Window receiver; storing the native function
    // as an instance field must not call it with the ApiClient as `this`.
    this.#fetch = fetcher.bind(globalThis);
  }

  async invoke(name, options = {}) {
    if (!plain(options) || Object.keys(options).some(key => !['params', 'query', 'body', 'etag', 'idempotencyKey', 'signal', 'waitBudgetMs'].includes(key))) {
      throw new ApiError('INVALID_ARGUMENT', '未声明的管理请求选项。');
    }
    const { params = {}, query = {}, body, etag, idempotencyKey, signal, waitBudgetMs } = options;
    if (!Object.hasOwn(OPERATIONS, name)) throw new ApiError('METHOD_NOT_ALLOWED', '没有此公开管理操作。');
    const op = OPERATIONS[name];
    if (!plain(params) || !plain(query)) throw new ApiError('INVALID_ARGUMENT', '参数须为普通对象。');
    const required = [...op.path.matchAll(/\{([a-z_]+)\}/g)].map(match => match[1]);
    if (Object.keys(params).length !== required.length || required.some(key => !Object.hasOwn(params, key))) {
      throw new ApiError('INVALID_ARGUMENT', '路径参数不匹配。');
    }
    const path = op.path.replace(/\{([a-z_]+)\}/g, (_, key) => encodeURIComponent(parameter(params[key], key === 'contribution_id' ? 'contribution' : 'uuid')));
    const url = new URL(path, this.#config.core_origin);
    for (const [key, value] of Object.entries(query)) {
      if (!Object.hasOwn(op.query, key)) throw new ApiError('INVALID_ARGUMENT', '未声明的查询参数。');
      url.searchParams.set(key, parameter(value, op.query[key]));
    }
    const headers = new Headers({ Accept: 'application/json' });
    let encoded;
    if (op.body !== (body !== undefined)) throw new ApiError('INVALID_ARGUMENT', op.body ? '需要 JSON 请求体。' : '此操作不接受请求体。');
    if (body !== undefined) {
      encoded = strictJson(body);
      if (new TextEncoder().encode(encoded).byteLength > 4 * 1024 * 1024) throw new ApiError('PAYLOAD_TOO_LARGE', '请求超过4MiB。');
      headers.set('Content-Type', 'application/json');
    }
    if (op.method !== 'GET') {
      if (typeof idempotencyKey !== 'string' || !/^[\x21-\x7e]{1,128}$/.test(idempotencyKey)) {
        throw new ApiError('INVALID_ARGUMENT', '写操作需要独立且稳定的 Idempotency-Key。');
      }
      headers.set('Idempotency-Key', idempotencyKey);
    } else if (idempotencyKey !== undefined) throw new ApiError('INVALID_ARGUMENT', '读取操作不接受幂等键。');
    if (op.revision) {
      if (typeof etag !== 'string' || !/^"rev-[1-9][0-9]*"$/.test(etag)) throw new ApiError('PRECONDITION_REQUIRED', '先读取当前强 ETag。', 428);
      headers.set('If-Match', etag);
    } else if (etag !== undefined) throw new ApiError('INVALID_ARGUMENT', '此操作不接受 If-Match。');
    const token = await this.#oauth.accessToken();
    if (typeof token !== 'string' || !token || token.length > 4096 || /[\u0000-\u0020\u007f]/.test(token)) throw new ApiError('AUTH_REQUIRED', '请通过可信核心登录。', 401);
    headers.set('Authorization', `Bearer ${token}`);
    // The derived deadline is the caller-visible business budget. A caller
    // that owns the surrounding pipeline may pass a longer HTTP wait budget
    // (waitBudgetMs) so a slow core pipeline is not aborted at the business
    // deadline; the deadline sent to core (body.timeout_ms) stays unchanged.
    const budget = Number.isInteger(waitBudgetMs) && waitBudgetMs >= 100 && waitBudgetMs <= 600000
      ? waitBudgetMs
      : name === 'invokeSkill'
        ? (Number.isInteger(body?.timeout_ms) && body.timeout_ms >= 100 && body.timeout_ms <= 300000 ? body.timeout_ms : 120000)
        : 10000;
    const deadline = AbortSignal.timeout(budget);
    const effectiveSignal = signal ? AbortSignal.any([signal, deadline]) : deadline;
    let response;
    try {
      response = await this.#fetch(url.href, {
        method: op.method, headers, body: encoded, signal: effectiveSignal,
        credentials: 'omit', mode: 'cors', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer',
      });
    } catch (error) {
      // Fetch may reject with any caller-supplied abort reason. Prefer the
      // actual signals, matching body-read classification below.
      if (signal?.aborted || (!deadline.aborted && error?.name === 'AbortError')) {
        throw new ApiError('CANCELED', '请求已取消；副作用状态须按原幂等键核实。');
      }
      if (deadline.aborted || error?.name === 'TimeoutError') {
        throw new ApiError('DEADLINE_EXCEEDED', '等待核心超时；副作用状态须按原幂等键核实。', 504);
      }
      throw new ApiError('CONNECTION_FAILED', '无法连接核心；未自动重试，请按原幂等键核实副作用。');
    }
    const requestId = response.headers.get('x-request-id');
    if (response.status === 401) {
      if (this.#oauth.invalidateAccessToken) this.#oauth.invalidateAccessToken(token);
      else this.#oauth.logout?.();
    }
    let data;
    try { data = await readJson(response); }
    catch (error) {
      if (error instanceof ApiError) throw error;
      const code = signal?.aborted ? 'CANCELED' : deadline.aborted ? 'DEADLINE_EXCEEDED' : 'CONNECTION_FAILED';
      throw new ApiError(code, '核心响应未完整接收；请核实原请求状态。', 0, requestId);
    }
    if (!response.ok) {
      const detail = plain(data?.error) ? data.error : null;
      throw new ApiError(detail?.code || `HTTP_${response.status}`, detail?.message || '核心拒绝请求。', response.status, requestId, detail);
    }
    return { data, etag: response.headers.get('etag'), requestId };
  }
}
