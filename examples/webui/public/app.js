import {runtimeConfig} from './runtime-config.js';
import {ApiClient} from './api.js';
import {OAuthSession} from './oauth.js';
import {BridgeHost,validateContribution,sameContribution} from './bridge.js';

const $ = selector => document.querySelector(selector);
const node = (tag, props = {}, ...children) => {
  const result = document.createElement(tag);
  for (const [name, value] of Object.entries(props)) {
    if (name.startsWith('on')) result.addEventListener(name.slice(2), value);
    else if (name === 'class') result.className = value;
    else if (name === 'text') result.textContent = value;
    else if (value !== undefined && value !== false) result.setAttribute(name, value === true ? '' : String(value));
  }
  result.append(...children.filter(value => value !== undefined && value !== null));
  return result;
};
const button = (text, action, props = {}) => node('button', {type: 'button', onclick: action, ...props}, text);

// One stroke-based 24x24 icon set shared by the Dock, launcher and pinned
// entries. Icons are built as SVG DOM nodes (no innerHTML) so the strict
// script-src 'self' CSP keeps protecting the shell.
const SVG_NS = 'http://www.w3.org/2000/svg';
const ICONS = {
  overview: [{tag:'rect',x:3.5,y:4.5,width:17,height:15,rx:1.8},{tag:'path',d:'M3.5 9.5h17M9.5 9.5v10'}],
  plugins: [{tag:'rect',x:4,y:4,width:7,height:7,rx:1.6},{tag:'rect',x:13,y:4,width:7,height:7,rx:1.6},{tag:'rect',x:4,y:13,width:7,height:7,rx:1.6},{tag:'rect',x:13,y:13,width:7,height:7,rx:1.6}],
  skills: [{tag:'path',d:'M13 3 6 13h5l-1 8 8-11h-5l0-7Z'}],
  accounts: [{tag:'circle',cx:12,cy:8.4,r:3.2},{tag:'path',d:'M5.2 20c.6-3.4 3.4-5.4 6.8-5.4s6.2 2 6.8 5.4'}],
  resources: [{tag:'path',d:'M12 3.4 20 7.8 12 12.2 4 7.8 12 3.4Z'},{tag:'path',d:'M4 12l8 4.4 8-4.4'},{tag:'path',d:'M4 16.2l8 4.4 8-4.4'}],
  clients: [{tag:'rect',x:3.5,y:5,width:17,height:10.5,rx:1.8},{tag:'path',d:'M9 19.5h6M12 15.5v4'}],
  contributions: [{tag:'rect',x:3.5,y:4.5,width:17,height:15,rx:1.8},{tag:'path',d:'M9.5 4.5v15'}],
  tasks: [{tag:'path',d:'M4 7h9M4 12h9M4 17h5.5'},{tag:'path',d:'M17.4 16.4l1.7 1.7 3-3.6'}],
  settings: [{tag:'path',d:'M4 7h4M12 7h8'},{tag:'circle',cx:10,cy:7,r:2},{tag:'path',d:'M4 12h9M17 12h3'},{tag:'circle',cx:15,cy:12,r:2},{tag:'path',d:'M4 17h2M10 17h10'},{tag:'circle',cx:8,cy:17,r:2}],
  restore: [{tag:'path',d:'M12 19V6M6.6 11.4 12 6l5.4 5.4'}],
  launcher: [{tag:'path',d:'M6 6h.01M12 6h.01M18 6h.01M6 12h.01M12 12h.01M18 12h.01M6 18h.01M12 18h.01M18 18h.01'}],
};
function icon(name) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  for (const [key, value] of Object.entries({viewBox:'0 0 24 24', fill:'none', stroke:'currentColor', 'stroke-width':'1.7', 'stroke-linecap':'round', 'stroke-linejoin':'round', 'aria-hidden':'true', focusable:'false', class:'app-glyph'})) svg.setAttribute(key, value);
  for (const shape of ICONS[name] || ICONS.plugins) {
    const element = document.createElementNS(SVG_NS, shape.tag);
    for (const [key, value] of Object.entries(shape)) if (key !== 'tag') element.setAttribute(key, value);
    svg.append(element);
  }
  return svg;
}
const appIcon = name => node('span', {class:'app-icon', 'aria-hidden':'true'}, icon(name));
const windows = new Map();
const widgetViews = new Map();
const widgetIntents = new Map();
const widgetPinned = new Map();
const dockPinned = new Map();
let launcherItems = [];
let launcherCursor = null;
let launcherLoading = false;
let launcherError = null;
let launcherEpoch = 0;
let layer = 10;
let accountId = null;
let preferences = null;
let preferenceEtag = null;
let toastTimer;
let sessionEpoch=0;
const oauth = new OAuthSession(runtimeConfig);
const api = new ApiClient(runtimeConfig, oauth);
const defaults = () => ({theme: {mode: 'system', reduce_motion: false, reduce_transparency: false}, dock: {position: 'bottom', auto_hide: false, pinned: []}, widgets: [], restore_windows: true});
const baseTokens = {
  light: {accent:'#4F7CFF', desktop:'#E9EEF7', surface:'#FFFFFF', text:'#18202C', muted_text:'#526074', border:'#CBD5E1', danger:'#B42318', radius_px:12, blur_px:16, panel_opacity:0.92, font:'system'},
  dark: {accent:'#80A7FF', desktop:'#121826', surface:'#1F2937', text:'#F3F4F6', muted_text:'#B4C0D0', border:'#475569', danger:'#FF8A80', radius_px:12, blur_px:16, panel_opacity:0.92, font:'system'},
};
let preview = defaults();
const mediaDark = matchMedia('(prefers-color-scheme: dark)');
const mediaMotion = matchMedia('(prefers-reduced-motion: reduce)');

function toast(message) {
  $('#toast').textContent = message;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { $('#toast').textContent = ''; }, 8000);
}
function errorDetail(error) {
  // Core HTTP/RPC responses may contain request data or upstream diagnostics in
  // error.message; keep toast feedback redacted to stable codes + fixed copy.
  const status = error?.status ?? error?.http_status;
  const code = typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(error.code) ? error.code : null;
  if (error?.name === 'AbortError' || error?.code === 'CANCELED') {
    return `${code || 'CANCELED'} · 操作未确认取消，请保留原请求键。`;
  }
  if (status === 401) return '登录已失效 · 请重新进入内核可信登录页面。';
  if (status === 403) return `${code || 'PERMISSION_DENIED'} · 当前授权来源不允许此操作。`;
  if ([404, 501, 503].includes(status)) return `${code || 'UNAVAILABLE'} · 接口、资源或依赖尚不可用。`;
  const isLocalApiValidation = error?.name === 'ApiError' && !error?.detail && (
    (status === 0 && code === 'INVALID_ARGUMENT') || (status === 428 && code === 'PRECONDITION_REQUIRED')
  );
  const isServerOrTransport = error?.name === 'ApiError'
    ? !isLocalApiValidation
    : (typeof status === 'number' && status >= 400) || Boolean(error?.detail);
  if (isServerOrTransport) {
    if (status === 0 || status >= 500 || code === 'CONNECTION_FAILED' || code === 'DEADLINE_EXCEEDED') {
      return `${code || 'NETWORK_ERROR'} · 连接中断；副作用结果可能未知，请保留原请求键。`;
    }
    return `${code || 'REQUEST_REJECTED'} · 核心拒绝此请求。`;
  }
  if (typeof error?.message === 'string' && error.message) {
    return code ? `${code} · ${error.message}` : error.message;
  }
  return code || '操作未完成。';
}
function toastError(error, prefix = '') {
  const message = errorDetail(error);
  toast(prefix ? `${prefix}${message}` : message);
}
function state(kind, title, message = '') {
  return node('div', {class:'state', 'data-kind':kind, role:kind === 'loading' ? 'status' : 'note'}, node('h3', {}, title), node('p', {}, message));
}
function failure(error) {
  // Core error bodies may contain request data or upstream diagnostics.
  // Standard window failure states keep only a stable machine code and a
  // fixed explanation for server errors, while displaying safe local validation messages.
  const status = error?.status ?? error?.http_status;
  const code = typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(error.code) ? error.code : null;
  if (error?.name === 'AbortError' || error?.code === 'CANCELED') {
    return state('unavailable', '等待已停止', '关闭或刷新视图不会回滚已经接受的操作。请使用原请求键核实结果。');
  }
  if (status === 401) return state('denied', '登录已失效', '请重新进入内核可信登录页面。');
  if (status === 403) return state('denied', '无权限', `${code || 'PERMISSION_DENIED'} · 当前授权来源不允许此操作。`);
  if ([404, 501, 503].includes(status)) return state('unavailable', '当前不可用', `${code || 'UNAVAILABLE'} · 接口、资源或依赖尚不可用。`);
  // ApiClient uses status 0 for both local validation and transport failures.
  const transportFailure = status === 0 && error?.name === 'ApiError'
    && (code === 'CONNECTION_FAILED' || code === 'DEADLINE_EXCEEDED');
  const redactMessage = status >= 500 || transportFailure;
  const fallback = '连接中断；副作用结果可能未知，请保留原请求键。';
  const message = (!redactMessage && typeof error?.message === 'string' && error.message) ? error.message : fallback;
  return state('error', '请求失败', `${code || 'NETWORK_ERROR'} · ${message}`);
}
function raw(value) { return node('pre', {class:'result'}, JSON.stringify(value, null, 2)); }
function rows(value) { return Array.isArray(value?.items) ? value.items : Array.isArray(value) ? value : []; }
function revision(value) { return value?.revision ? `"rev-${value.revision}"` : undefined; }
function permittedContent(win) {
  if (oauth.loggedIn) return true;
  win.content.replaceChildren(state('denied', '登录后继续', '授权由内核可信页面完成。本页面不会读取平台密码或内核登录 Cookie。'), button('前往可信登录', login, {class:'primary'}));
  return false;
}
async function request(operation, options = {}) {
  const epoch=sessionEpoch;
  try {
    const result = await api.invoke(operation, options);
    if(epoch!==sessionEpoch)throw new Error('登录来源已经改变；旧请求结果不再显示。');
    $('#connection').textContent = '已连接核心';
    return result;
  } catch (error) {
    // ApiClient invalidates only the exact rejected access token. A late 401
    // from an old request must not destroy a newer explicit login.
    if ((error?.status ?? error?.http_status) === 401 && !oauth.loggedIn) clearPrivateViews();
    // A logout or credential invalidation may have cleared the private UI
    // while this request was in flight. Do not overwrite the new session's
    // connection state with the outcome of that earlier request.
    if (epoch === sessionEpoch) $('#connection').textContent = (error?.status ?? error?.http_status) === 403 ? '当前请求无权限' : '请求未完成';
    throw error;
  }
}
function layoutKey() { return accountId ? `xelab:windows:${runtimeConfig.core_origin}:${runtimeConfig.client_id}:${accountId}` : null; }
function saveLayout() {
  const key = layoutKey();
  if (!key || !preview.restore_windows) return;
  const layout = [...windows.values()].filter(win => win.restoreRef || !win.ephemeral).map(win => ({app:win.restoreRef?'contribution':win.app.id,...(win.restoreRef?{contribution:win.restoreRef}:{}),rect:win.rect,minimized:win.minimized,maximized:win.maximized}));
  try { localStorage.setItem(key, JSON.stringify(layout)); } catch { /* Storage is optional. */ }
}
function clearPrivateViews() {
  sessionEpoch++;
  const key = layoutKey();
  accountId = null;
  if (key) localStorage.removeItem(key);
  for (const win of [...windows.values()]) closeWindow(win, false);
  for (const widget of widgetViews.values()) widget.dispose();
  widgetViews.clear();widgetIntents.clear();widgetPinned.clear();dockPinned.clear();
  launcherEpoch++;launcherItems=[];launcherCursor=null;launcherLoading=false;launcherError=null;
  preferences = null;
  preferenceEtag = null;
  preview = defaults();
  applyTheme();
  $('#widgets').replaceChildren();
  $('#connection').textContent = '未连接';
  $('#welcome').hidden = false;
  $('#login').textContent = '登录';
  renderLauncher();
}
oauth.addEventListener('logout', clearPrivateViews);
oauth.addEventListener('credentialchange',()=>{
  for(const win of windows.values()){
    win.bridge?.close('unavailable');
    if(win.app.id.startsWith('editor-')){
      win.credentialChanged=true;win.controller?.abort();
      for(const submit of win.content.querySelectorAll('[data-intent-submit]'))submit.disabled=true;
      win.content.prepend(state('unavailable','原请求已锁定','访问凭证已轮换；请先核实原 Call/Operation，保留原请求键，再明确创建新的意图。'));
    }
  }
  for(const widget of widgetViews.values())widget.bridge?.close('unavailable');
  toast('访问凭证已轮换；旧插件页面通道已关闭，请先核实未完成的原调用，再明确打开。');
});
async function login() {
  try { await oauth.startLogin(); } catch (error) { toastError(error, '无法进入可信登录：'); }
}
const hexLuminance = value => {
  const match = /^#([a-f0-9]{2})([a-f0-9]{2})([a-f0-9]{2})$/i.exec(value || '');
  if (!match) return null;
  const linear = part => {
    const channel = parseInt(part, 16) / 255;
    return channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * linear(match[1]) + 0.7152 * linear(match[2]) + 0.0722 * linear(match[3]);
};
function applyTheme() {
  const mode = preview.theme.mode;
  const resolved = mode === 'system' ? (mediaDark.matches ? 'dark' : 'light') : mode;
  const tokens = resolved === 'custom' ? preview.theme.custom_tokens : baseTokens[resolved];
  if (!tokens) return;
  for (const name of ['accent','desktop','surface','text','muted_text','border','danger']) {
    if (/^#[a-f0-9]{6}$/i.test(tokens[name])) document.documentElement.style.setProperty(`--${name.replaceAll('_','-')}`, tokens[name]);
  }
  document.documentElement.style.setProperty('--radius', `${Math.max(0, Math.min(24, tokens.radius_px))}px`);
  document.documentElement.style.setProperty('--blur', `${Math.max(0, Math.min(32, tokens.blur_px))}px`);
  document.documentElement.style.setProperty('--opacity', String(preview.theme.reduce_transparency ? 1 : Math.max(.6, Math.min(1, tokens.panel_opacity))));
  document.documentElement.style.setProperty('--font', ({system:'system-ui,sans-serif',sans:'Arial,sans-serif',serif:'Georgia,serif',mono:'ui-monospace,monospace'})[tokens.font] || 'system-ui,sans-serif');
  const customDark = resolved === 'custom'
    ? (hexLuminance(tokens.desktop) ?? hexLuminance(tokens.surface) ?? 1) < 0.4
    : false;
  document.documentElement.style.colorScheme = resolved === 'dark' || customDark ? 'dark' : 'light';
  document.documentElement.dataset.theme = mode;
  document.documentElement.classList.toggle('reduced-motion', preview.theme.reduce_motion || mediaMotion.matches);
  document.documentElement.classList.toggle('reduced-transparency', preview.theme.reduce_transparency);
  $('#dock').dataset.position = preview.dock.position;
  $('#dock').dataset.autoHide = String(preview.dock.auto_hide);
  renderDock();
  for(const win of windows.values())win.bridge?.themeChanged();
  for(const widget of widgetViews.values())widget.bridge?.themeChanged();
}
function bridgeTheme(){
  const mode=preview.theme.mode==='system'?(mediaDark.matches?'dark':'light'):preview.theme.mode;
  return{theme_tokens:structuredClone(mode==='custom'?preview.theme.custom_tokens:baseTokens[mode]),reduce_motion:preview.theme.reduce_motion||mediaMotion.matches,reduce_transparency:preview.theme.reduce_transparency};
}
mediaDark.addEventListener('change', applyTheme);
mediaMotion.addEventListener('change', applyTheme);

function workspace() { return {width: $('#windows').clientWidth, height: $('#windows').clientHeight}; }
function fit(win) {
  const area = workspace();
  if (win.maximized) Object.assign(win.element.style, {left:'6px', top:'6px', width:`${Math.max(300, area.width-12)}px`, height:`${Math.max(240, area.height-12)}px`});
  else {
    const r = win.rect;
    const limits=win.contribution?.spec.window;
    r.width = Math.min(area.width-12, Math.max(limits?.min_width||300, Math.min(r.width,limits?.max_width||4096)));
    r.height = Math.min(area.height-12, Math.max(limits?.min_height||240, Math.min(r.height,limits?.max_height||2160)));
    r.x = Math.max(6, Math.min(r.x, Math.max(6, area.width-r.width-6)));
    r.y = Math.max(6, Math.min(r.y, Math.max(6, area.height-r.height-6)));
    Object.assign(win.element.style, {left:`${r.x}px`, top:`${r.y}px`, width:`${r.width}px`, height:`${r.height}px`});
  }
  win.bridge?.viewportChanged();
}
function focus(win) {
  if (matchMedia('(max-width:650px)').matches) for (const other of windows.values()) {other.element.hidden = other !== win;other.bridge?.setVisible(other===win&&document.visibilityState==='visible');}
  win.minimized = false;
  win.bridge?.setVisible(document.visibilityState==='visible');
  win.element.hidden = false;
  if (++layer > 1000) { layer = 10; for (const other of windows.values()) other.element.style.zIndex = String(layer++); }
  for (const other of windows.values()) other.element.dataset.focused = String(other === win);
  win.element.style.zIndex = String(layer);
  $('#active-app').textContent = win.app.title;
  renderDock();
  saveLayout();
}
function closeWindow(win, persist = true) {
  // Keep keyboard focus inside the desktop instead of dropping it on the document body.
  const hadFocus = win.element.contains(document.activeElement);
  win.controller?.abort();
  win.dispose?.();
  win.element.remove();
  windows.delete(win.id);
  renderDock();
  const next = [...windows.values()].filter(value => !value.minimized).at(-1);
  if (next) focus(next); else $('#active-app').textContent = '桌面';
  if (hadFocus) {
    const target = next
      ? next.element.querySelector('.window-title')
      : $('#dock').querySelector(`[data-app-id="${win.app.id}"]`);
    (target || $('#desktop')).focus();
  }
  if (persist) saveLayout();
}
function pointerMove(win, handle, resize) {
  handle.addEventListener('pointerdown', event => {
    if (event.button !== 0 || (!resize && event.target.closest('button'))) return;
    if (win.maximized || matchMedia('(max-width:650px)').matches||(resize&&win.contribution?.spec.window.resizable===false)) return;
    focus(win);
    const start = {x:event.clientX,y:event.clientY,...win.rect};
    const pointerX = event.clientX, pointerY = event.clientY;
    handle.setPointerCapture(event.pointerId);
    const move = next => {
      if (resize) Object.assign(win.rect, {width:start.width+next.clientX-pointerX,height:start.height+next.clientY-pointerY});
      else Object.assign(win.rect, {x:start.x+next.clientX-pointerX,y:start.y+next.clientY-pointerY});
      fit(win);
    };
    const done = () => { handle.removeEventListener('pointermove',move); handle.removeEventListener('pointerup',done); handle.removeEventListener('pointercancel',done); saveLayout(); };
    handle.addEventListener('pointermove',move);
    handle.addEventListener('pointerup',done);
    handle.addEventListener('pointercancel',done);
  });
}
function openWindow(app, options = {}) {
  if (windows.size >= (runtimeConfig.max_open_windows || 16)) { toast('已达打开窗口上限，请先关闭一个窗口。'); return null; }
  const id = crypto.randomUUID();
  const heading = node('h2', {id:`title-${id}`}, app.title);
  const titlebar = node('header', {class:'window-title', tabindex:0, 'aria-label':`${app.title}窗口。Alt加方向键移动，Alt加Shift加方向键调整大小。`});
  const content = node('div', {class:'window-content'});
  const element = node('section', {class:'window', role:'dialog', 'aria-labelledby':`title-${id}`, 'data-view-id':id, 'data-app':app.id}, titlebar, content);
  const win = {id, app, content, element, rect:options.rect || {x:40+windows.size*24,y:24+windows.size*20,width:680,height:520}, minimized:false,maximized:Boolean(options.maximized),ephemeral:Boolean(options.ephemeral),restoreRef:options.restoreRef,controller:null};
  const minimize = () => {
    // Hand focus to the Dock button instead of leaving it on a now-hidden control.
    const hadFocus = element.contains(document.activeElement);
    win.minimized = true; element.hidden = true; win.bridge?.setVisible(false);
    renderDock();
    if (hadFocus) $('#dock').querySelector(`[data-app-id="${app.id}"]`)?.focus();
    saveLayout();
  };
  const maximize = () => { win.maximized = !win.maximized; fit(win); saveLayout(); };
  titlebar.append(node('div', {class:'window-controls'}, button('×',()=>closeWindow(win),{'aria-label':`关闭${app.title}`}),button('−',minimize,{'aria-label':`最小化${app.title}`}),button('□',maximize,{'aria-label':`最大化或恢复${app.title}`})),heading);
  titlebar.addEventListener('dblclick', event => { if (!event.target.closest('button')) maximize(); });
  titlebar.addEventListener('keydown', event => {
    if (!event.altKey || !['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(event.key)) return;
    if(event.shiftKey&&win.contribution?.spec.window.resizable===false)return;
    event.preventDefault();
    const horizontal = ['ArrowLeft','ArrowRight'].includes(event.key), delta = ['ArrowLeft','ArrowUp'].includes(event.key) ? -20 : 20;
    const key = event.shiftKey ? (horizontal ? 'width' : 'height') : (horizontal ? 'x' : 'y');
    win.rect[key] += delta;
    fit(win);
    saveLayout();
  });
  const resize = button('', ()=>{}, {class:'window-resize', 'aria-label':`调整${app.title}大小`});
  resize.addEventListener('keydown', event => {
    if (!event.key.startsWith('Arrow')) return;
    if(win.contribution?.spec.window.resizable===false)return;
    event.preventDefault();
    win.rect[['ArrowLeft','ArrowRight'].includes(event.key) ? 'width' : 'height'] += ['ArrowLeft','ArrowUp'].includes(event.key) ? -20 : 20;
    fit(win); saveLayout();
  });
  element.append(resize);
  element.addEventListener('pointerdown',()=>focus(win));
  element.addEventListener('focusin',()=> { if (element.dataset.focused !== 'true') focus(win); });
  windows.set(id,win);
  $('#windows').append(element);
  pointerMove(win,titlebar,false);
  pointerMove(win,resize,true);
  fit(win);
  focus(win);
  loadApp(win);
  titlebar.focus();
  if(options.minimized)minimize();
  return win;
}
window.addEventListener('resize',()=> {
  const narrow=matchMedia('(max-width:650px)').matches;
  const available=[...windows.values()].filter(win=>!win.minimized);
  // A minimized window can still retain data-focused; fall back to the
  // topmost remaining window without changing focus or its saved layout.
  const active=available.find(win=>win.element.dataset.focused==='true')
    || available.reduce((top,win)=>!top||Number(win.element.style.zIndex)>Number(top.element.style.zIndex)?win:top,null);
  if(narrow&&(!active||active.element.dataset.focused!=='true')){
    for(const win of windows.values())win.element.dataset.focused=String(win===active);
    $('#active-app').textContent=active?.app.title||'桌面';
  }
  for(const win of windows.values()){
    fit(win);
    win.element.hidden=win.minimized||(narrow&&win!==active);
    win.bridge?.setVisible(!win.element.hidden&&document.visibilityState==='visible');
  }
});

// Built-in windows share one navigation row: a truncating title, a grouped
// action set and the one refresh control for that window. Grouping the
// actions keeps them together when they wrap and gives assistive technology
// a named boundary; card-level .toolbar rows keep their existing layout.
function toolbar(win, title, ...actions) {
  return node('div',{class:'toolbar window-toolbar','data-window-toolbar':''},
    node('h2',{class:'window-toolbar-title',title},title),
    node('div',{class:'window-toolbar-actions',role:'group','aria-label':`${title}操作`},
      ...actions,
      button('刷新',()=>loadApp(win),{'aria-label':`刷新${title}`})));
}
async function loadApp(win) {
  win.controller?.abort();
  win.controller = new AbortController();
  if (!['settings','tasks'].includes(win.app.id) && !permittedContent(win)) return;
  win.content.replaceChildren(state('loading','正在读取核心…'));
  try { await win.app.render(win); } catch (error) { if (windows.has(win.id)) win.content.replaceChildren(toolbar(win,win.app.title),failure(error)); }
}
function editor(title, operation, {params={}, initial={}, etag, body=true, note='操作将以当前用户和本客户端授权提交；服务端会重新鉴权。'} = {}) {
  return openWindow({id:`editor-${operation}`,title,render:async win => {
    const key = crypto.randomUUID();
    const input = node('textarea',{'aria-label':'请求 JSON',spellcheck:false},JSON.stringify(initial,null,2));
    const outcome = node('div',{'aria-live':'polite'});
    const submit = button('提交',async()=> {
      if(win.credentialChanged){toast('原请求来源已改变，请先核实结果。');return;}
      let value;
      try { value = body ? JSON.parse(input.value) : undefined; } catch { outcome.replaceChildren(state('error','JSON 格式错误','请修正后再提交。'));return; }
      submit.disabled = true;
      outcome.replaceChildren(state('loading','请求中…','请保留原请求键，网络失败不等于操作回滚。'));
      try {
        const result = await request(operation,{params,body:value,etag,idempotencyKey:key,signal:win.controller.signal});
        outcome.replaceChildren(node('p',{},'核心已返回以下实际结果；异步 Operation 尚需检查其终态。'),raw(result.data));
      } catch (error) { outcome.replaceChildren(failure(error)); }
      finally { submit.disabled = Boolean(win.credentialChanged); }
    },{class:'primary','data-intent-submit':true});
    win.content.replaceChildren(node('div',{class:'editor-form'},node('p',{class:'muted'},note),...(body?[node('label',{},'请求 JSON',input)]:[]),node('p',{class:'code'},`幂等键：${key}`),submit,outcome));
  }},{ephemeral:true});
}
function details(title, data) { return openWindow({id:'details',title,render:async win=>win.content.replaceChildren(raw(data))},{ephemeral:true}); }
async function listSection(win, {title,operation,params={},query={},actions=[],renderItem}) {
  const result = await request(operation,{params,query:{limit:50,...query},signal:win.controller.signal});
  const list = node('div',{class:'list'});
  const append = data => { for (const item of rows(data)) list.append(renderItem(item)); };
  append(result.data);
  const pageError = node('div', {class:'list-page-error'});
  const more = button('加载下一页',async()=> {
    more.disabled = true;
    try {
      const next = await request(operation,{params,query:{limit:50,...query,cursor:more.dataset.cursor},signal:win.controller.signal});
      if (!more.isConnected) return;
      append(next.data);
      pageError.replaceChildren();
      more.dataset.cursor = next.data.next_cursor || '';
      more.hidden = !next.data.next_cursor;
    } catch(error) {
      if (!more.isConnected) return;
      pageError.replaceChildren(failure(error));
    } finally {
      if (more.isConnected) more.disabled = false;
    }
  }, {'aria-label':`加载下一页${title}`, hidden:!result.data.next_cursor});
  more.dataset.cursor = result.data.next_cursor || '';
  if (!list.childElementCount) list.append(state('empty','暂无可见项目','当前账户授权范围内没有记录。'));
  win.content.replaceChildren(toolbar(win,title,...actions),list,pageError,more);
}

async function plugins(win) {
  const [installations,deployments] = await Promise.all([
    request('listInstallations',{query:{limit:200},signal:win.controller.signal}),
    request('listDeployments',{query:{limit:200},signal:win.controller.signal}),
  ]);
  const install = button('安装签名镜像',()=>editor('安装插件','installPlugin',{initial:{image:'',publisher_id:'',signature:''}}));
  const deploy = button('创建部署',()=>editor('创建部署','createDeployment',{initial:{installation_id:'',display_name:'',enabled:false,replicas:1,limits:{cpu_millis:500,memory_bytes:536870912,ephemeral_bytes:268435456,pids:128},config:{},volume_ids:[]}}));
  const list = node('div',{class:'list'});
  for (const item of rows(deployments.data)) {
    const spec = item.spec;
    const actions = node('div',{class:'toolbar'},
      button('详情',()=>details('部署详情',item)),
      button(spec.enabled?'停用':'启用',()=>editor('改变部署启停','setDeploymentEnabled',{params:{deployment_id:item.id},initial:{enabled:!spec.enabled},etag:revision(item),note:'停用会撤销新路由。核心 API 与 CLI 仍可独立使用。'})),
      button('审批',()=>editor('审批插件版本','approvePlugin',{params:{deployment_id:item.id},initial:{rules:[],egress:[]},etag:revision(item)})),
      button('配置',()=>editor('修改部署','updateDeployment',{params:{deployment_id:item.id},initial:{spec},etag:revision(item),note:'先停用部署并等待实例排空，才能修改配置。安装制品和卷绑定不可在此替换；升级、卷变更或启用应使用各自的工作流。'})));
    list.append(node('article',{class:'card'},node('h3',{},spec.display_name),node('p',{},node('span',{class:'badge'},item.phase),` · ${spec.enabled?'已启用':'已停用'}`),node('p',{class:'code'},item.id),node('p',{},(item.conditions||[]).join(' · ')),actions));
  }
  for (const item of rows(installations.data)) list.append(node('article',{class:'card'},node('h3',{},item.plugin_id),node('p',{},`版本 ${item.version} · ${item.state}`),node('p',{class:'code'},item.image_digest),node('div',{class:'toolbar'},button('安装详情',()=>details('固定安装制品',item)))));
  if (!list.childElementCount) list.append(state('empty','暂无可见插件','安装签名制品后，创建关闭状态的部署并审批。'));
  win.content.replaceChildren(toolbar(win,'插件中心',install,deploy),list);
  if (installations.data.next_cursor || deployments.data.next_cursor) win.content.append(state('unavailable','还有更多项目','本视图最多显示每类200项。请使用 CLI 分页或缩小核心授权范围。'));
}
async function skills(win) {
  await listSection(win,{title:'Skill 浏览器',operation:'listSkills',actions:[button('注册固定 Skill',()=>editor('注册 Skill','registerSkill',{initial:{installation_id:'',definition:{},enabled:false}}))],renderItem:item=>node('article',{class:'card'},node('h3',{},item.definition.name),node('p',{},`${item.definition.version} · ${item.availability}`),node('p',{class:'code'},`UUID ${item.id}`),node('p',{class:'code'},item.definition_digest),node('p',{},(item.reason_codes||[]).join(' · ')),node('div',{class:'toolbar'},button('定义与输入 Schema',()=>details('不可变 Skill 定义',item)),button('调用测试',()=>editor('调用固定 Skill','invokeSkill',{params:{skill_id:item.id},initial:{input:{},idempotency_key:crypto.randomUUID()},note:`固定UUID ${item.id}；定义摘要 ${item.definition_digest}。输入须符合此版本Schema，权限仍由核心逐次校验。`})),button(item.enabled?'禁用':'启用',()=>editor('改变 Skill 状态','setSkillEnabled',{params:{skill_id:item.id},initial:{enabled:!item.enabled},etag:revision(item)})),button('归档',()=>editor('归档 Skill','archiveSkill',{params:{skill_id:item.id},etag:revision(item),body:false,note:'归档是不可逆的逻辑停用；历史调用仍保留。'}))))});
}
async function accounts(win) {
  const signal = win.controller.signal;
  const accountInput = node('input',{placeholder:'账户 UUID','aria-label':'账户 UUID',value:accountId||''});
  const display = node('div');
  let sequence = 0;
  const inspect = async id => {
    const current = ++sequence;
    display.replaceChildren(state('loading','读取账户及授权来源…'));
    try {
      const result = await request('getAccount',{params:{account_id:id},signal});
      if (current !== sequence || signal.aborted || !display.isConnected) return;
      display.replaceChildren(node('h3',{},`${result.data.display_name} · ${result.data.status}`),raw(result.data));
      const read = (title,operation) => button(title,async()=> { try { const data=await request(operation,{params:{account_id:id},signal});if (signal.aborted || !display.isConnected) return;details(title,data.data); } catch(error){ if (!signal.aborted && display.isConnected) toastError(error); } });
      display.append(node('div',{class:'toolbar'},read('有效权限与阻断祖先','getEffectivePermissions'),read('授权组来源','listGrants'),read('资源配额','getQuota'),button('API Key 元数据',()=>openWindow({id:`api-keys:${id}`,title:'API Key 元数据',render:keys=>apiKeys(keys,id)},{ephemeral:true})),button('子账户',async()=> { try { const data=await request('listAccounts',{query:{parent_id:id,limit:200},signal});if (signal.aborted || !display.isConnected) return;details('子账户与继承模式',data.data); }catch(error){ if (!signal.aborted && display.isConnected) toastError(error); } })));
    } catch(error) {
      if (current !== sequence || signal.aborted || !display.isConnected) return;
      display.replaceChildren(failure(error));
    }
  };
  win.content.replaceChildren(toolbar(win,'账户与权限'),node('p',{class:'muted'},'账户身份、祖先限制与凭证来源均以核心返回为准；WebUI 不收集平台密码。'),node('div',{class:'inline-field'},accountInput,button('读取',()=>inspect(accountInput.value.trim()))),display);
  if (accountId) await inspect(accountId); else display.replaceChildren(state('unavailable','当前账户详情尚不可用','当前委托未获准读取本人会话元数据。可输入已知账户 UUID，在现有授权内查询。'));
}
function keyMetadata(value) {
  // Only the read model's scalar metadata is displayed, even if a broken
  // backend accidentally attaches a one-time issuance field to its response.
  const result={};
  for(const field of ['id','revision','owner_id','name','prefix','status','issuer_credential_id','created_at','updated_at','last_used_at']) {
    const item=value[field];
    if(item===null||typeof item==='string'||Number.isSafeInteger(item))result[field]=item;
  }
  if(['selected','all_snapshot','follow_parent'].includes(value.inheritance?.mode))result.inheritance={mode:value.inheritance.mode};
  return result;
}
async function apiKeys(win,account) {
  const signal = win.controller.signal;
  await listSection(win,{title:'API Key 元数据',operation:'listApiKeys',params:{account_id:account},renderItem:item=>node('article',{class:'card'},node('h3',{},item.name),node('p',{},`${item.status} · ${item.prefix}`),raw(keyMetadata(item)),button('读取密钥元数据',async()=>{try{const result=await request('getApiKey',{params:{credential_id:item.id},signal});if(signal.aborted||!windows.has(win.id))return;details('API Key 元数据详情',keyMetadata(result.data));}catch(error){if(!signal.aborted&&windows.has(win.id))toastError(error);}}))});
}
async function resources(win) {
  const result = await request('getNode',{signal:win.controller.signal});
  win.content.replaceChildren(toolbar(win,'资源与系统状态'),node('p',{class:'muted'},'以下为核心实际返回的宿主状态与资源账本。内核4C16G预留不借给界面。'),raw(result.data));
}
async function clients(win) {
  const signal = win.controller.signal;
  await listSection(win,{title:'UI 客户端',operation:'listClients',actions:[button('注册公共客户端',()=>editor('注册 UI Client','createClient',{initial:{name:'',plugin_id:'',redirect_uris:[],allowed_origins:[],maximum_rules:[]}})),button('默认界面',async()=> { try { const result=await request('getDefaultUi',{signal});if(signal.aborted||!windows.has(win.id))return;editor('设置默认界面','setDefaultUi',{initial:{deployment_id:result.data.deployment_id??null},etag:result.etag||revision(result.data),note:'设为 null 关闭根路径跳转。修改前请保留部署说明中的内核 CLI 恢复命令。'}); }catch(error){if(!signal.aborted&&windows.has(win.id))toastError(error);} })],renderItem:item=>node('article',{class:'card'},node('h3',{},item.spec.name),node('p',{},item.status),node('p',{class:'code'},item.client_id),node('p',{},item.spec.allowed_origins.join(', ')),node('div',{class:'toolbar'},button('详情',()=>details('Client 信任范围',item)),button('修改',()=>editor('修改 Client','updateClient',{params:{client_id:item.id},initial:item.spec,etag:revision(item),note:'修改将作废旧授权请求与本Client现有凭证族。禁用Client不能通过修改复活。'})),button('禁用',()=>editor('禁用 Client','disableClient',{params:{client_id:item.id},body:false,etag:revision(item),note:'禁用会撤销本Client凭证族；保留核心 API/CLI 恢复路径。'}))))});
}
async function openContribution(value){
  if(!accountId||!oauth.loggedIn){toast('打开页面需要当前账户的 session.read 权限以固定桥接主体。');return null;}
  const current=await request('getUiContribution',{params:{deployment_id:value.deployment_id,contribution_id:value.spec.id}});
  const fixed=validateContribution(current.data,{parentOrigin:location.origin,coreOrigin:runtimeConfig.core_origin});
  if(!sameContribution(value,fixed))throw new Error('贡献或权限已改变，请刷新后明确打开当前版本。');
  return openCheckedContribution(fixed);
}
// Internal bridge targets have already passed a fresh core read and all pinned
// identity checks. Actual iframe mounting still revalidates the target below.
async function openCheckedContribution(fixed,sourceCurrent=()=>true){
  const epoch=sessionEpoch,subject=accountId;
  const current=()=>epoch===sessionEpoch&&oauth.loggedIn&&accountId===subject&&Boolean(subject)&&sourceCurrent();
  if(!current())throw new Error('登录来源或页面通道已改变，请重新打开页面。');
  if(fixed.spec.kind!=='window')throw new Error('该贡献不是窗口。');
  const reference=await contributionReference(fixed);
  if(!current())throw new Error('登录来源或页面通道已改变，请重新打开页面。');
  return openWindow({id:`plugin:${fixed.deployment_id}:${fixed.spec.id}`,title:`${fixed.spec.title} · ${fixed.plugin_id}`,render:win=>displayContribution(win,fixed,reference,false)},{ephemeral:true,restoreRef:reference});
}
async function contributionReference(fixed) {
  const bindings=fixed.bindings.map(binding=>({alias:binding.alias,skill_id:binding.skill_id,definition_digest:binding.definition_digest,modes:[...binding.modes].sort()})).sort((left,right)=>left.alias<right.alias?-1:left.alias>right.alias?1:0);
  const digest=[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(bindings))))].map(value=>value.toString(16).padStart(2,'0')).join('');
  return{deployment_id:fixed.deployment_id,contribution_id:fixed.spec.id,installation_id:fixed.installation_id,manifest_digest:fixed.manifest_digest,contribution_digest:fixed.contribution_digest,bindings_digest:`sha256:${digest}`};
}
function validContributionReference(value){
  const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i,digest=/^sha256:[a-f0-9]{64}$/;
  return value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===6&&uuid.test(value.deployment_id)&&uuid.test(value.installation_id)&&/^[a-z][a-z0-9_-]{0,63}$/.test(value.contribution_id)&&['manifest_digest','contribution_digest','bindings_digest'].every(field=>digest.test(value[field]));
}
async function displayContribution(win,fixed,reference,keepRect){
  if(!windows.has(win.id)||win.controller.signal.aborted)return;
  win.dispose?.();win.restoreRef=reference;win.contribution=fixed;
  win.app.id=`plugin:${fixed.deployment_id}:${fixed.spec.id}`;win.app.title=`${fixed.spec.title} · ${fixed.plugin_id}`;
  win.element.dataset.app=win.app.id;win.element.querySelector('.window-title h2').textContent=win.app.title;
  for(const[index,control]of [...win.element.querySelectorAll('.window-controls button')].entries())control.setAttribute('aria-label',`${['关闭','最小化','最大化或恢复'][index]}${win.app.title}`);
  const resize=win.element.querySelector('.window-resize');resize.hidden=!fixed.spec.window.resizable;resize.setAttribute('aria-label',`调整${win.app.title}大小`);
  if(!keepRect){win.rect.width=fixed.spec.window.width;win.rect.height=fixed.spec.window.height;}
  fit(win);renderDock();saveLayout();
  await mountContribution(win.content,fixed,win);
}
function restoreContribution(item){
  const reference=item.contribution;
  if(!validContributionReference(reference))return;
  openWindow({id:`plugin:${reference.deployment_id}:${reference.contribution_id}`,title:`插件窗口 · ${reference.contribution_id}`,render:win=>restoreContributionView(win,reference)},{...item,ephemeral:true,restoreRef:reference});
}
async function restoreContributionView(win,reference){
  const read=async()=>{
    const result=await request('getUiContribution',{params:{deployment_id:reference.deployment_id,contribution_id:reference.contribution_id},signal:win.controller.signal});
    const fixed=validateContribution(result.data,{parentOrigin:location.origin,coreOrigin:runtimeConfig.core_origin});
    if(fixed.spec.kind!=='window')throw new Error('保存的贡献不再是窗口。');
    return{fixed,current:await contributionReference(fixed)};
  };
  try{
    const{fixed,current}=await read();
    if(JSON.stringify(current)!==JSON.stringify(reference))throw new Error('安装、贡献版本或获准白名单已改变，尚未恢复插件页面。');
    await displayContribution(win,fixed,current,true);
  }catch(error){
    if(!windows.has(win.id)||win.controller.signal.aborted)return;
    const outcome=node('div');
    const retry=button('明确重新发现并加载',async()=>{
      retry.disabled=true;outcome.replaceChildren(state('loading','重新核对当前贡献…'));
      try{const{fixed,current}=await read();await displayContribution(win,fixed,current,true);}
      catch(next){outcome.replaceChildren(failure(next));retry.disabled=false;}
    });
    win.content.replaceChildren(state('unavailable','插件窗口等待确认','原布局已保留；没有恢复旧调用、输入或结果，也未自动接受新版白名单。'),failure(error),retry,outcome);
  }
}
async function mountContribution(container,fixed,owner){
  const frame=node('iframe',{class:'bridge-frame'}),status=node('p',{class:'contribution-note'},'正在核对固定贡献并握手…');
  container.replaceChildren(node('p',{class:'contribution-note',title:`安装 ${fixed.installation_id}；清单 ${fixed.manifest_digest}`},`固定贡献 ${fixed.contribution_digest.slice(0,23)}…`),status,frame);
  const bridge=new BridgeHost({iframe:frame,api,contribution:fixed,subjectId:accountId,isCurrent:subject=>oauth.loggedIn&&accountId===subject,coreOrigin:runtimeConfig.core_origin,viewId:owner.id,theme:bridgeTheme,
    openWindow:async (contribution,sourceCurrent)=>(await openCheckedContribution(contribution,sourceCurrent))?.id,
    onState:(phase,reason)=>{if(phase==='active')status.hidden=true;else if(phase==='closed'){owner.bridge=null;owner.closed=true;clearInterval(owner.refreshTimer);container.replaceChildren(state('unavailable','页面通道已关闭',`${reason} · 请重新发现并明确打开当前版本。`));}},
  });
  owner.bridge=bridge;
  const observer=new ResizeObserver(()=>bridge.viewportChanged());observer.observe(frame);
  owner.dispose=()=>{observer.disconnect();clearInterval(owner.refreshTimer);bridge.close('close');};
  await bridge.mount();
  bridge.setVisible(document.visibilityState==='visible'&&!owner.minimized&&!owner.element.hidden);
}
async function preferenceMutation(intentId,mutate){
  let intent=widgetIntents.get(intentId);
  if(!intent){const current=await request('getMyUiPreferences');const body=structuredClone(current.data.spec);mutate(body);intent={body,etag:current.etag||revision(current.data),key:crypto.randomUUID()};widgetIntents.set(intentId,intent);}
  const saved=await request('setMyUiPreferences',{body:intent.body,etag:intent.etag,idempotencyKey:intent.key});
  widgetIntents.delete(intentId);preferences=saved.data;preferenceEtag=saved.etag||revision(saved.data);preview=structuredClone(saved.data.spec);applyTheme();await renderWidgets();await resolveDockPins();renderLauncher();
}
async function widgetMutation(intentId,mutate){return preferenceMutation(intentId,body=>mutate(body.widgets));}
const contributionKey=value=>({deployment_id:value.deployment_id,contribution_id:value.spec.id});
const pinId=key=>`${key.deployment_id}:${key.contribution_id}`;
const isPinned=value=>preview.dock.pinned.some(key=>pinId(key)===pinId(contributionKey(value)));
async function togglePin(value) {
  const key=contributionKey(value),identity=pinId(key),remove=isPinned(value);
  if(!remove){
    if(!accountId||!oauth.loggedIn)throw new Error('固定贡献需要当前账户和核心偏好。');
    const current=await request('getUiContribution',{params:key});
    const fixed=validateContribution(current.data,{parentOrigin:location.origin,coreOrigin:runtimeConfig.core_origin});
    if(fixed.spec.kind!=='window'||!sameContribution(value,fixed))throw new Error('固定贡献已改变，请重新发现后明确选择。');
    dockPinned.set(identity,{fixed});
  }
  await preferenceMutation(`${remove?'unpin':'pin'}:${identity}`,body=>{
    if(remove)body.dock.pinned=body.dock.pinned.filter(item=>pinId(item)!==identity);
    else if(!body.dock.pinned.some(item=>pinId(item)===identity)){
      if(body.dock.pinned.length>=64)throw new Error('Dock 最多固定64个贡献。');
      body.dock.pinned.push(key);
    }
  });
  if(remove)dockPinned.delete(identity);
}
function pinControl(value) {
  const control=button(isPinned(value)?'取消固定到 Dock':'固定到 Dock',async()=>{
    control.disabled=true;
    try{await togglePin(value);control.textContent=isPinned(value)?'取消固定到 Dock':'固定到 Dock';control.setAttribute('aria-label',`${isPinned(value)?'取消固定':'固定'} ${value.spec.title}`);}
    catch(error){toastError(error);}finally{control.disabled=false;}
  },{disabled:value.availability!=='ready'&&!isPinned(value),'aria-label':`${isPinned(value)?'取消固定':'固定'} ${value.spec.title}`});
  return control;
}
async function resolveDockPins() {
  const epoch=sessionEpoch;
  const wanted=preview.dock.pinned;
  for(const id of dockPinned.keys())if(!wanted.some(key=>pinId(key)===id))dockPinned.delete(id);
  const pending=wanted.filter(key=>!dockPinned.has(pinId(key)));
  for(const key of pending)dockPinned.set(pinId(key),{loading:true});
  renderDock();
  let index=0;
  await Promise.all(Array.from({length:Math.min(4,pending.length)},async()=>{
    while(index<pending.length){
      const key=pending[index++];let entry;
      try{
        const current=await request('getUiContribution',{params:key});
        const fixed=validateContribution(current.data,{parentOrigin:location.origin,coreOrigin:runtimeConfig.core_origin});
        if(fixed.spec.kind!=='window')throw new Error('固定记录不是窗口贡献。');
        entry={fixed};
      }catch(error){entry={error};}
      if(epoch!==sessionEpoch)return;
      if(preview.dock.pinned.some(item=>pinId(item)===pinId(key)))dockPinned.set(pinId(key),entry);
      renderDock();
    }
  }));
}
async function addWidget(value){
  if(!accountId||!oauth.loggedIn){toast('组件需要读取当前账户身份与核心偏好。');return;}
  const current=await request('getUiContribution',{params:{deployment_id:value.deployment_id,contribution_id:value.spec.id}});
  const fixed=validateContribution(current.data,{parentOrigin:location.origin,coreOrigin:runtimeConfig.core_origin});
  if(!sameContribution(value,fixed))throw new Error('贡献或权限已改变，请刷新后重新选择。');
  if(fixed.spec.kind!=='widget')throw new Error('该贡献不是组件。');
  await widgetMutation(`add:${fixed.deployment_id}:${fixed.spec.id}`,items=>{
    if(items.length>=32)throw new Error('布局最多32项。');
    const id=crypto.randomUUID(),placement={instance_id:id,contribution:contributionKey(fixed),column:0,row:0,columns:fixed.spec.widget.columns,rows:fixed.spec.widget.rows};
    while(items.some(other=>overlaps(placement,other))&&placement.row<255)placement.row++;
    if(items.some(other=>overlaps(placement,other)))throw new Error('当前网格没有可用位置，请先调整组件布局。');
    widgetPinned.set(id,fixed);items.push(placement);
  });
}
function overlaps(left,right){return left.column<right.column+right.columns&&left.column+left.columns>right.column&&left.row<right.row+right.rows&&left.row+left.rows>right.row;}
function editWidget(placement,fixed) {
  openWindow({id:`widget-layout:${placement.instance_id}`,title:`组件布局 · ${fixed.spec.title}`,render:async win=>{
    const result=await request('getMyUiPreferences',{signal:win.controller.signal});
    let original=result.data.spec.widgets.find(item=>item.instance_id===placement.instance_id);
    if(!original||pinId(original.contribution)!==pinId(contributionKey(fixed)))throw new Error('组件已移除或布局来源已改变。');
    const form=node('form',{class:'settings-grid'}),inputs={},outcome=node('div',{'aria-live':'polite'});
    for(const[field,label,min,max]of [['column','列坐标',0,255],['row','行坐标',0,255],['columns','宽度格数',fixed.spec.widget.min_columns,fixed.spec.widget.max_columns],['rows','高度格数',fixed.spec.widget.min_rows,fixed.spec.widget.max_rows]]){
      inputs[field]=node('input',{type:'number',step:1,min,max,value:original[field],'aria-label':label,required:true});
      form.append(node('label',{},`${label}（${min}–${max}）`,inputs[field]));
    }
    const save=button('保存组件布局',()=>{});save.type='submit';
    form.addEventListener('submit',async event=>{
      event.preventDefault();const wanted={};
      for(const[field,input]of Object.entries(inputs)){
        const value=input.valueAsNumber;
        if(!Number.isInteger(value)||value<Number(input.min)||value>Number(input.max)){outcome.replaceChildren(state('error','布局超出范围','坐标必须为0–255整数，尺寸必须符合该固定贡献的签名范围。'));return;}
        wanted[field]=value;
      }
      save.disabled=true;outcome.replaceChildren(state('loading','正在保存布局…'));
      try{
        const current=await request('getUiContribution',{params:contributionKey(fixed),signal:win.controller.signal});
        const verified=validateContribution(current.data,{parentOrigin:location.origin,coreOrigin:runtimeConfig.core_origin});
        if(!sameContribution(fixed,verified))throw new Error('固定贡献或权限已改变，请重新发现后调整布局。');
        await widgetMutation(`layout:${placement.instance_id}:${JSON.stringify(original)}:${JSON.stringify(wanted)}`,items=>{
          const item=items.find(item=>item.instance_id===placement.instance_id);
          if(JSON.stringify(item)!==JSON.stringify(original))throw new Error('组件布局已改变，请关闭此窗口后重新读取。');
          const updated={...item,...wanted};
          if(items.some(other=>other.instance_id!==item.instance_id&&overlaps(updated,other)))throw new Error('此位置与其他组件重叠，请选择空闲网格。');
          Object.assign(item,wanted);
        });
        original=structuredClone(preview.widgets.find(item=>item.instance_id===placement.instance_id));
        outcome.replaceChildren(state('ready','组件布局已保存','位置和尺寸来自核心当前用户偏好。'));
      }catch(error){outcome.replaceChildren(failure(error));}finally{save.disabled=false;}
    });
    form.append(node('p',{class:'muted'},'每格96逻辑像素，间距12；小屏幕按顺序展示，保留此处保存的网格布局。'),save,outcome);
    win.content.replaceChildren(form);
  }},{ephemeral:true});
}
async function renderWidgets(){
  if(!oauth.loggedIn||!accountId)return;
  const epoch=sessionEpoch;
  const placements=preview.widgets||[],ids=new Set(placements.map(item=>item.instance_id));
  for(const[id,widget]of widgetViews)if(!ids.has(id)){widget.dispose();widget.element.remove();widgetViews.delete(id);widgetPinned.delete(id);}
  for(const placement of placements){
    if(epoch!==sessionEpoch)return;
    const key=JSON.stringify(placement.contribution);let widget=widgetViews.get(placement.instance_id);
    if(widget&&widget.key!==key){widget.dispose();widget.element.remove();widgetViews.delete(placement.instance_id);widget=null;}
    if(widget){widget.element.style.gridColumn=`${placement.column+1}/span ${placement.columns}`;widget.element.style.gridRow=`${placement.row+1}/span ${placement.rows}`;continue;}
    const card=node('article',{class:'card widget-card'}),body=node('div',{class:'widget-content'});
    const remove=button('移除',async()=>{try{await widgetMutation(`remove:${placement.instance_id}`,items=>{const index=items.findIndex(item=>item.instance_id===placement.instance_id);if(index>=0)items.splice(index,1);});}catch(error){toastError(error);}});
    card.append(node('div',{class:'toolbar'},node('h3',{},'桌面组件'),remove),body);card.style.gridColumn=`${placement.column+1}/span ${placement.columns}`;card.style.gridRow=`${placement.row+1}/span ${placement.rows}`;
    $('#widgets').append(card);
    const controller=new AbortController();
    widget={id:crypto.randomUUID(),key,element:card,dispose:()=>controller.abort(),bridge:null,visible:true};widgetViews.set(placement.instance_id,widget);
    const active=()=>epoch===sessionEpoch&&widgetViews.get(placement.instance_id)===widget&&card.isConnected;
    const retry=button('明确重新加载',async()=>{widget.dispose();card.remove();widgetViews.delete(placement.instance_id);widgetPinned.delete(placement.instance_id);await renderWidgets();});
    card.querySelector('.toolbar').append(retry);
    if([...widgetViews.values()].filter(item=>item.bridge).length>=(runtimeConfig.max_active_widgets??8)){body.replaceChildren(state('unavailable','等待激活','活动组件已达部署上限；移除其他活动组件后明确重新加载。'));continue;}
    body.replaceChildren(state('loading','读取获准组件…'));
    try{
      const result=await request('getUiContribution',{params:placement.contribution,signal:controller.signal});
      if(!active()){widget.dispose();if(epoch!==sessionEpoch)return;continue;}
      const fixed=validateContribution(result.data,{parentOrigin:location.origin,coreOrigin:runtimeConfig.core_origin});
      if(fixed.spec.kind!=='widget')throw new Error('布局引用不是获准组件。');
      if(widgetPinned.has(placement.instance_id)&&!sameContribution(widgetPinned.get(placement.instance_id),fixed))throw new Error('固定贡献发生变化，请明确重新加载。');
      widgetPinned.set(placement.instance_id,fixed);
      card.querySelector('h3').textContent=fixed.spec.title;
      card.querySelector('.toolbar').append(button('布局',()=>editWidget(preview.widgets.find(item=>item.instance_id===placement.instance_id)||placement,fixed),{'aria-label':`调整组件布局 ${fixed.spec.title}`}));
      await mountContribution(body,fixed,widget);
      if(!active()){widget.dispose();if(epoch!==sessionEpoch)return;continue;}
      const visible=new IntersectionObserver(entries=>{for(const entry of entries)setWidgetVisible(widget,entry.isIntersecting&&document.visibilityState==='visible');});visible.observe(card);
      const cleanup=widget.dispose;widget.dispose=()=>{controller.abort();visible.disconnect();cleanup();};
      card.querySelector('.toolbar').append(button('刷新',()=>widget.bridge?.refresh().catch(()=>{})));
      if((fixed.spec.refresh_interval_seconds??0)>0){
        try{
          await verifyPureWidget(fixed,controller.signal);
          if(!active()){widget.dispose();if(epoch!==sessionEpoch)return;continue;}
          widget.refreshSeconds=Math.max(fixed.spec.refresh_interval_seconds,runtimeConfig.widget_min_refresh_seconds||30);setWidgetVisible(widget,widget.visible);
        }catch{
          if(!active()){widget.dispose();if(epoch!==sessionEpoch)return;continue;}
          card.append(node('p',{class:'contribution-note'},'当前来源不足以证明纯只读目标；周期刷新未开启。'));
        }
      }
    }catch(error){
      if(!active()){widget.dispose();if(epoch!==sessionEpoch)return;continue;}
      body.replaceChildren(failure(error));
    }
  }
}
async function verifyPureWidget(fixed,signal){
  const bindings=fixed.bindings.filter(binding=>binding.modes.includes('call'));
  if(!bindings.length)throw new Error('缺少已批准读取。');
  const installed=await request('getInstallation',{params:{installation_id:fixed.installation_id},signal});
  for(const binding of bindings){
    const {data:skill}=await request('getSkill',{params:{skill_id:binding.skill_id},signal});
    const target=skill.definition.target;
    if(skill.id!==binding.skill_id||skill.definition_digest!==binding.definition_digest||skill.installation_id!==fixed.installation_id||!skill.enabled||skill.availability!=='ready'||target.kind!=='capability')throw new Error('读取绑定无法固定。');
    const capability=installed.data.manifest.capabilities.find(item=>item.contract.name===target.contract.name&&item.contract.version===target.contract.version&&item.contract.schema_digest===target.contract.schema_digest);
    if(capability?.side_effect!=='none')throw new Error('目标不是纯读取。');
  }
}
function setWidgetVisible(widget,visible){const resumed=visible&&!widget.visible;widget.visible=visible;widget.bridge?.setVisible(visible);clearInterval(widget.refreshTimer);if(visible&&widget.refreshSeconds&&widget.bridge){if(resumed)widget.bridge.refresh().catch(()=>{});widget.refreshTimer=setInterval(()=>widget.bridge?.refresh().catch(()=>{}),widget.refreshSeconds*1000);}}
document.addEventListener('visibilitychange',()=>{for(const win of windows.values())win.bridge?.setVisible(!win.minimized&&!win.element.hidden&&document.visibilityState==='visible');for(const widget of widgetViews.values())setWidgetVisible(widget,document.visibilityState==='visible'&&widget.element.getBoundingClientRect().bottom>0&&widget.element.getBoundingClientRect().top<innerHeight);});
async function contributions(win) {
  await listSection(win,{title:'插件页面',operation:'listUiContributions',renderItem:item=>node('article',{class:'card'},node('h3',{},item.spec.title||item.spec.id),node('p',{},`${item.spec.kind} · ${item.availability}`),node('p',{class:'code'},item.contribution_digest),node('p',{},item.reason_codes.join(' · ')),node('div',{class:'toolbar'},button('固定贡献详情',()=>details('已批准 UI 贡献',item)),button(item.spec.kind==='widget'?'添加桌面组件':'打开隔离窗口',async()=>{try{if(item.spec.kind==='widget')await addWidget(item);else await openContribution(item);}catch(error){toastError(error);}},{disabled:item.availability!=='ready'}),item.spec.kind==='window'?pinControl(item):null))});
}
async function settings(win) {
  const signal = win.controller.signal;
  if (oauth.loggedIn) {
    try {
      const result=await request('getMyUiPreferences',{signal});
      if(signal.aborted||!windows.has(win.id))return;
      preferences=result.data;preferenceEtag=result.etag||revision(result.data);preview=structuredClone(result.data.spec);applyTheme();await resolveDockPins();
      if(signal.aborted||!windows.has(win.id))return;
    } catch(error) {
      if(signal.aborted||!windows.has(win.id)||!oauth.loggedIn)return;
      toast(`核心偏好暂不可用（主题更改将仅为预览）：${errorDetail(error)}`);
    }
  }
  const notice = node('p',{class:'theme-preview-note'},preferences?'已读取当前用户核心偏好。':'核心偏好未加载；以下仅为本页预览，未持久保存。');
  const form = node('div',{class:'settings-grid'});
  const mode = node('select',{'aria-label':'主题模式'},...['system','light','dark','custom'].map(value=>node('option',{value},({system:'跟随系统',light:'明亮',dark:'深色',custom:'自定义'})[value])));
  mode.value=preview.theme.mode;
  const colors=node('div',{class:'theme-colors'});
  const mark = () => { notice.textContent='当前为未保存预览。';applyTheme(); };
  function customFields() {
    colors.replaceChildren();colors.hidden=preview.theme.mode!=='custom';
    if (colors.hidden) return;
    preview.theme.custom_tokens ||= structuredClone(baseTokens[mediaDark.matches?'dark':'light']);
    for (const name of ['accent','desktop','surface','text','muted_text','border','danger']) {
      const input=node('input',{type:'color',value:preview.theme.custom_tokens[name],'aria-label':`自定义 ${name}`});
      input.addEventListener('input',()=> { preview.theme.custom_tokens[name]=input.value;mark(); });
      colors.append(node('label',{},name,input));
    }
  }
  mode.addEventListener('change',()=> { preview.theme.mode=mode.value;if(mode.value!=='custom')delete preview.theme.custom_tokens;customFields();mark(); });
  const check = (title,key) => { const input=node('input',{type:'checkbox','aria-label':title});input.checked=preview.theme[key];input.addEventListener('change',()=> { preview.theme[key]=input.checked;mark(); });return node('label',{class:'check'},input,title); };
  const dock=node('select',{'aria-label':'Dock 位置'},...['bottom','left','right'].map(value=>node('option',{value},({bottom:'底部',left:'左侧',right:'右侧'})[value])));dock.value=preview.dock.position;dock.addEventListener('change',()=>{preview.dock.position=dock.value;mark();});
  const autoHide=node('input',{type:'checkbox','aria-label':'自动隐藏 Dock'});autoHide.checked=preview.dock.auto_hide;autoHide.addEventListener('change',()=>{preview.dock.auto_hide=autoHide.checked;mark();});
  let saveIntent = {key:crypto.randomUUID(), body:null};
  const save=button('保存到当前账户',async()=> {
    if (!preferences || !preferenceEtag) {toast('需要先登录并成功读取核心偏好及其ETag。');return;}
    const canonicalIntent=JSON.stringify(preview);
    if(saveIntent.body!==null&&saveIntent.body!==canonicalIntent)saveIntent={key:crypto.randomUUID(),body:null};
    saveIntent.body=canonicalIntent;
    save.disabled=true;
    try {const result=await request('setMyUiPreferences',{body:preview,etag:preferenceEtag,idempotencyKey:saveIntent.key,signal:win.controller.signal});preferences=result.data;preferenceEtag=result.etag||revision(result.data);preview=structuredClone(result.data.spec);applyTheme();notice.textContent='已保存到核心，重新登录后仍可读取。';saveIntent={key:crypto.randomUUID(),body:null};}
    catch(error){notice.replaceChildren(failure(error));}finally{save.disabled=false;}
  },{class:'primary'});
  form.append(node('label',{},'主题',mode),colors,check('减少动画','reduce_motion'),check('减少透明度','reduce_transparency'),node('label',{},'Dock 位置',dock),node('label',{class:'check'},autoHide,'自动隐藏 Dock'),notice,node('div',{class:'toolbar'},save,button('恢复已保存偏好',()=> {preview=preferences?structuredClone(preferences.spec):defaults();applyTheme();loadApp(win);})),node('p',{class:'code'},`核心：${runtimeConfig.core_origin}\n公共 Client：${runtimeConfig.client_id}`));
  customFields();
  win.content.replaceChildren(toolbar(win,'桌面设置'),form);
}
async function unavailable(win) {win.content.replaceChildren(toolbar(win,win.app.title),state('unavailable','当前版本尚不可用','Batch、Workflow、微插件与知识库属于后续执行系统。此桌面未伪造任务、数据或成功响应。'));}
async function tasks(win) {
  const input=node('input',{'aria-label':'Operation UUID',placeholder:'已接受操作的 UUID'});
  const result=node('div');
  win.content.replaceChildren(toolbar(win,'任务与能力'),node('p',{},'查询核心已经接受的 Operation；结果以其持久终态为准。'),node('div',{class:'inline-field'},input,button('查询 Operation',async()=>{result.replaceChildren(state('loading','查询中…'));try{const response=await request('getOperation',{params:{operation_id:input.value.trim()},signal:win.controller.signal});result.replaceChildren(raw(response.data));}catch(error){result.replaceChildren(failure(error));}})),result,state('unavailable','Batch / Workflow / 微插件 / 知识库尚不可用','未安装或实现的后续执行系统没有可展示的运行结果。'));
}
// Read-only overview (issue #14). Each section calls exactly one existing
// public API and renders only whitelisted non-sensitive scalars: plugin
// config, host runtime identifiers, credentials and raw response objects
// never reach the DOM. Sections load, fail and refresh independently; no
// trends, global totals or automatic polling are invented.
const overviewNodeFields = [
  ['host_cpu_millis','宿主 CPU（毫核）'],
  ['host_memory_bytes','宿主内存（字节）'],
  ['plugin_cpu_pool_millis','插件 CPU 池（毫核）'],
  ['plugin_memory_pool_bytes','插件内存池（字节）'],
  ['reserved_cpu_millis','已预留 CPU（毫核）'],
  ['reserved_memory_bytes','已预留内存（字节）'],
  ['admission_enabled','准入控制'],
  ['updated_at','核心更新时间'],
];
const overviewNodeConfigFields = [
  ['profile','运行 Profile'],
  ['kernel_cpu_millis','内核预留 CPU（毫核）'],
  ['kernel_memory_bytes','内核预留内存（字节）'],
  ['system_cpu_millis','系统预留 CPU（毫核）'],
  ['system_memory_bytes','系统预留内存（字节）'],
];
function overviewScalars(value, fields) {
  const entries = [];
  for (const [key, label] of fields) {
    const item = value?.[key];
    if (item === null || typeof item === 'string' || typeof item === 'boolean' || Number.isSafeInteger(item)) entries.push([label, item]);
  }
  return entries;
}
function overviewText(value) {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'boolean') return value ? '是' : '否';
  return String(value);
}
function overviewFacts(entries) {
  const list = node('dl', {class:'overview-facts'});
  for (const [label, value] of entries) list.append(node('dt', {}, label), node('dd', {}, overviewText(value)));
  return list;
}
function overviewNode(data) {
  const entries = overviewScalars(data, overviewNodeFields);
  const config = overviewScalars(data?.config, overviewNodeConfigFields);
  if (!entries.length && !config.length) return state('empty', '没有可显示的节点字段', '核心返回中没有本视图白名单内的非敏感字段。');
  return node('div', {class:'overview-node'},
    ...(entries.length ? [overviewFacts(entries)] : []),
    ...(config.length ? [node('h4', {}, '内核与系统预留'), overviewFacts(config)] : []));
}
function overviewBadge(value, fallback) { return node('span', {class:'badge'}, typeof value === 'string' && value ? value : fallback); }
function overviewFailure(error) {
  // Core error bodies may contain request data or upstream diagnostics. The
  // overview keeps only a stable machine code and a fixed explanation instead
  // of echoing the server-provided message into the DOM.
  const status = error?.status ?? error?.http_status;
  const code = typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(error.code) ? error.code : null;
  if (error?.name === 'AbortError' || error?.code === 'CANCELED') {
    return state('unavailable', '等待已停止', '刷新或关闭视图不会回滚已经接受的操作。');
  }
  if (status === 401) return state('denied', '登录已失效', '请重新进入内核可信登录页面。');
  if (status === 403) return state('denied', '无权限', `${code || 'PERMISSION_DENIED'} · 当前授权来源不允许此操作。`);
  if ([404, 501, 503].includes(status)) return state('unavailable', '当前不可用', `${code || 'UNAVAILABLE'} · 接口、资源或依赖尚不可用。`);
  return state('error', '请求失败', `${code || 'NETWORK_ERROR'} · 连接中断；副作用结果可能未知，请保留原请求键。`);
}
function overviewDeployment(item) {
  const spec = item?.spec ?? {};
  const conditions = (Array.isArray(item?.conditions) ? item.conditions : []).filter(value => typeof value === 'string');
  return node('article', {class:'card overview-item'},
    node('h3', {}, typeof spec.display_name === 'string' && spec.display_name ? spec.display_name : '未命名部署'),
    node('p', {}, overviewBadge(item?.phase, 'phase 未知'), ` · ${spec.enabled === true ? '已启用' : spec.enabled === false ? '已停用' : '启停未知'}`, Number.isSafeInteger(spec.replicas) ? ` · 副本 ${spec.replicas}` : ''),
    ...(conditions.length ? [node('p', {}, conditions.join(' · '))] : []),
    ...(typeof item?.id === 'string' ? [node('p', {class:'code'}, `UUID ${item.id}`)] : []),
    ...(typeof item?.updated_at === 'string' ? [node('p', {class:'muted'}, `核心更新 ${item.updated_at}`)] : []));
}
function overviewInstance(item) {
  return node('article', {class:'card overview-item'},
    node('h3', {}, '实例'),
    node('p', {}, overviewBadge(item?.phase, 'phase 未知'), ' ', overviewBadge(item?.health, 'health 未知')),
    ...(Number.isSafeInteger(item?.restart_count) ? [node('p', {}, `重启次数 ${item.restart_count}`)] : []),
    ...(typeof item?.last_heartbeat_at === 'string' ? [node('p', {}, `最近心跳 ${item.last_heartbeat_at}`)] : []),
    ...(typeof item?.deployment_id === 'string' ? [node('p', {class:'code'}, `部署 ${item.deployment_id}`)] : []),
    ...(typeof item?.id === 'string' ? [node('p', {class:'code'}, `UUID ${item.id}`)] : []));
}
async function overviewPage(win, {operation, title, renderItem, emptyMessage}) {
  const result = await request(operation, {query:{limit:50}, signal:win.controller.signal});
  const list = node('div', {class:'list'});
  for (const item of rows(result.data)) list.append(renderItem(item));
  if (!list.childElementCount) list.append(state('empty', '暂无可见项目', emptyMessage));
  const pageError = node('div', {class:'overview-page-error'});
  const hint = node('p', {class:'overview-page-hint muted'}, result.data.next_cursor ? '仅显示当前已取到的项目；还有更多可加载。' : '');
  const more = button('加载下一页', async () => {
    more.disabled = true;
    try {
      const next = await request(operation, {query:{limit:50, cursor:more.dataset.cursor}, signal:win.controller.signal});
      if (!more.isConnected) return;
      for (const item of rows(next.data)) list.append(renderItem(item));
      pageError.replaceChildren();
      more.dataset.cursor = next.data.next_cursor || '';
      more.hidden = !next.data.next_cursor;
      hint.textContent = next.data.next_cursor ? '仅显示当前已取到的项目；还有更多可加载。' : '已加载全部可见项目。';
    } catch (error) {
      if (!more.isConnected) return;
      pageError.replaceChildren(overviewFailure(error));
      hint.textContent = '下一页读取失败；已加载内容保持不变。';
    } finally { if (more.isConnected) more.disabled = false; }
  }, {'aria-label':`加载下一页${title}`, hidden:!result.data.next_cursor});
  more.dataset.cursor = result.data.next_cursor || '';
  return node('div', {}, list, pageError, more, hint);
}
function overviewSection(win, {key, title, source, load}) {
  const headingId = `overview-${key}-${win.id}`;
  const readAt = node('span', {class:'overview-read-at'}, '尚未读取');
  const body = node('div', {class:'overview-body', 'aria-live':'polite'});
  const section = node('section', {class:'overview-section', 'data-section':key, 'aria-labelledby':headingId},
    node('header', {class:'overview-head'},
      node('h3', {id:headingId}, title),
      node('span', {class:'overview-source'}, `来源 ${source}`),
      readAt,
      button('刷新', () => { run(); }, {'aria-label':`刷新${title}`, class:'overview-refresh'})),
    body);
  const refresh = section.querySelector('.overview-refresh');
  let sequence = 0;
  async function run() {
    const current = ++sequence;
    refresh.disabled = true;
    body.replaceChildren(state('loading', '正在读取核心…'));
    try {
      const rendered = await load();
      if (current !== sequence || !section.isConnected) return;
      readAt.textContent = `读取于 ${new Intl.DateTimeFormat('zh-CN', {hour:'2-digit', minute:'2-digit', second:'2-digit'}).format(new Date())}`;
      body.replaceChildren(rendered);
    } catch (error) {
      if (current !== sequence || !section.isConnected) return;
      readAt.textContent = '读取失败';
      body.replaceChildren(overviewFailure(error));
    } finally {
      if (current === sequence && section.isConnected) refresh.disabled = false;
    }
  }
  return {section, run};
}
async function overview(win) {
  const sections = [
    overviewSection(win, {key:'node', title:'节点资源', source:'getNode',
      load:async () => overviewNode((await request('getNode', {signal:win.controller.signal})).data)}),
    overviewSection(win, {key:'deployments', title:'部署', source:'listDeployments',
      load:() => overviewPage(win, {operation:'listDeployments', title:'部署', renderItem:overviewDeployment, emptyMessage:'当前账户授权范围内没有可见部署。'})}),
    overviewSection(win, {key:'instances', title:'实例', source:'listInstances',
      load:() => overviewPage(win, {operation:'listInstances', title:'实例', renderItem:overviewInstance, emptyMessage:'当前账户授权范围内没有可见实例。'})}),
  ];
  win.content.replaceChildren(
    toolbar(win, '总览'),
    node('p', {class:'muted overview-note'}, '只读总览：仅展示当前账户已取到的公开 API 数据；各区域独立刷新。无历史趋势、全局总数或实时监控。'),
    node('div', {class:'overview-grid'}, ...sections.map(entry => entry.section)));
  await Promise.all(sections.map(entry => entry.run()));
}
const apps = [
  {id:'overview',title:'总览',icon:'overview',render:overview},
  {id:'plugins',title:'插件中心',icon:'plugins',render:plugins},
  {id:'skills',title:'Skill',icon:'skills',render:skills},
  {id:'accounts',title:'账户与权限',icon:'accounts',render:accounts},
  {id:'resources',title:'系统状态',icon:'resources',render:resources},
  {id:'clients',title:'UI 客户端',icon:'clients',render:clients},
  {id:'contributions',title:'插件页面',icon:'contributions',render:contributions},
  {id:'tasks',title:'任务与知识库',icon:'tasks',render:tasks},
  {id:'settings',title:'设置',icon:'settings',render:settings},
];
function renderDock() {
  const dock=$('#dock');dock.replaceChildren();
  for (const app of apps.filter(value=>!['clients','contributions','tasks'].includes(value.id))) {
    const active=[...windows.values()].filter(win=>win.app.id===app.id);
    dock.append(button('',()=> { const minimized=active.find(win=>win.minimized||win.element.hidden);if(minimized){focus(minimized);minimized.element.querySelector('.window-title')?.focus();}else openWindow(app); },{'aria-label':`打开${app.title}`,'data-app-id':app.id,'data-active':String(active.length>0)}));
    dock.lastChild.append(appIcon(app.icon),node('span',{},app.title));
  }
  for(const key of preview.dock.pinned){
    const entry=dockPinned.get(pinId(key)),fixed=entry?.fixed,title=fixed?.spec.title||key.contribution_id;
    const group=node('div',{class:'dock-pin'});
    const active=[...windows.values()].some(win=>win.app.id===`plugin:${key.deployment_id}:${key.contribution_id}`);
    const pinned=button('',async()=>{
      try{await openContribution(fixed);}catch(error){dockPinned.set(pinId(key),{fixed,error});renderDock();toastError(error);}
    },{'aria-label':`打开固定贡献 ${title}`,disabled:!fixed||Boolean(entry.error),'data-active':String(active),title:entry?.error?'贡献不可用；取消固定后重新发现。':`固定部署 ${key.deployment_id}`});
    pinned.append(icon('contributions'),node('span',{},title));
    group.append(pinned);
    group.append(button('×',async()=>{try{await togglePin({deployment_id:key.deployment_id,spec:{id:key.contribution_id,title}});}catch(error){toastError(error);}},{'aria-label':`取消固定 ${title}`,class:'dock-unpin'}));
    dock.append(group);
  }
  for (const win of windows.values()) if(win.minimized) {
    const restore=button('',()=>{focus(win);win.element.querySelector('.window-title')?.focus();},{'aria-label':`恢复${win.app.title}`,class:'dock-restore'});
    restore.append(icon('restore'),node('span',{},win.app.title));
    dock.append(restore);
  }
  const launcher=button('',openLauncher,{'aria-label':'打开应用启动器'});
  launcher.append(appIcon('launcher'),node('span',{},'应用'));
  dock.append(launcher);
}
function renderLauncher() {
  const search=$('#app-search').value.trim().toLowerCase();
  $('#app-grid').replaceChildren(...apps.filter(app=>app.title.toLowerCase().includes(search)||app.id.includes(search)).map(app=>button('',()=>{$('#launcher').close();openWindow(app);},{'aria-label':`启动${app.title}`})));
  for (const [index,entry] of [...$('#app-grid').children].entries()) {
    const matching=apps.filter(app=>app.title.toLowerCase().includes(search)||app.id.includes(search))[index];
    entry.append(appIcon(matching.icon),node('span',{},matching.title));
  }
  for(const[ index,win]of[...windows.values()].entries())if(win.app.title.toLowerCase().includes(search))$('#app-grid').append(button(`↥ ${win.app.title}`,()=>{$('#launcher').close();focus(win);},{'aria-label':`聚焦窗口${index+1} ${win.app.title}`}));
  if(!oauth.loggedIn)return;
  const found=launcherItems.filter(item=>`${item.spec.title} ${item.spec.id} ${item.plugin_id}`.toLowerCase().includes(search));
  for(const item of found){
    const launch=button(item.spec.kind==='widget'?'添加桌面组件':'打开隔离窗口',async()=>{
      launch.disabled=true;
      try{if(item.spec.kind==='widget')await addWidget(item);else await openContribution(item);$('#launcher').close();}
      catch(error){toastError(error);}finally{launch.disabled=item.availability!=='ready';}
    },{disabled:item.availability!=='ready','aria-label':`启动贡献 ${item.spec.title}`});
    $('#app-grid').append(node('article',{class:'launcher-contribution card'},node('h3',{},item.spec.title),node('p',{},`${item.spec.kind} · ${item.availability}`),node('p',{class:'code'},`${item.plugin_id} · ${item.deployment_id}`),node('p',{},item.reason_codes.join(' · ')),launch,item.spec.kind==='window'?pinControl(item):null));
  }
  const status=node('div',{class:'launcher-status'});
  if(launcherLoading)status.append(state('loading','正在发现获准贡献…'));
  else if(launcherError)status.append(failure(launcherError),button('重新发现贡献',()=>loadLauncher(true)));
  else if(!found.length)status.append(state('empty','已加载贡献中没有匹配项','搜索只包含当前授权可见的贡献；可继续分页或重新发现。'));
  if(launcherCursor&&!launcherLoading)status.append(button('加载更多贡献',()=>loadLauncher(false)));
  $('#app-grid').append(status);
}
async function loadLauncher(reset) {
  if(!oauth.loggedIn)return;
  if(launcherLoading&&!reset)return;
  const epoch=reset?++launcherEpoch:launcherEpoch;
  if(reset){launcherItems=[];launcherCursor=null;}
  launcherLoading=true;launcherError=null;renderLauncher();
  try{
    const result=await request('listUiContributions',{query:{limit:50,...(!reset&&launcherCursor?{cursor:launcherCursor}:{})}});
    if(epoch!==launcherEpoch)return;
    for(const item of rows(result.data))if(!launcherItems.some(existing=>pinId(contributionKey(existing))===pinId(contributionKey(item))))launcherItems.push(item);
    launcherCursor=result.data.next_cursor||null;
  }catch(error){if(epoch===launcherEpoch)launcherError=error;}
  finally{if(epoch===launcherEpoch){launcherLoading=false;renderLauncher();}}
}
let launcherReturnFocus=null;
function openLauncher(){
  renderLauncher();
  launcherReturnFocus=document.activeElement instanceof HTMLElement?document.activeElement:null;
  $('#launcher').showModal();
  $('#app-search').focus();
  loadLauncher(true);
}
$('#launcher').addEventListener('close',()=>{
  // Restore after the UA finishes moving focus out of the closed dialog; a launch action
  // has already focused the new window, which must not be stolen back.
  setTimeout(()=>{
    const active=document.activeElement;
    if(active&&active!==document.body&&!$('#launcher').contains(active))return;
    const target=launcherReturnFocus&&document.contains(launcherReturnFocus)?launcherReturnFocus:$('#launcher-toggle');
    target.focus();
  },0);
});
$('#launcher-toggle').addEventListener('click',openLauncher);
$('#launcher-close').addEventListener('click',()=>$('#launcher').close());
$('#app-search').addEventListener('input',renderLauncher);
$('#theme-toggle').addEventListener('click',()=>openWindow(apps.find(app=>app.id==='settings')));
$('#welcome-login').addEventListener('click',login);
$('#login').addEventListener('click',()=> { if(oauth.loggedIn){oauth.logout();clearPrivateViews();toast('已退出本WebUI客户端；内核可信登录会话由内核独立管理。');}else login(); });
document.addEventListener('keydown',event=> {if(event.key==='Escape'&&$('#launcher').open)$('#launcher').close();});
function tick() {$('#clock').textContent=new Intl.DateTimeFormat('zh-CN',{hour:'2-digit',minute:'2-digit'}).format(new Date());}
tick();setInterval(tick,30000);
renderDock();renderLauncher();applyTheme();
async function boot() {
  try {
    if (location.pathname === '/ui/org.xelab.webui/callback') {
      await oauth.finishLogin(location.href);
      history.replaceState({},'', '/ui/org.xelab.webui/');
    }
    if (!oauth.loggedIn) return;
    $('#login').textContent='退出';$('#welcome').hidden=true;$('#connection').textContent='正在验证连接…';
    try {
      const sessions=await request('listSessions',{query:{limit:200}});
      const subjects=[...new Set(rows(sessions.data).filter(item=>item.status==='active').map(item=>item.account_id))];
      if(subjects.length===1) accountId=subjects[0];
    } catch { /* Authorization may intentionally exclude session metadata. */ }
    const key=layoutKey();
    // Read the previous session's layout before any further await. Interactive
    // windows opened while preferences load already save their own layout.
    let restored=[];
    try {const stored=key?JSON.parse(localStorage.getItem(key)||'[]'):[];if(Array.isArray(stored))restored=stored.slice(0,runtimeConfig.max_open_windows||16);}catch{/* Invalid optional local layout is discarded. */}
    try {const result=await request('getMyUiPreferences');preferences=result.data;preferenceEtag=result.etag||revision(result.data);preview=structuredClone(result.data.spec);applyTheme();await renderWidgets();await resolveDockPins();}catch{ /* Settings reports the unavailable dependency. */ }
    if(key&&key===layoutKey()&&preview.restore_windows&&windows.size===0) {
      try {for(const item of restored){if(!item?.rect||!['x','y','width','height'].every(key=>Number.isFinite(item.rect[key])))continue;if(item.app==='contribution')restoreContribution(item);else{const app=apps.find(candidate=>candidate.id===item.app);if(app)openWindow(app,item);}}}catch{/* Invalid optional local layout is discarded. */}
    }
  }catch(error){clearPrivateViews();const code=typeof error?.code==='string'&&/^[A-Z][A-Z0-9_]{0,63}$/.test(error.code)?error.code:null;toast(code?`登录未完成：${code}`:`登录未完成：${errorDetail(error)}`);}
}
boot();
