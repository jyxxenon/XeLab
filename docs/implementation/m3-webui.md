# M3 官方 WebUI、插件页面与整体测试

本页保留的4C16G容量要求及既有证据属于 `standard` profile；[compact 1C512MiB](compact-node.md) 有独立准入与整机验收，不复用本页容量结论。


> 2026-11-09 验收补记：M3 功能提交 #45/#46/#47 的精确完整与专项 CI 已全部通过。下文保留相应切片开发时的命令、历史状态和证据边界；当前验收表与精确 head/tree/CI 见 [当前验收记录](m3-acceptance-20261109.md)，最终集成与 main CI 见 [目标 #38](https://github.com/jyxxe/XeLab/issues/38)。历史“待验收”表述不得替代该最新记录，组件通过也不替代真实 OCI 或正式生产验收。
[实施目录](README.md) · [M3 进度](m3-progress.md) · [核心 OAuth/UI](m3-oauth-ui.md) · [WebUI 部署](../../examples/webui/DEPLOYMENT.md) · [独立 UI 插件](../../examples/ui-reference/README.md)

证据快照：2026-11-04 23:07 UTC。D/E 的执行代码和 F 的真实集成测试已存在，最终集成和新隐私修复门禁尚未完成；本快照不自动代表后续分支状态，最新状态见[目标 #38](https://github.com/jyxxe/XeLab/issues/38)。该时刻 main `e9ad62b83708e46569ca47f74413f6890950cdb5` 的 [CI 41860893005](https://github.com/jyxxe/XeLab/actions/runs/41860893005) 已成功，包含合并的 #39–44，尚不包含 #45–47。#46 的精确提交 `7249b969…` 已在 [CI 41922164310](https://github.com/jyxxe/XeLab/actions/runs/41922164310) 的 full 和 focus 两个 job 完成真实 F、53 项浏览器检查与11项 Core 检查，workspace/契约/lint全部通过；这不替代新隐私修复、依赖 PR 或最终 main 的完整门禁。
## 已实现路径

- `examples/webui/server.py`、`Dockerfile`、`build_artifact.py`：独立 `org.xelab.webui`，UID/GID 65532，已有 mTLS Lifecycle、签名静态路由及公开运行配置；没有数据库或管理代理后门。
- `examples/webui/public/{app,api,oauth}.js`、HTML/CSS：菜单、Dock、启动器、多窗口、组件、键盘/小屏操作、主题及本人偏好；贡献搜索和分页、固定窗口 Dock、签名尺寸范围内的组件布局编辑、API Key 只读元数据，固定贡献窗口按当前权限及签名/白名单摘要受控恢复；通过封闭操作表访问真实管理 API。未知副作用保留原幂等键，凭证变化后锁定原编辑器，不盲目刷新重发。
- `examples/webui/public/bridge.js`：固定安装/部署/贡献摘要，隔离 iframe、随机 view/nonce、精确 source/origin、协议/序列、负载/并发/速率限制；`skill.call` 仅解析固定 alias，宿主注入贡献部署，结果另读原 Call 复核当前权限；`window.open` 只开同一固定部署的获准窗口。
- `examples/ui-reference/`：独立 HTTP echo 进程、窗口和组件、固定 HTTP Skill/OpenAPI、`xelab.ui/1` 客户端；组件能请求窗口，不取得核心凭证或任意代理能力。输出采用文本，未收到真实结果不会显示成功。
- `crates/kernel/src/{ui,webui,deployments}.rs` 及 OAuth/HTTP/Skill 既有模块：签名贡献发现、账户偏好、默认 UI、精确 Client/回调及停用配置更新；沿用核心 Authorizer、Broker、Runtime 和追加迁移 16。
- `crates/kernel/tests/m3_ui.rs`、`tools/m3-ui-browser.py`、`tools/prepare-m3-ui-images.sh`：实际签名 OCI 制品、核心 HTTPS/HostService/Controller、PostgreSQL 和 Chromium 的整体门禁，不模拟核心响应。

桌面有插件/部署/审批/配置/版本与状态、Skill 注册/启停/调用、账户/子账户/权限来源、资源、Client、默认 UI 和 Operation 入口；实际能力取决于当前账户和 Client 上限。 BatchEngine、Workflow、微插件及知识库业务保持不可用；桥的未来 batch 方法返回明确不支持，不制造成功或业务数据。

## 已执行证据与尚缺证据

| 检查 | 2026-11-04 已执行结果 | 不能据此证明的内容 |
|---|---|---|
| WebUI Node / 回环 mTLS / Chromium 桌面 / 隔离桥 | 17 / 9 / 20+12 / 12 项通过，无跳过 | 浏览器使用明确核心响应夹具，非真实 Owner/OCI 整体授权；最新桥12项包含严格 framing 参数，真实非默认OCI壳场景待新CI |
| 真实 HTTP/2 TLS / Chromium151 | 6 项通过：40 个不同 Call 正文与完成事件、10 次完成后取消；真实字节边界、UTF-8、超时与取消负向 | 本地 JSON 服务与 token provider 是明确适配器，不是 Core/OCI/OAuth 验收；204 的无正文语义与 Inspector 事件单独记录 |
| 独立 UI 插件 Python / Node / Chromium | 7 / 5 / 4 项通过，无跳过 | 组件适配器不实现核心授权、OAuth、签名准入或 Runtime |
| WebUI 打包组件 | `68e50b22…` 镜像，真实生成的 Lifecycle RPC、mTLS 静态服务通过 | 非签名安装，也不是生产镜像的整体核心调用 |
| UI reference 生产镜像打包组件 | `5a654ccb…`，真实 ENTRYPOINT、Lifecycle、5 文件 GET/HEAD、HTTP echo 及拒绝/排空，42 条断言通过 | 42 条断言不是 42 个独立测试；上下文为明确的组件值，未验证核心授权或签名 |
| F hosts 防护 | 2 项实际临时文件测试通过；保留他人行、精确恢复、冲突地址拒绝 | 没有在本地修改真实 hosts 或运行 privileged OCI |
| F Rust 目标 | 类型检查及 `clippy --test m3_ui -- -D warnings` 通过，fmt/脚本语法通过 | 不代表被忽略的整体测试已运行 |

HTTP/2 读取回归直接服务生产 `api.js`，不拦截或伪造浏览器响应。原实现同一回归中40次真实UI读取成功，但6次被Inspector报告取消，只有34份独立正文完成证据；修正后40份及10次完成后取消均通过。修正先在clone分支严格计数，不存第二份JavaScript块数组，合法正文才用原Response的native消费者读取并复核字节数；并行取消两分支，保留原上限、Content-Type、严格UTF-8、JSON和调用取消/超时。原tee分支仍缓存合法正文，不是常量内存。残留timer、releaseLock和简单TransformStream的单一根因均被对照反证，未据此修改预算或采用不合格候选。

独立的#45真实OCI失败现场还发现reference在第三次POST之前进入draining/unhealthy；仅有成功Call不能排除独立静态租约围栏，cgroup删除也不能推导退出原因。新增固定Controller事件分别记录健康检查阶段与未知工作围栏，在停止前保留32条有界证据；测试只输出角色、枚举、计数与相对时间。健康阈值、原needed谓词、资源与物理围栏不变，真实最终CI仍须验证，不能称整体故障已修复。

后续 `3a3e0479…` 的 full CI 明确发生在登录前：api.js 504、static_unknown=1、WebUI被物理围栏重启；没有发生OAuth或Skill POST。为区分等待位置，新增成功时静默的 `STATIC_UNSETTLED` 诊断，仅在未结算租约释放时输出 transport_setup/fetch/authority_monitor/lease_complete 枚举及耗时；phase_ms是当前阶段停留时间，不是累计fetch时间。收集器仍限32条、只映射内部部署到角色，不输出路径、query、凭据或原始错误。具体超时根因仍待真实阶段证据；不修改原deadline、授权监视或unknown围栏，缺失事件也不能作为没有失败的证明。

2026-11-12 的真实 OCI 失败复核显示两个不同签名：`widget_bridge_calls_real_http_skill` 的调用与文本检查已通过，超时发生在随后的网络审计结算，原步骤名只到调用名；`valid_call_after_replay_rejection` 则停在 iframe 结果等待。现在 `tools/m3-ui-browser.py` 为每次 Skill 调用记录 `fill_input`/`submit_click`/`wait_iframe_result`/`check_result`/`audit_settle`/`audit_pump`/`audit_read`/`complete` 阶段与累计耗时，并报告首个不匹配点（提交、HTTP 响应、响应体核验、Call 只读证明、贡献配置复核、iframe 固定状态与结果）；窗口导航和帧核验也有独立步骤名。诊断仅在安全报告中保留最多 8 次调用，只含固定标签、布尔值、计数和时序，不保留正文、URL、标识或异常文本；不重试业务动作，不改变原调用次数、期限、权限和重放断言，也不能替代真实通过证据。#82 的根因仍待新 CI 的阶段证据。

每次 Skill 调用分别记录其浏览器上下文中固定 Call 证明和贡献复核 GET 的最近 8 个 HTTP 状态码。最近一次读取返回非 200 时，即使 iframe 尚未完成，报告也标记该次读取失败。

同一调用最多保留 32 条固定 GET 的请求时序，区分发起、收到响应、结束和失败。报告只保留请求类别、状态码、耗时和固定失败类别，便于排查结果传递期间停在哪一步。

公开 CSP 原先枚举无关账户的部署来源，UI游标原先明文携带被过滤部署标识并暴露全局候选数量桶；两者均是阻断合并的P1元数据泄露。现实现专用UI namespace的固定frame-src、公开默认/配置父源和经过真实OAuth Client绑定的framing-only精确父源，另以不透明游标和分页前Policy预选修复目录泄露。详见[贡献规范](../plugins/ui-contributions.md)。最新4项真实PostgreSQL/独立mTLS回归通过，但最终Core/UI全回归与真实OCI门禁仍待执行；不能把该证明当用户授权或把组件通过当整体通过。

打包 QA 保留 `packaged-ui-qa-20261104/evidence.json`、源文件 SHA-256、探针及日志； 实际观察到 UID 65532、只读根、零有效 capability 和 NoNewPrivs。 该本地 Docker 的 `CgroupDriver=none`，CPU/内存/PID 标志仅已配置，**没有逐容器资源限额执行证据**。 临时容器、QA 镜像标签和测试私钥已删除；镜像短摘要是本次执行标识，不是发布/签名引用。

待通过的是 [Kernel M1 工作流](../../.github/workflows/kernel.yml) 在最终精确提交上的 `Independent WebUI and iframe components`、`Prepare signed OCI WebUI and UI reference`、 `Real OCI OAuth desktop iframe Skill and restart`，以及既有 workspace/迁移/契约/lint 回归。 不能用旧 PR 绿灯、打包组件或独立可信登录页面测试替代该整体门禁。 准备好下文固定版本 Playwright 的两个环境变量后，可单独重跑工作流中的组件步骤：

```bash
set -euo pipefail
node --test examples/webui/test_api.mjs examples/ui-reference/test_bridge.mjs
"$XELAB_OAUTH_BROWSER_PYTHON" -m unittest discover -s examples/webui -p 'test_server.py' -v
"$XELAB_OAUTH_BROWSER_PYTHON" -m unittest discover -s examples/webui -p 'test_http2.py' -v
"$XELAB_OAUTH_BROWSER_PYTHON" -m unittest discover -s examples/webui -p 'test_browser.py' -v
"$XELAB_OAUTH_BROWSER_PYTHON" -m unittest discover -s examples/webui -p 'test_shell.py' -v
"$XELAB_OAUTH_BROWSER_PYTHON" -m unittest discover -s examples/webui -p 'test_bridge.py' -v
"$XELAB_OAUTH_BROWSER_PYTHON" -m unittest discover -s examples/ui-reference -p 'test_http.py' -v
"$XELAB_OAUTH_BROWSER_PYTHON" examples/ui-reference/test_browser.py --webui-public examples/webui/public -v
```

## 实际部署与 CLI 恢复

生产宿主需满足内核 **4C16G 加系统预留及插件预算**，不能套用下面测试的合成元数据池。 按[部署说明](../../examples/webui/DEPLOYMENT.md)构建、签名并通过真实 Publisher/安装 API 准入。 DNS 的核心域名和 `*.plugins.example.org` 应指向同一核心 HTTPS 监听器；证书须覆盖核心名和该通配符。 例如核心 `https://core.example.org:8443`，`server.listen=0.0.0.0:8443`， `ui_gateway.base_domain=plugins.example.org`、`public_port=8443`；各来源保留不同 Host，不能把全部 Host 改成核心 Host。 核心域名必须位于专用UI命名空间之外。443 时使用无显式默认端口的规范 origin。`shell_origins=[]` 时，裸静态页面只允许公开默认WebUI；非默认壳须有当前有效、已批准且健康的固定WebUI Client及Core生成的framing-only证明，不能把第三方任意源加入可信壳。 为部署分配的页面源是 `https://d-<部署 UUID 去连字符>.plugins.example.org:8443`，OAuth 回调固定在其 `/ui/org.xelab.webui/callback`。

以下从仓库根目录运行，前提是已有有效核心、受信安装及私有 Owner token 文件。 设置真实的 `CORE_ORIGIN`、`CORE_CA_FILE`、`OWNER_TOKEN_FILE`、`OWNER_ID`、`INSTALLATION_ID` 和 `GATEWAY_AUTHORITY`（示例 `plugins.example.org:8443`）；不把密码/令牌写进命令或请求 JSON。 所有请求文件从仓库模板/契约样例和实际响应生成；检查 Client 规则并按对象范围收窄后再提交。

```bash
set -euo pipefail
umask 077
setup=$(mktemp -d)
export SETUP_DIR="$setup"
api() { local op=$1; shift; xelabctl api "$op" --endpoint "$CORE_ORIGIN" --ca-file "$CORE_CA_FILE" --token-file "$OWNER_TOKEN_FILE" "$@"; }
etag() { jq -r '"\"rev-\(.revision)\""' "$1"; }
intent() { local path="$setup/intent-$1"; if [[ ! -f $path ]]; then uuidgen > "$path"; fi; cat "$path"; }
wait_op() {
  local id; id=$(jq -er .id "$1")
  for ((n=0;n<480;n++)); do
    api getOperation --path "operation_id=$id" > "$setup/operation.json" || return
    case $(jq -r .state "$setup/operation.json") in
      succeeded) jq .result "$setup/operation.json" > "$2"; return;;
      failed|canceled) echo 'Operation failed; inspect the private response file' >&2; return 1;;
    esac
    sleep 0.25
  done
  return 1
}
jq --arg id "$INSTALLATION_ID" --arg core "$CORE_ORIGIN" '.installation_id=$id | .enabled=false | .config.core_origin=$core | .config.client_id=null' docs/preset-plugins/webui/deployment.template.json > "$setup/create.json"
api createDeployment --body-file "$setup/create.json" --idempotency-key "$(intent create-deployment)" > "$setup/create-operation.json"
wait_op "$setup/create-operation.json" "$setup/deployment.json"
DEPLOYMENT_ID=$(jq -er .id "$setup/deployment.json")
export DEPLOYMENT_ID
export UI_ORIGIN="https://d-${DEPLOYMENT_ID//-/}.$GATEWAY_AUTHORITY"
api getEffectivePermissions --path "account_id=$OWNER_ID" > "$setup/effective.json"
node --input-type=module <<'JS'
import fs from 'node:fs';
import {OPERATIONS} from './examples/webui/public/api.js';
const read=p=>JSON.parse(fs.readFileSync(p,'utf8')), dir=process.env.SETUP_DIR;
const examples=read('docs/contracts/examples/http-requests.json');
const spec=read('docs/contracts/openapi.json'), names=new Set(Object.keys(OPERATIONS));
const actions=new Set(Object.values(spec.paths).flatMap(value=>Object.values(value)).filter(value=>names.has(value.operationId)).map(value=>value['x-permission']));
for(const action of ['plugin.http.invoke','capability.invoke'])actions.add(action);
const maximum_rules=read(dir+'/effective.json').rules.filter(value=>actions.has(value.action));
if(!maximum_rules.length||maximum_rules.length>256)throw Error('Review the registered desktop ceiling');
const client={...examples.createClient.value,name:'XeLab desktop',plugin_id:'org.xelab.webui',allowed_origins:[process.env.UI_ORIGIN],redirect_uris:[process.env.UI_ORIGIN+'/ui/org.xelab.webui/callback'],maximum_rules};
fs.writeFileSync(dir+'/client.json',JSON.stringify(client));
for(const name of ['approvePlugin','setDeploymentEnabled','setDefaultUi'])fs.writeFileSync(dir+'/'+name+'.json',JSON.stringify(examples[name].value));
JS
# Review client.json: maximum_rules retains actual selectors/conditions;
# it is a public-client ceiling, never an automatic grant to other accounts.
api createClient --body-file "$setup/client.json" --idempotency-key "$(intent create-client)" > "$setup/client-result.json"
api getDeployment --path "deployment_id=$DEPLOYMENT_ID" > "$setup/deployment.json"
jq --arg client "$(jq -er .client_id "$setup/client-result.json")" '{spec:.spec} | .spec.config.client_id=$client' "$setup/deployment.json" > "$setup/patch.json"
api updateDeployment --path "deployment_id=$DEPLOYMENT_ID" --body-file "$setup/patch.json" --if-match "$(etag "$setup/deployment.json")" --idempotency-key "$(intent configure-webui)" > "$setup/config-operation.json"
wait_op "$setup/config-operation.json" "$setup/configured.json"
api getDeployment --path "deployment_id=$DEPLOYMENT_ID" > "$setup/deployment.json"
api approvePlugin --path "deployment_id=$DEPLOYMENT_ID" --body-file "$setup/approvePlugin.json" --if-match "$(etag "$setup/deployment.json")" --idempotency-key "$(intent approve-webui)"
api getDeployment --path "deployment_id=$DEPLOYMENT_ID" > "$setup/deployment.json"
jq '.enabled=true' "$setup/setDeploymentEnabled.json" > "$setup/enable.json"
api setDeploymentEnabled --path "deployment_id=$DEPLOYMENT_ID" --body-file "$setup/enable.json" --if-match "$(etag "$setup/deployment.json")" --idempotency-key "$(intent enable-webui)" > "$setup/enable-operation.json"
wait_op "$setup/enable-operation.json" "$setup/ready.json"
for ((n=0;n<480;n++)); do
  api getDeployment --path "deployment_id=$DEPLOYMENT_ID" > "$setup/ready.json" || break
  [[ $(jq -r .phase "$setup/ready.json") == ready ]] && break
  sleep 0.25
done
jq -e '.phase=="ready" and .spec.enabled==true' "$setup/ready.json" > /dev/null || exit 1
api getDefaultUi > "$setup/default.json"
jq --arg id "$DEPLOYMENT_ID" '.deployment_id=$id' "$setup/setDefaultUi.json" > "$setup/default-webui.json"
api setDefaultUi --body-file "$setup/default-webui.json" --if-match "$(etag "$setup/default.json")" --idempotency-key "$(intent set-default-webui)"
```

`Client.id` 是管理资源 UUID，`Client.client_id` 才是写入 WebUI 配置的公开 OAuth 标识。 Skill 的目标动作独立于 `skill.invoke`：示例另外选取已有 `plugin.http.invoke`、`capability.invoke` 规则，不创造授权；含 Blob 输入的固定 Skill 还需按实际对象选择已获准的 `blob.read` 上限及当前 ACL。 `updateDeployment` 请求必须是完整 `{spec:...}`，仅完全停用/排空时允许；返回 202 Operation，成功结果为 Deployment，不能当作同步 200。 前述临时 JSON 不含密码但包含管理信息，应私有保管。步骤键保存在该目录；传输结果未知时保留目录并查询原 Operation/按原键核实，不重跑初始化或换键重放副作用。

停用与恢复无需依赖桌面。保留上述工作目录及原 Owner 凭证，用最新 ETag 关闭该部署、清空默认 UI；随后可用同一 CLI 安装或配置替代界面：

```bash
set -euo pipefail
api getDeployment --path "deployment_id=$DEPLOYMENT_ID" > "$setup/deployment.json"
api setDeploymentEnabled --path "deployment_id=$DEPLOYMENT_ID" --body-file "$setup/setDeploymentEnabled.json" --if-match "$(etag "$setup/deployment.json")" --idempotency-key "$(intent disable-webui)" > "$setup/disable-operation.json"
wait_op "$setup/disable-operation.json" "$setup/disabled.json"
api getDefaultUi > "$setup/default.json"
api setDefaultUi --body-file "$setup/setDefaultUi.json" --if-match "$(etag "$setup/default.json")" --idempotency-key "$(intent clear-default-ui)"
api getNode
```

根路径此时明确返回 503；可信登录页面、核心 API 和 CLI 仍可独立使用。第三方页面部署另按[参考插件步骤](../../examples/ui-reference/README.md)，其注册 Skill/业务授权不能用 `plugin.ui.open` 代替。

## 独立宿主整体门禁的复现

仅在可销毁、独占 Linux 宿主执行：需 root/sudo、真实 containerd/runc、可写 cgroups v2 的 cpu/memory/pids 控制器、nftables、iproute2、Docker、OpenSSL、Python venv、Node、jq、uuidgen、Rust 和可用 `/mnt` 空间。 隔离 PostgreSQL 16 的角色必须能创建测试数据库，容器共享内存建议 512MiB；用真实测试 DSN 设置 `XELAB_TEST_DATABASE_URL`，不要在共享日志打印它。 测试会修改专用插件 cgroup 父组、网络与一条唯一 hosts 行，应与其他 privileged 场景串行执行；保留既有受管 `xh-rpc` 的 `172.29.240.0/24` 配置，冲突时拒绝，不重绑其他宿主网络。

下面沿用工作流中的构建、版本、镜像准备和 sudo 环境保留方式。`--env-file` 只追加，不自动导出，因此本地显式 `set -a`；私有临时路径和两个浏览器绝对路径须保留给 root：

```bash
set -euo pipefail
: "${XELAB_TEST_DATABASE_URL:?Set the isolated PostgreSQL test DSN}"
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
cargo test --workspace --all-targets --no-run --locked
cargo build --workspace --bins --locked
sudo systemctl start containerd
m3_env=$(mktemp)
m3_browser=$(mktemp -d)
trap 'rm -f -- "$m3_env"; rm -rf -- "$m3_browser"' EXIT
python3 -m venv "$m3_browser"
"$m3_browser/bin/pip" install 'playwright==1.62.0' 'jsonschema==4.26.0'
"$m3_browser/bin/python" -m playwright install --with-deps chromium
"$m3_browser/bin/python" - "$m3_env" <<'PY'
import sys
from playwright.sync_api import sync_playwright
with sync_playwright() as browser:
    chromium=browser.chromium.executable_path
with open(sys.argv[1],'a') as output:
    output.write(f'XELAB_OAUTH_BROWSER_PYTHON={sys.executable}\nXELAB_OAUTH_BROWSER_CHROMIUM={chromium}\n')
PY
bash tools/prepare-m3-ui-images.sh --isolated-test-host --env-file "$m3_env"
set -a
. "$m3_env"
set +a
python3 - <<'PYTEST'
import glob, os, subprocess
binaries=[p for p in glob.glob("target/debug/deps/m3_ui-*") if os.path.isfile(p) and os.access(p,os.X_OK)]
assert len(binaries)==1,binaries
variables="XELAB_M3_UI_TEST,XELAB_M3_UI_NAMESPACE,XELAB_TEST_WEBUI_IMAGE,XELAB_TEST_UI_REFERENCE_IMAGE,XELAB_TEST_DATABASE_URL,XELAB_OAUTH_BROWSER_CHROMIUM,XELAB_OAUTH_BROWSER_PYTHON"
subprocess.run(["sudo", "--preserve-env="+variables, binaries[0], "--ignored", "--nocapture"],check=True)
PYTEST
```

准备脚本以实际平台 manifest 摘要固定两镜像，生成一次性测试签名安装请求；已成功导入的自身 tar 才删除。 其中固定发布者/签名种子仅用于可销毁测试，不是生产密钥。测试生成唯一数据库、私有根目录和证书；浏览器只固定测试证书 SPKI，CLI 使用真实 CA/SAN/Host 校验，hosts 行由 guard 精确撤回。 未用非默认 `CARGO_TARGET_DIR`，以保持与工作流的 binary glob 一致；若有多份旧可执行目标，先核对来源，不任意选择一份。

整体测试要求实际安装/审批/启用、注册固定 Skill、真实 Owner/子账户可信登录和 PKCE、桌面读取/调用/偏好、第三方窗口/组件与同部署窗口打开； 错误 nonce/协议/序列/来源后要求仅合法调用产生一次 POST、Call 和日额度，无并发泄漏；真实撤权后拒绝新调用且不计费。 停用 WebUI 后运行真正 `xelabctl`，随后在同一测试进程重新建立 App/Controller/HostService/HTTPS listener，复用持久数据库与密钥，检查账本、撤权、OCI Skill 和 cgroup。 这是**核心组件重启**，不是 daemon SIGKILL/reexec、OS 重启、断电或独立宿主恢复证据。

F 的 node_budget 明确使用 8000 CPU millis/32GiB 的**合成元数据池**；仍断言真实 4C16G 总容量不足以通过生产准入。 插件确实由 Runtime 在真实 cgroup 运行，测试还直接读取两实例的 `cpu.max`、`memory.max`、`pids.max` 并比较批准值，重启后复核 reference。 只有整体测试成功输出 `M3_UI_EVIDENCE` 才产生这些执行证据；仅编译、DB 限额或 Docker 配置值均不能代替。 即使通过也不证明生产 4C16G 预留/峰值负载；正式 [RUN-03](run03-host.md)、独立宿主恢复仍待适格宿主，真实 AWS 演练 **DEFERRED**，恢复条件见 [M3 总进度](m3-progress.md)。

## 真实浏览器发现的目录接口缺口

首次 OCI/浏览器执行卡在插件中心；随后源码审计确认目录接口仍未实现，请求到达该分派时将返回 503。 这不是浏览器已观测到 503 的证据：后续安全诊断显示实际目录 GET 尚未发送，另由下述预检错误阻断。 现补齐 listPublishers/listInstallations/listDeployments/listInstances，复用 Authorizer/Policy、Origin、实际对象 owner 和既有 DTO。 安装按 plugin ID、部署/实例按各自对象与 owner 授权；listInstances 规范类型同步为 instance，无新字段或迁移。

SQL 先选当前可见对象，再逐对象复核规则；不泄露私有 ID/总数。按 `(created_at,id)`、创建水位分页，旧状态实时读取。 每页最多 200 项/8MiB；15 分钟游标用现有 ring AES-GCM、领域派生 Auth 密钥与随机 nonce，绑定主体、完整凭证链、 Origin、对端、过滤、页大小及授权/来源版本。撤权、同范围新授权或版本变化后须从第一页重读。

新增 PostgreSQL + 生产 App.router OAuth/CORS 回归执行真实 Client/PKCE/同意，检查受限 Owner 两部署、子账户过滤、 跨源/跨主体拒绝、私有过滤存在性隔离、游标篡改/过期/过滤/授权变化、创建水位与状态更新。 这些元数据组件不声称 OCI 整体验收；修正后的最终提交仍须通过真实 CI。


## 带查询参数的实际浏览器预检

目录实现后的真实完整门禁仍卡在同一视图。安全报告只有无查询的 preferences 200， 没有目录 GET；源码与新 PostgreSQL 回归确认 `OPTIONS /api/platform/v1/installations?limit=200` 被认证端点的查询限制提前拒绝（修复前实际 400，而非期待 204）。 预检现在先经过既有注册来源、声明路由、方法、请求头及空正文检查； OAuth token/登录的非法查询仍拒绝，实际管理 GET 继续验证参数 Schema 与当前授权。

修复后的生产 App.router/PostgreSQL 正负回归通过，OAuth HTTP 8 项、目录 2 项及 真实 Chromium/PKCE/刷新复用回归的 43 项检查全部通过，包含新增 native account query/CORS 200。 这仍是独立核心浏览器组件；完整 OCI 桌面、iframe、撤权和重启结论须由修复后的最终 CI 取得。
