# 独立 UI Contribution 参考插件

`org.xelab.ui-reference` 是独立普通 OCI 插件，不是 WebUI 内置应用。它在 `7000` 提供已有 `PluginLifecycle` mTLS RPC，在 `8080` 运行自己的 mTLS HTTP 应用。HTTP `echoUiReference` 真正解析并返回提交文本；候选 Skill 固定该操作和原始 OpenAPI 摘要。静态页面包含一个窗口和一个桌面组件，两者均仅通过 `xelab.ui/1` 的 `echo` 别名调用 Skill，组件还可请求同部署的 `echo_window`。

页面不读取密码、Cookie 或核心令牌，不访问核心 HTTP、不选择 Skill UUID、目标 URL 或部署。宿主从已批准贡献填入固定 `provider_deployment_id`，再执行全部业务授权。未获得绑定时只显示不可用；未收到真实后端结果时不显示成功。组件刷新事件不自动重复调用业务。输入或输出中的 HTML 当普通文本显示。

Echo Skill 的业务请求使用 10 秒期限。页面最多等待桥响应 40 秒，给宿主的调用前贡献核验、原 Call 读取和发送前贡献复核各留出 10 秒。等待超时后保留原意图键供核实。

## 构建、签名与部署

在仓库根目录执行。`PUBLISHER_ID` 必须来自实际受信 Publisher；页面、Skill、清单或 OpenAPI 改变时发布新版本，不能替换已安装的旧制品。

```sh
python3 examples/ui-reference/build_artifact.py --publisher-id "$PUBLISHER_ID"
docker build -f examples/ui-reference/Dockerfile \
  -t docker.io/local/xelab-ui-reference:1.0.0 .
docker save docker.io/local/xelab-ui-reference:1.0.0 \
  -o examples/ui-reference/generated/plugin.tar
sudo ctr -n xelab images import examples/ui-reference/generated/plugin.tar
```

为 ARM64 构建时显式使用 `--platform linux/arm64` 并使用对应平台镜像。非默认版本同时指定 `--plugin-version`、tag 和独立输出目录，Docker 使用 `--build-arg ARTIFACT_DIR=<目录>`。从真实 containerd 导入结果读取**平台 OCI manifest** 摘要，不能以可变 tag、Docker image config 摘要或多平台 index 摘要代替。

```sh
sudo ctr -n xelab images tag docker.io/local/xelab-ui-reference:1.0.0 \
  docker.io/local/xelab-ui-reference@sha256:<实际平台manifest摘要>
python3 examples/echo/sign_artifact.py \
  --manifest examples/ui-reference/generated/xelab/plugin.json \
  --image docker.io/local/xelab-ui-reference@sha256:<实际平台manifest摘要> \
  --key publisher.key > examples/ui-reference/generated/install.json
xelabctl api installPlugin --endpoint "$CORE_ORIGIN" --ca-file core-ca.crt \
  --token-file owner-token --body-file examples/ui-reference/generated/install.json \
  --idempotency-key ui-reference-install-1
```

等真实安装 Operation 完成，再以其实际 `installation_id` 创建部署。配置为 `{}`、单副本、无卷。建议初始限额为 `cpu_millis=250`、`memory_bytes=268435456`、`ephemeral_bytes=16777216`、`pids=64`；这不是生产容量验收结果。镜像 UID/GID 固定 `65532:65532`，内核保持只读根文件系统和既有 cgroup 限制，不要求宿主挂载、额外 capability 或特权网络。

使用公开 `createDeployment` → `approvePlugin` → `setDeploymentEnabled`。此插件不申请 Secret、Blob 或外部网络；审批体为 `{"rules":[],"egress":[]}`。审批和启停使用各步骤实际 ETag，不假定固定 revision。等待真实部署 Ready，再从生成清单的 `skills[0]` 构造 `CreateSkill`，提交实际 `installation_id`，注册后显式启用；安装不会自动注册或授权 Skill。

内核需配置带实际 DNS/TLS 的 `ui_gateway`，由平台为部署分配独立 `https://d-<deployment UUID 无连字符>.<base_domain>[:port]`。不得将此源与核心登录源、官方 WebUI 或其他插件共用。官方 WebUI 的实际 OAuth Client 必须已注册、启用并获准作为宿主。

调用者分别需要 `plugin.ui.open`、精确 Skill 的 `skill.invoke`、目标 `plugin.http.invoke`，以及读取既有 Call 结果所需的 `capability.call.read`；OAuth Client 范围也必须允许这些操作。`plugin.ui.open` 本身不授予业务权限。账户、授权来源和 Guest/子账户共享仍使用核心现有管理接口。

通过 `listUiContributions` / `getUiContribution` 查看实际 `echo_window`、`echo_widget` 的安装、摘要、隔离源、可用状态与解析绑定，在官方桌面打开窗口或添加组件。iframe URL fragment 由宿主生成；直接打开裸页面会显示缺少可信通道，不能手工拼入核心凭证。

## 可执行组件检查

```sh
python3 -m unittest discover -s examples/ui-reference -p 'test_http.py' -v
node --test examples/ui-reference/test_bridge.mjs
python3 examples/ui-reference/test_browser.py \
  --webui-public examples/webui/public -v
```

Python 测试执行真实回环 HTTPS、临时 CA/内核和错误工作负载证书、严格输入、GET/HEAD/ETag、路径和身份头拒绝、排空及并发槽归还；另用现有 Ed25519 签名工具验证精确 envelope 和篡改拒绝。签名单元测试使用明确的组件测试镜像引用，不证明该 OCI 镜像存在或已获准安装。

`test_http.py` 的 Schema 用例导入 `jsonschema`；系统 Python 未安装时会报 `ModuleNotFoundError` 而不是跳过。可按 CI 方式安装后运行：

```sh
python3 -m pip install -r docs/tools/requirements.txt
```

浏览器驱动要求实际官方 `BridgeHost` / `ApiClient` 文件、Chromium 和 Python Playwright。它运行独立 Python 子进程的真实 mTLS 业务及静态服务，通过明确的受控 Core **组件适配器**与官方宿主消息桥互操作；检查真实 echo、固定部署、DOM/存储隔离、文本输出、窗口打开、绑定缺失、撤权关闭和错误 nonce/序列。该适配器不实现或冒充核心 Authorizer、Broker、OAuth、签名准入及 OCI Runtime。

本组件已执行的结果：Python 7 项、Node 5 项、实际 Chromium 4 项通过且无跳过。第一轮浏览器测试暴露 Playwright 字符串等待触发严格 CSP 的 `unsafe-eval` 拒绝；已改测试等待函数，保留 `script-src 'self'`，未放宽 CSP。

## 完整验收边界

容器和真正内核 OCI 生命周期、平台签名/审批、OAuth 登录、官方 WebUI、实际 SkillRouter → Broker 调用、跨账户撤权及重启后状态仍需整体集成测试；上述组件结果不能代替这些结论。本参考插件不依赖 AWS，不标记 off-host、灾备、生产容量或未来 Batch/Workflow 功能完成。
