# M3 声明式 HTTP、HTTP Skill 与静态网关

本页保留的4C16G容量要求及既有证据属于 `standard` profile；[compact 1C512MiB](compact-node.md) 有独立准入与整机验收，不复用本页容量结论。


> 2026-11-09 验收补记：M3 功能提交 #45/#46/#47 的精确完整与专项 CI 已全部通过。下文保留相应切片开发时的命令、历史状态和证据边界；当前验收表与精确 head/tree/CI 见 [当前验收记录](m3-acceptance-20261109.md)，最终集成与 main CI 见 [目标 #38](https://github.com/jyxxe/XeLab/issues/38)。历史“待验收”表述不得替代该最新记录，组件通过也不替代真实 OCI 或正式生产验收。
[实施索引](README.md) · [持续进度](m3-progress.md) · [HTTP 契约](../communication/plugin-http.md) · [来源持久化](m3-http-provenance.md)

此页记录 HTTP 开发分支的实际源码与验收边界。M3-B 尚未合并到 main，
本地集成回归、真实内核 OCI 及最终 CI 仍在执行；不能宣布 M3-B 或整个 M3 完成。
普通 capability Skill 的七项公开操作已随 PR #39/#40 交付。
HTTP Skill 复用这些操作；HostService 插件侧代理按[路线图 M4](roadmap.md)继续实现。

## 制品、契约与入口

安装复用现有固定 OCI manifest digest、Ed25519 清单信封与发布者信任。
镜像内 `/xelab/http/openapi.json` 的原始 SHA-256 必须匹配签名 RouteSpec；
Schema 15 保存不可变字节及历史 HTTP Call 绑定，详见[持久化说明](m3-http-provenance.md)。
接口权威来自已验证安装，不能使用插件 Describe 或用户提交 URL 替换。

Registry 只注册明确的方法和字面路径，前缀不是业务 catch-all。
操作 `x-permission` 必须等于 RouteSpec.required_action，且为现有已注册的
`plugin.http.invoke` 或插件自身命名空间动作，资源类型必须为 plugin。
输入、输出、错误状态、媒体类型及非敏感自定义头均按签名声明验证。
拒绝重复 JSON key、引用型 Schema、编码或点段路径、未声明操作和协议升级。

当前 profile 支持 JSON 业务操作、声明式 `200 text/event-stream`、
以及 static GET/HEAD；HTTP Skill 固定操作的方法与所有成功状态，
JSON 正文/输出和 SSE 的 item/output Schema 与签名候选及 OpenAPI 精确核对。
无正文操作使用 null identity 输入，204 和声明式 HEAD 返回 null，不能由输入选择 URL 或方法。
HEAD 的所有响应均须显式无 content，不能以空正文冒充已验证 JSON 输出。
路径模板、查询参数、
静态 Range、WebSocket、插件 Cookie 和重定向明确拒绝。
WebUI、UI Contribution、OAuth 与 UI 桥还没有因此获得准入。
data_schema_version 非 none 的公开制品门禁继续关闭。

## 授权、实例与生命周期

业务转发进入同一个 Broker，复用 Identity/Authorizer、祖先配额、来源计费、
幂等记录、审计、RpcDelegation 和 Controller 围栏；不建立平行权限系统。
HTTP Skill 同时要求 skill.invoke 与目标 required_action，固定安装、部署、
实例 generation、operationId 与摘要。多个获批目标没有精确绑定时拒绝，
不会按名称选最新版或从请求头接受提供者。

直接 HTTP 的内部 ContractRef 为 plugin_id + `.http`、插件精确版本和 HTTP 契约摘要，
只用于统一 Call 账本，不创建裸 RPC capability provider。
HTTP Skill 的虚拟 ContractRef 保留 Skill.name/version/definition_digest。
HTTP-only 插件通过签名 Describe、Lifecycle 健康及 HTTP8080 TLS 探针确认 Ready，
不依靠伪造 capability。业务 HTTP 与 RPC 共享实例 max_active_requests。

静态 GET/HEAD 使用 plugin_http_requests 占用相同物理池，
不伪造用户、业务 Call、日额度或账户配额。
已知传输完成才释放静态预留；断线、失败或未知结果保留到 Controller 确认旧进程停止。
审批保存原 plugin.permission.grant 来源及安装/清单绑定；替代授权不能复活旧审批。
在途调用、静态下载和响应交付持续复核当前来源、审批、信任及固定实例。
deadline 覆盖入口处理、准入等待、传输与交付；不盲目重试未知副作用或切换提供者。
完成 Skill/HTTP Call 的结果读取、幂等重放和流交付复核原始计费来源、
固定绑定及输入 Blob 的原始与当前读权限；call.read 不能替代业务权限。
读取结果继续绑定原调用主体/凭证；HTTP 结果还要求原部署当前有效审批。
API Key 的整数额度接受合法 1.0 编码，轮换不能删除、提高或重置已用上限。

重启先停止旧进程再归还物理槽。离线恢复保留契约、Skill 和历史 Call，
撤销凭证/发布者、停用部署并清除当前 HTTP 审批与瞬时静态账本。
历史来源不等于恢复后的新授权；CLI 和核心管理 API 不依赖任何 WebUI。

## 可信来源与转发上下文

可信管理 API、登录与探针只在配置的 public_origin Host 提供。
静态页面只接受平台分配的 `d-<deployment UUID无连字符>.<base_domain>[:port]`，
并固定对应部署。未知 Host、冲突 authority、Forwarded/X-Forwarded-* 拒绝；
反向代理必须保留精确 Host 并移除这些转发来源头。
插件 Host 不能提供内核登录、OAuth、管理路径或可信登录 Cookie。
静态 CSP 限定已批准 shell_origins，禁止 worker、网络连接和表单等权限；
没有隔离来源时不得退回可信登录同源。

敏感 Cookie 请求要求精确 Origin 和会话绑定的 X-CSRF-Token；
可信登录返回该响应头，只能由登录/激活路径设置 __Host-xelab_auth。
旧 Cookie 失效不妨碍显式新密码/激活凭证认证；它不会成为该认证的权限来源。
Bearer 与 Cookie 同时出现时核对主体，跨账户组合拒绝。
Bearer-only CLI 保留现有用法。

核心仅连接运行时观测到的固定 CIDR 地址 HTTP8080，验证工作负载 CA、
证书有效期、精确 DNS 及实例/generation SPIFFE；插件验证精确内核 SPIFFE。
外部原始 Bearer、Cookie、身份/委托头和 hop-by-hop 头不透传。
以下保留字段由已持久准入的核心重新建立：

| 头 | 可信来源 |
|---|---|
| X-Xelab-Delegation | 既有不透明 RpcDelegation |
| X-Xelab-Subject / Call-ID | 已认证主体 / 已持久 Call UUID |
| X-Xelab-Deadline-Unix-Ms | 原始剩余期限的十进制 Unix 毫秒 |
| X-Xelab-Idempotency-Key | 持久业务键 UTF-8 的无填充 base64url |

业务键与网关 HTTP 去重键保持分离；后者不能被盲目转发为业务权限或重试授权。

## SSE 与资源边界

HTTP SSE 使用既有 StreamEvent，event/id/data 与固定 Call、kind 和 sequence 一致；
accepted 首帧，连续序号，恰好一个终帧。逐帧验证签名 Schema 和当前权限，
确认 EOF、无终帧后数据及持久提交后才交付 completed。
缺终帧、错误来源/序号、畸形输出及 completed 后数据均失败。
Last-Event-ID 不支持恢复，同一 HTTP 幂等键不重新生成或拼接旧流。

HTTP `streamSkill` 通过同一 HTTP Broker 接入已有有界 Skill SSE 输出，
后端事件仍使用原 `plugin_id.http` 契约并固定 Call/instance；
核心逐帧验证完整签名 StreamEvent 和精确 item Schema，仅由核心填入 Skill UUID/摘要。
完成输出另验 Skill output Schema，确认 EOF、原权限与持久提交后才包装 completed。
同一流键返回原 Call 冲突而不重复扣费，选错流式/非流式入口在准入前拒绝。
取消、断线或畸形流仍保留 unknown 和原进程资源，实际 Controller 围栏后才能释放。
Skill 队列交付也复核当前 HTTP 审批，不让已入队结果越过撤权。


单帧上限 1 MiB，有界队列与消费者 30 秒停滞限制遵循
[流控契约](../communication/streaming.md)。入口 actor 限制为 32，
每个 JSON 请求至多 16 MiB 且取签名路由更低限制。
静态保留响应限制为 32，业务 HTTP 保留响应为 64；响应体上限 16 MiB，
这些容量持续到实际 Body 被销毁，不能因物理 Call 已结束或读到 EOF 提前归还。
内核 4C16G 预留及现有 fail-closed 资源门槛不变。

## 参考制品与可执行验证

[独立 HTTP 参考插件](../../examples/http/README.md)提供实际 echo、hold、SSE 与静态页，
混合版本实现真实 CapabilityService，并与 HTTP 共用四个应用物理槽。
制品构建、签名、导入、部署与容器探针命令见该 README；部署仍通过公开管理 API。
访问静态页面使用配置的隔离部署来源，业务请求使用已声明路径及当前授权。

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test -p xelab-kernel --lib http_contracts --locked
cargo test -p xelab-kernel --lib plugin_http --locked
cargo test -p xelab-kernel --lib http_component_tests --locked -- --nocapture --test-threads=1
cargo test -p xelab-kernel --test postgres --locked
python3 -m unittest discover -s examples/http -p 'test_*.py' -v
python3 docs/tools/validate_docs.py --strict
```

PostgreSQL 组件需要隔离的 XELAB_TEST_DATABASE_URL。
真实内核 OCI 入口为 [tests/http.rs](../../crates/kernel/tests/http.rs) 与
[Kernel 工作流](../../.github/workflows/kernel.yml)，要求独占 containerd/runc、
cgroups v2、网络及显式 XELAB_HTTP_OCI_TEST=1；不能用 Docker 组件探针代替。
混合 OCI 测试镜像中由 `--include-rpc` 生成的签名 `hold` Skill 用于验收 Task 取消与工作负载停止。

记录时，6 项不可变契约 PostgreSQL 测试（含缓存/篡改）、16 项 HTTP/网关、
4 项元数据快照（含完整 4 MiB 原始契约）、3 项 Broker 监控/Schema 与 2 项 API 回归通过。
Python 参考插件 12 项测试及 HTTP-only/混合两个实际打包探针通过。
核心/PG/独立真实 mTLS 插件组件已完整通过：原 5 秒 Skill 调用、同键重放、
双层授权拒绝、JSON/SSE、精确撤权失败、跨部署 owner 隔离、缺少冻结上下文拒绝，
以及声明两槽的两路实际请求、第三路核心 503 且无新增 Call/计费、成功后槽释放。
此前四路 debug 组件试验有实际 deadline 失败，不能计为压力或容量通过；
签名参考制品与真实 OCI 四槽混合 HTTP/RPC 场景保持不变，已在 #43 的真实 OCI 阶段通过。
原 13 项安全/组件场景已分别实际通过（串行 11 项与修正夹具后的 2 项），
包括 PG 排队授权写入者、Grant/签发账户跨账本等待到期、原始有效替代来源继续计费，
以及冻结上下文排除过期未计费来源。测试组规则保留签发 Key 的原始到期上限，
未放松 require_subset。fmt 和全 workspace/all-target Clippy（-D warnings）通过。
另有实际 API→JSONB 1.0 额度/轮换与 mTLS 首帧 EOF/item 拒绝组件 2 项通过，
原始结果/Blob 权限的真实 PostgreSQL 3 项及 Identity/Skill/PostgreSQL 25 项通过。
完整 workspace 尝试的库结果为 150 通过、5 失败、3 项显式忽略；
其中空 ContractRef 旧夹具已按现契约修正并单测通过，
其余 4 项归档/克隆失败来自本地主机 overlay 目录属性列表的长度/读取不一致。
保持相同源码、路径及严格检查，在隔离非特权容器真实 tmpfs /tmp 上，
归档 2 项及克隆 3 项全部通过；这不等于原宿主完整 workspace 通过。
后续 integration 25 项通过。[Draft #43](https://github.com/jyxxe/XeLab/pull/43)
的 [c537bef CI](https://github.com/jyxxe/XeLab/actions/runs/41841936407) 实际 HTTP/static OCI、
旧 OCI 生命周期和 XFS 卷/进程恢复通过；后续全平台恢复业务测试因夹具 Host
仍为示例域名而失败。已改用实际恢复配置的 public_origin，不放宽生产 Host 检查；
该修正的完整 CI 与最终 main CI 仍须通过。
这些组件结果不替代真实 OCI、浏览器或生产验收。
AWS/独立宿主与 RUN-03 继续按[持续进度](m3-progress.md)单独待验收。


补齐完整 HTTP Skill profile 的回归入口：`cargo test --lib plugin_http::tests`、
`cargo test --lib signed_http_skill_stream_and_fixed_methods_execute_with_original_authority_and_accounting`，
以及 `cargo test --test http -- --ignored --nocapture` 的签名真实 OCI 场景。
后者要求隔离宿主与既有真实两镜像准备步骤，不能把默认 ignored 或元数据组件当作 OCI 通过。
