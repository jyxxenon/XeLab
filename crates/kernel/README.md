# XeLab Kernel：M1–M4 与 M5 工作流和同步任务

这是基于现有 **2.8.0 契约**的 Rust 实现，crate 版本为 0.1.0。已实现 M1 普通插件、身份与管理闭环，以及 M2 卷、Blob、Secret、部署备份/恢复、整体离线恢复和内部格式监督器。M3 源码提供普通 OCI Skill 的七项公开操作、声明式 HTTP、OAuth/Client/UI 控制面及独立 WebUI/消息桥；内部 Schema 为 **21**，历史 SQL 及校验和不变。源码功能范围与实际验收状态分别记录：逐项测试、精确提交、PR 集成和 main CI 以有时间戳的[持续进度](../../docs/implementation/m3-progress.md)及[目标 #38](https://github.com/jyxxe/XeLab/issues/38)最新证据为准，不能仅凭实现代码宣布完整 M3 完成。正式生产、AWS/独立宿主和完整格式迁移验收仍独立待完成；公开版本化制品安装入口仍关闭。

## 已实现与边界

| 模块 | 当前实现 | 后续能力与验收边界 |
|---|---|---|
| 元数据 | PostgreSQL 显式追加迁移及校验和、单控制器锁、事务内操作/审计/outbox、原生离线快照及门禁 | 在线升级迁移、多个控制器、自动备份调度；原生快照要求精确版本/布局 |
| 身份与授权 | Owner 引导、五种角色、Guest 自助、固定父级子账户与激活、三种继承模式、不可变权限组/授权、API Key 与会话/密码管理、实时源链撤销、树配额、审计、Cookie CSRF 与可信 Host；恢复后历史用户显式重新激活 | 任务执行复核委托来源链；缓存式授权优化待实现，恢复不复活旧权限 |
| OAuth/UI 控制面 | 精确 Client origin/redirect/规则上限、code + PKCE S256、可信登录/原生同意、短期单次码、刷新轮换/重用撤族、来源绑定 CORS、默认 UI、签名贡献发现及本人偏好；已随 #44 合并 | 独立 OCI WebUI 已通过 #45 精确完整/专项门禁；不代理插件密码或核心 Cookie |
| 制品 | 预导入固定 OCI manifest digest、Ed25519 信封、原始清单/契约摘要及实际内容校验、严格 JSON/Schema 校验、OCI 归档及冷内容库导入 | 在线拉取、image index 自动选平台、仓库登录、依赖安装、卸载；公开非 none 格式安装关闭 |
| 依赖 | `resolveDependencies`、普通插件/能力完整解析、精确契约/安装/配置/代次与特性固定、并发强环/16层图检查、可选降级和升级计划日志 | HostService 已提供固定能力和 Skill 的发现/解析/调用；task 执行依赖 TaskEngine，微/扩展宿主仍未交付 |
| 控制器 | 安装/批准/启用/健康/排空停止、有界对账与重启、完全停用排空后的配置更新、部署重建与同格式卷切换、内部初始化/格式迁移监督器 | 多副本、滚动升级、运行中动态配置；完整格式升级/不兼容回退仍待正式备份验收 |
| 执行 | containerd/runc 真容器、cgroups v2 CPU/内存/PID、只读根目录、受限 tmpfs、无 Linux capabilities、隔离网络、工作负载 mTLS | 外网/代理、尚未实现的 HostService 方法、GPU、微插件/MPR、Extension Plugin；组件预算不代替生产 RUN-03 |
| 调用 | 固定契约/安装/部署、双层授权、共享实例并发、树配额/源链计费、幂等/unknown 账本、有界 SSE 缓冲与取消围栏；普通无版本数据格式 capability 四类副作用的单次/声明流和原实例 QueryResult | #46 精确真实 OCI 副作用/QueryResult 门禁已通过。符合签名范围的一元 Capability Skill 可按实例排队，Batch 和 Schedule 待实现 |
| 事件 | 持久化发布/outbox、24h 去重、独立游标、30s 租约、旧租约 fencing、退避重投/死信、保留和容量上限、SSE/HostService、原生快照及恢复授权重置 | 当前源代码与专项证据见 [M4 事件](../../docs/implementation/m4-events.md)和[#54](https://github.com/jyxxe/XeLab/issues/54)；正式 daemon/独立宿主及 AWS 仍由 #50 跟踪 |
| 工作流定义 | `createWorkflow/getWorkflow/listWorkflows/archiveWorkflow`；同一所有者和名称下递增不可变版本，校验 DAG、输入映射和签名目标，按当前权限分页，使用 ETag 归档 | 归档阻止同一版本的新任务，历史任务继续可读 |
| 任务提交与查询 | `createTask/getTask/listTasks/listTaskSteps`；在一个事务中固定 Workflow 版本、deadline、执行权限上限、授权来源和需要固定的提供者，初始化步骤状态 | 服务身份执行需单独审批。HTTP 与真实 PostgreSQL 回归见 `crates/kernel/tests/workflows.rs` |
| 同步 TaskEngine | 控制器以 PostgreSQL 租约领取能力契约型或固定 HTTP 同步 Skill，经 Broker 准入、计费及调用，原子记录 Attempt 与 Call；结果提交检查 fence 并推进下游与 outbox | Task 步骤采用单次调用；任务级 HostService 附属授权、Blob 大结果与长任务 TaskWorker 待实现 |
| Task 期限对账 | 控制器定期回收过期租约，并独立于同步调用处理已到整体期限、无活动或待核实步骤的 Task | Task 记录 `DEADLINE_EXCEEDED`，保留既有步骤输出、Attempt 和 Call |
| UNKNOWN 核实 | `resolveUnknownStep` 在当前授权与步骤 ETag 下核对已成功结算的关联 Call，或核实尚未越过持久化派发屏障的已释放 Call | 记录操作者和证据，推进步骤 fence。旧账本缺少标记、可能已经发送的 Call 继续按未知结果处理 |
| Task 显式重试 | `retryTask` 复核原授权、依赖、整体期限与次数上限，对已证明未派发的失败步骤重新排队 | 保留原 Attempt 和业务幂等键，下一次领取推进 fence |
| Task 取消 | `cancelTask` 停止领取与准入，记录取消意图，沿关联 Call 账本处理仍在途的调用 | 等待 Controller 确认物理停止并释放预留，再将 Task 置为 `canceled`。保留已确认结果与仍未知的步骤 |
| HTTP | #43 已合并签名原始 OpenAPI、精确操作/动作/Schema、共享 Broker 账本、直接 HTTP SSE、隔离来源静态 GET/HEAD 与物理槽；#47 扩展固定 HTTP Skill 的六方法、成功状态和 SSE | #47 精确 HTTP Skill 六方法/流真实 OCI 门禁已通过；不是任意 URL/路径模板/查询参数代理，未声明协议拒绝 |
| 独立 WebUI/消息桥 | #45 实现 UID 65532 OCI 桌面、公开管理 API/OAuth 客户端、window/widget、固定 alias 的 skill.call、同部署 window.open、通道撤权/登出/升级失效及独立 UI 参考插件 | 组件与打包探针通过不能替代真实核心 OCI/Owner OAuth/iframe 全链；#45 精确完整/专项门禁均通过，未来 batch 方法明确不可用 |
| 持久卷 | 独立 XFS 硬配额、预留/扩容/回收、实际计数、单写者 fence、OCI 挂载、新私有卷恢复、同格式克隆/回退、内部格式证明 | 多副本应用行为、公开格式安装/迁移、正式独立宿主恢复验收 |
| Blob | 不可变上传/下载、摘要/长度校验、pin/TTL、可恢复清理、HTTPS CLI、受限工作负载 RPC、整体离线备份/恢复 | 自动备份调度、正式 AWS/独立宿主演练 |
| Secret | AES-256-GCM 托管、元数据 API、轮换/撤销、部署绑定、工作负载 mTLS 租约；恢复后旧 Secret/绑定撤销 | 主密钥轮换；恢复后需显式重建所需秘密及授权 |
| 备份/恢复 | 部署一致性备份、新卷恢复/切换、整体离线源冻结、元数据/Blob/镜像/卷重建、权限重置、持久检查点与中断续作、格式备份登记 | 自动备份调度、正式 AWS/独立宿主恢复、不同格式升级/不兼容回退的完整正式演练；兼容对象存储始终 off_host=false |
| 运维 | HTTPS 管理 API、独立 CLI、WebUI 配置/默认界面及停用恢复、离线备份/恢复与账户维护命令、探针、结构化错误日志、数据库审计、故障恢复测试 | UDS 控制通道、指标/Tracing 导出、自动备份、数据与 AI 平台；独立 WebUI 的精确整体门禁见持续进度 |

当前公开安装 profile 接受单副本、普通依赖、无扩展点且 data_schema_version 为 none 的普通插件；宿主权限申请包括显式签名/审批的能力、Skill、事件及 Blob 代理动作，必需代理规则须完整批准，可选 secret.use 保留原约束。事件阶段接通公开订阅/发布/确认及 HostService 事件 RPC。允许受控持久卷、签名 capability/HTTP Skill 候选、经验证的 http/static/webui 路由及固定 WebUI/UI Contribution 声明；页面必须有独立来源和对应签名准入，不因 UI 存在而授予业务权限。内部版本化格式的初始化、同格式切换和 Plan/Apply/Verify 见[格式监督器](../../docs/implementation/m2-format-transitions.md)；内部实现不等于公开准入或正式验收。业务 Schema 必须自包含，拒绝 $ref/$id 等引用。业务等待槽和期限由符合条件的签名清单限定。零等待槽的实例在活动槽满后立即拒绝新请求。见 [Skill 准入与撤权](../../docs/implementation/m3-skills.md)。

`registerSkill/getSkill/listSkills/setSkillEnabled/archiveSkill/invokeSkill/streamSkill` 固定安装、不可变定义与 UUID，复用 Broker 并发、配额、来源链和 unknown 围栏。普通 capability 的 `none/idempotent/queryable/non_repeatable` 均支持首次单次和已声明流；从不自动重派业务。queryable 的 getCall 仅向原实例/代次发送 QueryResult，复核原来源，不切换提供者或重新 Invoke。内部版本化数据 profile 仍保留既有 none/idempotent 限制，公开版本化制品门禁关闭。HTTP Skill 固定签名 GET/HEAD/POST/PUT/PATCH/DELETE、声明成功状态和 Schema；无正文/204/HEAD 使用契约允许的 null，声明流接入已有 Skill SSE，不能由输入选 URL/方法。两类扩展已通过 #46/#47 精确真实 OCI 门禁，主线最终验收状态见持续进度与目标 #38。M4 HostService 已接入 Skill 发现/解析/检查/单次及流式调用，并复用原 Broker 资源和来源链；详见 [HostService](../../docs/implementation/m4-host.md)。边界和命令见 [Skill](../../docs/implementation/m3-skills.md)、[流式调用](../../docs/implementation/m3-skill-streams.md)、[HTTP](../../docs/implementation/m3-http.md)和[WebUI 整体门禁](../../docs/implementation/m3-webui.md)。

M4 第一阶段新增普通依赖清单准入、固定部署绑定、请求范围路由基础和失败策略；启用会重新核对真实提供者，物理停止前不释放资源预留。绑定不是授权，实际调用继续检查当前调用者与完整来源链。实现和验证范围见 [依赖说明](../../docs/implementation/m4-dependencies.md)与[目标 #51](https://github.com/jyxxe/XeLab/issues/51)。

事件公开操作为 `publishEvent/listSubscriptions/createSubscription/getSubscription/deleteSubscription/streamDeliveries/ackDelivery`；
HostService 接通 `PublishEvent/Subscribe/AckEvent`。主题是全局命名空间，必须显式 ids/all 授权，
owned_by 不匹配；订阅另校验 owner。新凭证按当前权限续用持久游标，创建凭证仅供审计。
事件至少一次投递，消费者仍须去重；不可把确认成功当成外部业务副作用的恰好一次保证。

配置仍使用现有 `kernel.toml`；`unix_socket` 暂未提供控制服务。`ui_gateway` 提供精确部署来源的静态/WebUI 代理，未配置时不降级到可信内核同源页面。WebUI 需先创建 disabled 部署、取得隔离来源、注册精确 Client、以完整 `{spec}` 更新配置并轮询 202 Operation，审批/启用至 Ready 后再设默认界面；根路径不可用返回 503，核心 API/CLI 独立。部署步骤和同一 TLS listener 的通配域名配置见[WebUI 说明](../../examples/webui/DEPLOYMENT.md)。备份 URI 的标准 AWS 后端还需独立凭证、主密钥及仓库注册，见 [备份任务](../../docs/implementation/m2-backup-jobs.md)。

工作负载 Blob 代理、显式批准与固定输入白名单见 [M2 Host Blob](../../docs/implementation/m2-host-blobs.md)。

## 构建与主机要求

```bash
cargo build --workspace --locked
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

生成 `xelabd`、`xelabctl` 和参考插件 `xelab-echo`。Proto 直接由仓库原文件生成，构建工具内置 protoc；没有另写一套 RPC 定义。提交的 Cargo.lock 固定依赖解析结果。

运行需要独占的 Linux 节点、cgroups v2（cpu/memory/pids）、containerd/runc、`ctr`、`ip`、`nft` 和本机 PostgreSQL。守护进程以 root 运行以管理 OCI、网络和 cgroup；插件 UID/GID 为 65532，不获得宿主权限。本阶段仅接受 Unix socket 或数字回环地址连接 PostgreSQL。

必须满足：

- 默认 `resources.profile = "standard"`（省略同义）：内核预留至少 **4000 mCPU / 16 GiB**，系统另算。原示例预留 2 CPU / 4 GiB，宿主高于 6 CPU / 20 GiB 才有插件资源。
- 显式 `compact` 目标为 **1 vCPU / 512MiB 整机**，内核最低 500m/192MiB、系统最低 250m/256MiB；实际有效内存至少 480MiB，插件仅使用扣除后的真实余量。以小规模 API/CLI 为基线；现有 WebUI/AI/MPR 资源不自动缩减。配置、限制与尚待执行的整机稳定性验收见 [compact 节点](../../docs/implementation/compact-node.md)。
- 使用独立 containerd namespace、独立且不与宿主路由冲突的 IPv4 CIDR（/16～/28）。
- 本版采用 `/sys/fs/cgroup/xelab`。不要在已有其他管理器使用该路径的共享宿主上运行。
- HTTPS 服务证书须匹配 `public_origin`；工作负载 CA 使用独立的 EC P-256 证书及 PKCS#8 私钥。工作负载证书有效期 1 小时，约 30 分钟更新；插件须重新加载证书，参考插件每 5 分钟重建监听。
- DSN、HMAC key、master key、TLS/CA 私钥文件仅属运行用户，普通文件、无符号链接/硬链接、权限不宽于 0600。HMAC key 至少 32 字节，master key 恰好 32 字节。原始凭证不写日志或元数据。

从 [配置示例](../../docs/contracts/examples/kernel.toml) 复制到宿主配置目录，填写实际地址及秘密文件路径。用 `openssl rand -out <file> 32` 在 `umask 077` 下生成随机密钥；密码通过 stdin 输入，不放进命令行。

```bash
xelabctl validate-config --config /etc/xelab/kernel.toml
xelabctl migrate --config /etc/xelab/kernel.toml --target 25
xelabctl bootstrap --config /etc/xelab/kernel.toml --owner-name admin
xelabd --config /etc/xelab/kernel.toml
```

`validate-config` 检查配置结构和本地约束。当前迁移目标为 25。
迁移会先为空库建立原始基线。已有库先检查已应用的版本和校验和，再顺序执行追加迁移。
重复执行仍核对布局与校验和。v20 新增任务准入证明，v21 新增 Attempt 与 Broker Call 的关联，v22 为任务期限和活动租约增加索引，v23 保存任务核实证据，v24 为待收敛取消任务增加索引，v25 保存派发和重试证据。旧版本离线快照须先在对应版本恢复并迁移，再重新导出。bootstrap 只允许空账户库，须在启动守护进程前执行。
守护进程不会隐式迁移数据库。

## 管理与插件示例

CLI 的 `api` 子命令从原 OpenAPI 读取 operationId、路径及方法。所有服务请求使用 HTTPS；自签测试服务证书可以用 `--ca-file` 指定，不提供跳过校验选项。JSON 输出到 stdout，错误摘要到 stderr。

```bash
xelabctl api login --endpoint https://kernel.example.org:8443 \
  --body-file login.json --ca-file server.crt
xelabctl api getNode --endpoint https://kernel.example.org:8443 \
  --token-file session.token --ca-file server.crt
```

`login.json` 为 `{"account_id":"<bootstrap 输出的 UUID>","password":"<密码>"}`，按秘密文件保护。将首次返回的 `access_token` 保存到当前用户拥有的 0600 token 文件；不要把 token 放进仓库。会话有效期 1 小时，登录和会话撤销均记录审计。

制作参考插件的顺序：

1. 生成发布者 Ed25519 密钥，将公钥通过 `trustPublisher` 登记，取得 `publisher_id`。
2. 生成清单和四个契约文件；先 `cargo build --bin xelab-echo --locked`，再构建镜像。示例 Dockerfile 用于 Ubuntu 24.04/同架构构建产物，Docker 只用于示例镜像打包，内核运行不依赖 Docker。
3. 管理员将镜像导入配置指定的 containerd namespace，取得**平台对应的 image manifest** 摘要（不是多平台 index 摘要），再给该镜像添加包含 `@sha256:...` 的不可变名称。
4. 对已确定的镜像摘要和原始清单签名，提交 `installPlugin`。安装成功不自动启用。

```bash
python3 examples/echo/build_artifact.py --publisher-id <publisher-uuid>
docker build -t docker.io/local/xelab-echo:1.0.0 -f examples/echo/Dockerfile .
docker save docker.io/local/xelab-echo:1.0.0 -o examples/generated/echo.tar
sudo ctr -n xelab images import examples/generated/echo.tar
sudo ctr -n xelab images list
sudo ctr -n xelab images tag docker.io/local/xelab-echo:1.0.0 \
  docker.io/local/xelab-echo@sha256:<manifest-digest>
python3 examples/echo/sign_artifact.py \
  --manifest examples/generated/xelab/plugin.json \
  --image docker.io/local/xelab-echo@sha256:<manifest-digest> \
  --key publisher.key > install.json
```

之后按以下顺序调用，JSON 模型仍以原契约为准：

| operationId | 请求/检查 |
|---|---|
| `installPlugin` | `install.json`；轮询 `getOperation`，获得 installation_id |
| `createDeployment` | installation_id、display_name、enabled=false、limits、config={}、volume_ids=[]；返回 operation |
| `approvePlugin` | deployment_id 路径；`{"rules":[],"egress":[]}`，必须传当前 If-Match |
| `setDeploymentEnabled` | `{"enabled":true}`，使用更新后的 revision；轮询 operation 至成功 |
| `invokeCapability` | 清单中的完整 contract、`input:{"message":"hello"}`、可选 provider_deployment_id |
| `getCall` | 用调用结果或错误的 resource_id 查询，unknown 不能当作成功或自动重试 |
| `setDeploymentEnabled` | `{"enabled":false}`；operation 成功时容器已经停止且资源已释放 |

路径参数使用 `--path deployment_id=<uuid>`；版本条件示例为 `--if-match '"rev-2"'`。每次读资源取当前 revision，不猜版本。写请求建议显式提供 `--idempotency-key <uuid>` 并保留，网络重试复用同一 key；相同 key、不同请求返回冲突。CLI 未传时生成新 key，因此重新运行命令不等于重放原请求。

普通插件、节点与探针可用 HTTP 操作：

`getLiveness`、`getReadiness`、`login`、`revokeSession`、`getNode`、`trustPublisher`、`getPublisher`、`revokePublisher`、`installPlugin`、`getInstallation`、`createDeployment`、`getDeployment`、`approvePlugin`、`getPluginApproval`、`setDeploymentEnabled`、`getInstance`、`getOperation`、`invokeCapability`、`getCall`。

身份可用操作按既有 operationId 分组：

| 对象 | 操作 |
|---|---|
| 账户 | `listAccounts`、`getAccount`、`updateAccount`、`archiveAccount`、`createChildAccount`、`activateAccount`、`changePassword`、`updateInheritance`、`getEffectivePermissions` |
| 权限 | `listRoles`、`listPermissions`、`listGroups`、`createGroup`、`getGroup`、`archiveGroup`、`publishGroupVersion`、`getGroupVersion`、`listGrants`、`createGrant`、`getGrant`、`revokeGrant`、`checkAuthorization` |
| 凭证 | `listApiKeys`、`createApiKey`、`getApiKey`、`revokeApiKey`、`rotateApiKey`、`listSessions`、`revokeSession` |
| 配额/审计 | `getQuota`、`updateQuota`、`listAuditEvents` |

身份操作也通过 `xelabctl api <operationId>` 调用。`createChildAccount` 在 `--path account_id=<parent>` 下提交 `{"display_name":"child","inheritance":{"mode":"all_snapshot"}}`，首次返回待激活账户及 24 小时激活令牌；`activateAccount` 提交该令牌与新密码。服务账户不签发交互密码。归档保留原父级，不能迁移账户树。

`createApiKey` 使用 `--path account_id=<owner>`，例如 `{"name":"echo only","inheritance":{"mode":"selected","rules":[{"action":"capability.invoke","resource":{"kind":"capability","match":"ids","ids":["org.xelab.echo@1.0.0"]}}]},"conditions":{"expires_at":"<未来 RFC3339 时间>","max_calls":100}}`。签发者须已有对应能力权限。返回 `credential` 元数据与只出现一次的 `secret`；同幂等键重放返回 409 和已有资源 ID，不再次泄露秘密。激活令牌和 API Key 原文均不落库。

独立 Python 插件见 [echo-python](../../examples/echo-python/README.md)：仅使用现有 Proto 生成代码，与 Rust 插件复用完全相同的契约文件和摘要，使用不同镜像/安装/部署，经同一管理 API 接入。

## 恢复与安全语义

- 准入在事务中锁定节点预算，实例与 reservation 唯一关联；重复准入不重复扣账。只有运行时确认 task 和 cgroup 中进程已消失，才允许释放账本。
- 每次守护进程重启先撤出路由并停止旧 namespace 中的容器，再将未确认调用标记 unknown、归还并发配额、按原意图重新启动。实例资源预约保持不变，避免重启超售。这意味着当前版本的内核重启会中断插件服务。
- 安装异步执行前和提交时重新检查会话、发布者信任与安装权限。调用前和返回结果前都检查当前授权；RPC 委派绑定实际实例/代次/原调用，HostService 业务代理另需签名声明及当前批准上限，插件身份本身不授予用户业务权限。
- API Key 及子账户使用实时来源图：同一授权路径上的父级/凭证/固定上限取交集，独立有效来源取并集。快照持久保存真实来源 grant，后来新增权限不会扩张快照，替代 grant 不会复活已撤销来源。权限组仅为不可变模板，读取或引用模板不产生权限。
- 身份写入持独占授权事务锁，认证与调用准入/结果提交持共享锁；不跨请求或事务复用授权证明。同一授权事务内的证明复用仍核验来源当前到期时间，撤权后新准入和结果交付重新判定。最后一个有效独立 Owner 不能被禁用、归档或撤成不完整权限。
- 子账户数、层级、API Key、日调用和并发调用按祖先链约束；密钥派生分支共享来源密钥的累计调用预算。调用超时/返回未知或 HTTP 处理任务丢失时，控制器先撤路由、确认旧进程终止，再归还并发配额并重建原实例。
- 浏览器会话 Cookie 为 `Secure`、`HttpOnly`、`SameSite=Lax`、`__Host-` 前缀；本分支的敏感 Cookie 请求要求精确 Origin 及会话绑定 X-CSRF-Token。只有可信登录/激活可设置登录 Cookie；新密码认证不依赖旧 Cookie 的有效性。CLI 使用 Bearer。密码修改撤销交互会话，不撤销独立 API Key。
- 丢失 PostgreSQL 控制器锁连接后停止接收业务写入/调用；结果写回带状态条件，不把恢复后被废止的调用写成成功。
- 停用先撤路由，再发送 Drain；超时后强制停止。存活探针使用清单期限与失败阈值，启动失败使用有限次数及退避，需人工停用/启用开始新代次。
- 容器不得访问宿主业务 API、其他插件或外网；内核发起的连接可以接收响应。配置、密钥及 Docker/containerd socket 不挂入插件。制品签名不替代沙箱。
- 发布者撤销阻止新安装及依赖当前发布者信任的 Skill/HTTP 路由；不自动删除已安装制品。普通直接 capability 仍保留既有部署信任语义；需要停止部署时显式停用。

## 验证和发布门槛

默认测试包括严格 JSON、Schema、配置/秘密文件、权限条件交集、制品路径/信封、OCI 隔离参数，以及真实 PostgreSQL 的 AUTH-01～09、会话撤销、重复迁移、并发准入、防超售和幂等释放。设置 `XELAB_TEST_DATABASE_URL` 后运行数据库测试；测试 DSN 须有创建一次性数据库的权限。未设置时，部分用例提前返回，Cargo 仍计为 `ok`；默认输出会捕获部分用例的跳过提示，另有用例不打印提示。向上述 `cargo test` 命令追加 `-- --nocapture` 能显示已有提示，但不能证明所有数据库用例都已执行；须记录 DSN 与实际测试范围，不能据此宣称数据库验证完成。

CI 另在一次性 Linux 主机运行 `tests/oci.rs`：真实 containerd + Rust/Python 两个 OCI 镜像 + cgroup + mTLS，经管理 Router 完成安装、批准、启用、调用、幂等重放/冲突、两处恢复注入、调用配额回收、停用及撤权；实际执行 CPU 压力、内存 OOM、只读根目录/出网拒绝，并以真实 HTTPS 服务运行 `xelabctl`。错误签名、错误实例代次证书和过期版本条件须被拒绝。该测试需显式 `XELAB_OCI_TEST=1`，默认忽略，**只允许在可销毁测试主机上手动运行**；命令见 [CI](../../.github/workflows/kernel.yml)。

现有托管 OCI 组件测试使用小的实际容器 cgroup 和独立测试数据库中的合成 standard 节点预算；生产 `xelabd` 按显式 profile 验证真实容量。它验证真实插件执行、HTTPS/CLI 和控制面逻辑，不等价于 standard 的 4C16G 保留量验收，也不等价于 compact 的 1C512MiB 整机长测或灾备验收。

独立 WebUI 整体门禁包含实际浏览器/OCI、两实例真实 CPU/内存/PID cgroup 读数、撤权账本、停用后 CLI 与同进程核心组件重启；尚未通过不能当作 daemon 重执行或独立宿主恢复证据。真实 AWS 按维护者指令 DEFERRED；正式 RUN-03、独立宿主及完整格式迁移验收保留工具和门禁，不能用合成预算代替。身份求值和全局授权写锁优先保证正确性，大账户树下的吞吐须实测再优化。



## PR #3 审查修复

- 调用准入在授权/调用事务锁内选择一个可用的真实来源路径，将请求凭证链与该路径全部 Grant 的来源凭证链合并检查 `max_calls`。独立来源取并集；耗尽的 Key 不阻断其他合法来源。`call_credential_charges` 与 Call 原子写入，幂等成功重放不重复计费，撤销 Grant/Key 不退还已用额度。轮换仍扣除已使用预算。
- 自授 Grant 证明签发权限时，忽略同账户其他非引导自授绑定，只使用独立来源（外部 Grant、父级继承或初始 Owner）。这些自授绑定仍在最外层保留权限/来源记录；撤销独立来源后不能互相维持权限。此优化针对同账户自授，其他来源图仍受现有深度/路径边界限制。
- 控制器启用与停用清理分别保存 `(created_at,id)` 游标与上界，每轮各最多 16 项，并在项间检查 250 ms 时间片。Probe 按实例代次复用、分批回收；已清理禁用记录不反复协调。完整行为、回归与单项延迟限制见 [Controller 稳定化](../../docs/implementation/m1-acceptance.md#controller-稳定化pr-4-遗留项)。

升级前备份并停机，确认没有未完成任务，执行上面的 `--target 25` 后再启动。
旧二进制拒绝不匹配的元数据版本，不能直接回退；原生快照恢复同样要求精确布局。
v1 已有的凭证/账户派生调用继续计入预算；旧版本未记录的实际 Grant 来源无法事后精确重建，因此已有受此漏洞影响的限次来源 Key 应在升级时撤销后重新签发，不把旧账本当成完整历史计费证据。v7 持久备份任务见 [备份任务记录](../../docs/implementation/m2-backup-jobs.md)，v8 新卷恢复和切换见 [恢复实现](../../docs/implementation/m2-restores.md)，v9 元数据快照、启动门禁与权限重置见 [离线恢复组件](../../docs/implementation/m2-platform-recovery.md)。
v10–11 部署重建与卷克隆见[部署重建实现](../../docs/implementation/m2-deployment-upgrades.md)，
v12 格式初始化见[初始化监督器](../../docs/implementation/m2-schema-bootstrap.md)，
v13 格式备份登记见[登记组件](../../docs/implementation/m2-format-backups.md)。
v14 为恢复后的历史用户提供[维护窗口重新激活](../../docs/implementation/m2-recovered-accounts.md)，
需要实际宿主 root、当前恢复 Owner 凭证和明确的目标修订；不恢复旧授权。
v15 保存[原始 HTTP 契约与调用绑定](../../docs/implementation/m3-http-provenance.md)，v16 保存[OAuth/UI 状态](../../docs/implementation/m3-oauth-ui.md)；恢复仍撤销旧凭证、Client 和信任，历史记录不能复活权限。
v17 保存[依赖固定绑定和升级计划](../../docs/implementation/m4-dependencies.md)，不改变既有权限快照。
v18 保存[HostService 原调用与独立来源上限](../../docs/implementation/m4-host.md)，v19 保存[事件、订阅和租约](../../docs/implementation/m4-events.md)。
离线恢复保留事件/outbox/死信历史，但停用全部旧订阅并围栏旧租约，不恢复历史调用或临时句柄权限。
已验证的业务格式可随认证数据进行[整体备份/恢复](../../docs/implementation/m2-platform-formats.md)，保留逻辑卷和历史格式绑定；恢复仍禁用部署并撤销旧信任，不自动迁移或重新授权。
内部[格式变更执行器](../../docs/implementation/m2-format-transitions.md)已经接通，
正式备份下的完整迁移与故障验收尚未完成，公开版本化制品安装入口仍关闭。

## M2 存储后端预检

`xelabctl storage-check --config /etc/xelab/kernel.toml` 只读验证平台卷目录的
XFS project quota 强制执行条件。后端创建/扩容原语和真实文件系统测试见
[M2-A 操作说明](../../docs/implementation/m2-storage.md)。公开 Volume API、
异步恢复、挂载与内部 v5 迁移见 [M2 卷实现](../../docs/implementation/m2-volumes.md)；
仅通过 capability 预检不代表整个卷服务已就绪。
启动 readiness 等待 active/inactive 两条队列各自完成首轮固定水位扫描；
首批成功不表示恢复完成。全局旧进程围栏完成后不因后续批次错误重复执行。

Blob 的接口、容量边界、清理与 v4 升级说明见 [M2 Blob 实现记录](../../docs/implementation/m2-blobs.md)。
