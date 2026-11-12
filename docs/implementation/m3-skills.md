# M3 Skill 注册与普通 OCI 调用


> 2026-11-09 验收补记：M3 功能提交 #45/#46/#47 的精确完整与专项 CI 已全部通过。下文保留相应切片开发时的命令、历史状态和证据边界；当前验收表与精确 head/tree/CI 见 [当前验收记录](m3-acceptance-20261109.md)，最终集成与 main CI 见 [目标 #38](https://github.com/jyxxe/XeLab/issues/38)。历史“待验收”表述不得替代该最新记录，组件通过也不替代真实 OCI 或正式生产验收。
[实施索引](README.md) · [持续目标与验收清单](m3-progress.md) · [Skill 契约](../skills/README.md)

本页记录 M3-A 的已合并注册/纯调用切片与开发分支中的普通副作用扩展。
普通四类副作用及 QueryResult 的新真实 OCI 门禁仍待执行，不能据此声明 M3 已完成。
实现复用现有 PostgreSQL、Identity/Authorizer、Broker、Controller、Runtime 和 mTLS；
该子集首次交付使用 Schema 14；后续 [HTTP 集成](m3-http-provenance.md)追加至 Schema 15，
不修改已发布 SQL 或迁移校验和。

## 实际操作与边界

| operationId | 本次实现 |
|---|---|
| `registerSkill` | 从明确 installation_id 的已验证清单候选注册不可变定义，默认禁用 |
| `getSkill`、`listSkills` | 按当前对象读取权限返回定义与实时可用性；列表使用身份绑定的有期限签名游标 |
| `setSkillEnabled` | If-Match 乐观锁启停；重新启用复核候选和来源，归档后不能恢复 |
| `archiveSkill` | 逻辑归档、禁止新路由、保留历史定义，返回 204 |
| `invokeSkill` | 普通 capability 目标的非流式调用，通过 Broker 发送至固定安装的真实 OCI 实例 |
| `streamSkill` | 后续切片实现普通 OCI 声明流；准确边界与待验收证据见[流式调用](m3-skill-streams.md) |

HTTP 目标见独立 HTTP 实现；HostService 的 Skill 方法已接入 [M4 代理](m4-host.md)。
micro、extension 和异步任务排队仍未交付。
`HostService.ListSkillCandidates/ResolveSkill/CheckSkillAccess/InvokeSkill/InvokeSkillStream`
均使用实际 mTLS 实例、原 Call 及当前授权来源，不接受插件自报内部路由上下文。
本次不新增 BatchEngine、Workflow、MPR 或 Extension 执行系统。
普通无版本数据格式的 capability 支持 `none`、`idempotent`、`queryable` 和 `non_repeatable`，
声明了匹配流 Schema 时同样可使用流。副作用分类控制重试/核实，不能用来拒绝首次执行。
同步 Broker 不自动重发任何业务请求，不能因制品声明 idempotent 就推定未验证持久写入可重试；
内部格式化数据 profile 仍只允许原已验证的 none/idempotent，
公开版本化数据制品安装门禁继续关闭。

## 注册与不可变来源

普通签名 OCI 清单可以声明经过验证的 `skills[]` 候选及 `skill_required` 入口。
每个候选的 name 必须处于 `plugin_id.` 命名空间，目标 plugin_id、完整 ContractRef、
输入/输出/流式 Schema 必须与该清单 capability 精确一致。
候选中不得出现任意目标 URL、实例地址或其他目标种类字段。
所有业务 Schema 使用现有自包含 profile，拒绝 `$ref/$dynamicRef/$recursiveRef/$id`，
不会联网解析或读取宿主文件。

安装时沿用原始清单字节、固定镜像摘要及 Ed25519 签名验证。
注册读取仅能由已验证安装流程写入的 installation 记录，要求当前已安装、发布者仍可信，
并要求请求定义与签名清单候选逐字段相同、数据库契约摘要和 Schema 一致。
注册本身不重新挂载镜像或重新验证原始签名，不将解析后的 JSON 重新序列化冒充原始签名字节。
这里复用现有安装记录的可信边界；未来若增加离线篡改恢复等来源要求，必须同时增加可验证证据。

Skill UUID、name/version、安装 UUID、定义及 definition_digest 均不会原地修改。
摘要使用 RFC 8785 的 UTF-16 属性顺序、ECMAScript 数字格式及 SHA-256。
当前定义数字 profile 拒绝超出 ±(2^53−1) 的整数，以避免不同精确整数在 IEEE-754 转换后产生歧义；
需要更大精度的 Schema 常量应先采用明确的字符串业务表示或后续一致性扩展。
同 name/version 的其他定义或安装返回 CONTRACT_CONFLICT；重复注册不改变所有者、启停或归档状态。
管理动作检查 `skill.register` 及真实来源 plugin 的 `plugin.install`；
启用与归档分别检查 `skill.enable`、`skill.archive`。注册不会授予调用权限。

## 调用、撤权与资源

外部只提交 Skill UUID、业务 input、受上限约束的 timeout_ms 和幂等键。
Broker 在同一准入事务读取固定 Skill，要求 `skill.invoke` 和目标 `capability.invoke` 同时成立，
保留账户祖先、源凭证和条件交集；两层授权来源均进入同一 Call 的来源计费记录。
每次根调用仍只扣一次账户日额度，并与直接 capability 调用共享实例并发池。
只选择该 installation 的就绪健康实例，不按名称选择其他安装或最新版本。
Call 持久保存 Skill UUID/摘要，RPC 委托仍固定实例、generation、主体、凭证和期限。
冻结的业务来源只保留已进入该 Call 计费记录的凭证证明；未计费的耗尽来源不能维持在途工作。
输入和输出复用固定业务 Schema 校验。请求整体超时覆盖数据库锁等待；
准入事务取消即回滚，派发后取消保留 Call/reservation，交由控制器确认进程终止后回收。
请求使用独立的有界数据库连接；取消会先取消该后端查询再关闭协议驱动，服务端 statement timeout 作为后备，
不能仅丢弃 Rust future 而留下锁等待。准入提交后释放空闲连接，不跨插件 RPC 持有数据库后端。

只声明一元 Capability Skill、要求经 Skill 调用且无路由的签名制品可配置业务等待队列。
各主体和 Skill 按已选实例及代次共享等待槽，并按入队顺序取得活动槽。等待期间释放数据库事务；
取得活动槽后复核固定制品、健康状态、原授权来源和输入 Blob，提交 Call、委托和额度后才派发。
满队列返回 `RESOURCE_EXHAUSTED`，等待期限取签名队列期限和原调用期限的较早值，到期返回
`DEADLINE_EXCEEDED`。请求断开、审批失效、禁用或换代会清除等待项。队列随内核进程退出回收，
客户端可以用原幂等键重试排队中断的请求。

禁用/归档和来源撤权会阻止新调用；在途 Skill 调用定期复核当前来源、双层授权及部署，
结果提交前再次复核。失效时放弃响应并撤销委托，保留结果未知的调用记录。
丢弃 RPC future 不证明插件已停止执行：超时/错误的活动预约继续保留，
只有现有 Controller 确认实例进程停止后才归还并发额度，不能提前释放导致超售。
同 HTTP 幂等键的未知结果不重新发送；成功重放仍重新鉴权，不再次扣账。
请求体的稳定业务 `idempotency_key` 独立于 HTTP 重放键，原样传入 RPC 并记录在 Call；省略时取 HTTP 键。
停止、重启后的新实例可以继续提供同一固定安装，不能修改历史 Skill 或把未知副作用当作成功。

## 已提交结果的核实

对于 `queryable` 的 unknown Call，`getCall` 在有权限时调用原物理实例/generation 的真实
`CapabilityService.QueryResult`，携带持久原 Call ID/业务幂等键，不调用 Invoke、不选择新提供者。
核实要求 capability.call.read、原业务/Skill 权限、原主体/凭证/Origin 和已计费冻结来源仍成立。
RPC 上限为原 deadline 剩余与 2 秒的更小值；无锁网络阶段前后分别校验授权及固定绑定。
查询使用无 HostService 权限的短期委托，不覆盖原调用委托，不新增业务 Call 或日额度。

SUCCEEDED 必须带匹配 call ID、摘要及固定 capability/Skill output Schema 的 completed；
FAILED 必须带合法 failed；其余未确定状态不得带伪造结果。记录缺失、RPC 中断、错误配对、
实例 generation 已更换或原 deadline 已到均保持 unknown，绝不推断“尚未执行”或重发副作用。
只有确认结果可结算原预约；仍未知的 non_repeatable 工作保留物理槽，等 Controller 实际围栏。
getCall 不重建或拼接断开的业务流，M5 的自动任务恢复不在本切片内。

## 离线备份与恢复

普通 capability Skill 不再触发旧的“任何 Skill 均拒绝快照”门禁；源冻结及元数据导入均核对
不可变 UUID、名称/版本/摘要、OCI 安装身份、签名候选和契约 Schema，拒绝损坏或未来目标。
Call 历史校验固定 Skill UUID/摘要/契约；部署可能已升级，不能把部署当前安装误当作历史提供者证据。
恢复保留定义与管理意图，但原凭证、授权、发布者信任和部署启用状态仍按既有恢复流程撤销。
保留历史不是取得新的路由资格；MPR/Extension/Workflow 等未来快照门禁继续关闭。

## 测试入口与证据边界

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo test -p xelab-kernel --lib skills::tests -- --nocapture
python3 docs/tools/validate_docs.py --strict
```

PostgreSQL 测试需显式设置隔离的 `XELAB_TEST_DATABASE_URL`。
`actual_postgres_registry_disable_restore_conflict_and_archive` 验证真实注册持久状态、
启停恢复、相同版本冲突、发布者撤销、列表与归档；该测试没有 OCI 提供者，不声称执行业务。
候选单元测试覆盖命名空间、目标与 Schema 不一致、外部引用、重复版本、伪造 URL，
并使用非 BMP 属性名及浮点格式检查摘要规范化。
独立 API 测试和现有 OCI 组件测试须另行运行并保存真实结果；参考制品构建器将候选纳入签名清单。

[PR #39](https://github.com/jyxxe/XeLab/pull/39) 已作为首个非流式实现切片合并至 main
`136cb02b503be9e7e2e5c49007dc609199cddc15`。精确提交 `7ab2f0e…` 的
[完整 Kernel M1 CI](https://github.com/jyxxe/XeLab/actions/runs/41804075279) 已成功，
包含 PostgreSQL、真实 OCI、离线恢复及适用回归；合并后的 main CI 仍须独立确认。
本地 `/tmp` 的 xattr 列表不一致使部分既有归档测试按 fail-closed 拒绝；不放松验证来掩盖环境错误。
最终通过结论以对应 PR 的精确提交、CI 日志及实际组件结果为准，不能将测试入口存在算作通过。
AWS 与独立宿主正式验收继续按[持续目标](m3-progress.md)标为 DEFERRED；
它们不阻断本功能开发，也不被计入当前已执行证据。

普通副作用开发分支的入口为 `actual_postgres_stateless_effects_never_replay_uncertain_dispatch`、
QueryResult 的真实 mTLS/原来源专项，以及 `tests/support/ordinary_effects.rs` 的签名 OCI 场景。
后者检查三类非纯 unary/stream 成功、核心缓存重放、已提交但丢响应后的原提供者核实、
非可重复 unknown、原进程围栏和重启后账本；代码/编译存在不表示真实 OCI 已通过。

本地普通副作用专项已实际执行：6 项 Artifact（含四类流与公开版本数据门禁）、
3 项 PostgreSQL Broker 测试（其中 stateless 测试逐一覆盖三类非纯效果），
以及 4 项 QueryResult 检查（含真实 PostgreSQL/Tonic mTLS、查询中撤权及原来源拒绝）通过。
QueryResult 首次组件运行因测试误用生产 workload chown 在非 root 环境失败；
修正为与已有 mTLS 测试相同的短期精确 DNS/SPIFFE 证书后重测通过，生产 TLS 未改。
独立宿主 OCI 场景仍须在最终精确提交实际运行，不把这些局部通过当作完整验收。

新增 raw queryable 的真实 PostgreSQL COPY 回归也已通过：调用由实际 Broker 准入为 unknown，
skill_id/http_binding 为空的原来源/Origin 与单独空权限查询委托经过导出、约束验证、导入和追加
迁移重复检查；原 Call/委托 UUID 与 JCS 来源摘要保持一致，恢复后旧凭证/旧来源不能复活，
目标仍受 rebuilding 物理恢复门禁限制。这是元数据组件，不是宿主外备份认证。
