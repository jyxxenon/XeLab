# 任务恢复、结果未知与检查点

[文档总目录](../README.md)

> 规格版本：2.8.0；状态：待实现的规范性设计。MUST/必须表示实现及验收要求，不能理解为现有功能。

## 中断后的分类

| 能力副作用类型 | 查询后处理 |
|---|---|
| none | 可在原整体期限和重试次数内重试 |
| idempotent | 使用同一步稳定键查询/重放，由插件持久化去重保证 |
| queryable | 先 QueryResult，已完成则提交结果，未执行可重试，不明则 unknown |
| non_repeatable | 没有确定结果则 unknown，不自动重试 |

平台仅保存 running 不能证明外部消息未发送或扣款未提交。重启后先核对所有过期租约与插件执行记录，再决定接管；任务记录恢复、步骤重试、检查点续算是不同能力。

## 人工核实

resolveUnknownStep 只在 unknown 状态允许。confirmed_succeeded 必须提供可信证据及满足输出 Schema 的 output；confirmed_not_executed 表示外部核实未执行，随后由显式 retry 决定重排。证据及操作者全审计。

未确认的“认为失败”不是 confirmed_not_executed。不能通过修改 task.state 跳过核实。补偿动作是新的获授权步骤，也可能失败，不能宣称自动恢复原世界状态。

同步 Broker 在发送业务请求前持久化派发标记。内核可以用已释放预留的关联 Call 核实标记仍为未派发的步骤。标记已经推进或旧账本缺少标记时，保持未知，等待可信结果。核实未执行后保留历史 Attempt，步骤进入失败状态，由 `retryTask` 显式复核原授权、依赖、整体期限和次数上限后再重新排队。

## 检查点

插件先完整上传 Blob，再报告 checkpoint；记录 blob_id、data_schema_version、plugin_version、契约及提供者绑定。内核事务提交后 checkpoint 才有效。已引用 checkpoint 必须 pin，不因默认 Blob TTL 删除。

恢复时确认插件版本/格式兼容、当前授权有效和资源准入通过，ExecuteTaskRequest.checkpoint_blob_id 才能传入。不同模型/提供者不能默认读取相同检查点。

宿主磁盘丢失不属于进程检查点恢复，必须按宿主外备份流程恢复。
