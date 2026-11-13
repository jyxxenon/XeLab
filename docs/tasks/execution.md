# 任务、尝试、租约与 fencing

[文档总目录](../README.md)

> 规格版本：2.8.0；状态：待实现的规范性设计。MUST/必须表示实现及验收要求，不能理解为现有功能。

## 执行记录

Task 固定 workflow_id、输入与 ExecutionDelegation；TaskStep 代表节点；Attempt 代表单次执行。一个步骤在同一时刻只允许一个未过期活动尝试。执行器在事务中用 FOR UPDATE SKIP LOCKED 领取 ready 步骤。

默认租约 30s，插件每 10s 发送 Heartbeat，内核每次收到后在合法 fence 下续约。execute 的 execution_id 表示该次执行，业务 idempotency_key 对同一步所有尝试稳定不变。

## fence

领取或接管步骤使 fence 单调增加。提交进度、检查点、结果必须同时匹配 attempt_id/execution_id/fence 和未失效租约；旧执行器迟到结果拒绝提交并审计，不覆盖新结果。

fence 保护平台元数据提交，不自动阻止外部系统副作用。外部写入仍需稳定幂等键或支持 fence 的目标系统。

## 步骤完成事务

验证当前授权与租约 → 校验输出契约 → 写 Attempt/Step 终态及输出引用 → 使依赖满足的下游步骤 ready → 写 outbox → 提交。大结果先写不可变 Blob，再提交引用，失败时未引用对象由 GC 处理。

## 取消

Task 先进入 cancel_requested，停止领取新步骤，通知活动插件，处理可取消子调用。全部活动步骤终止后 task=canceled；若外部结果仍不明，保留 unknown 步骤，不能假装全部副作用已撤销。

授权失效进入 paused_authorization，不通过服务身份偷偷续跑；恢复需要当前权限与原固定委托均有效。更换 owner 或服务主体要重新批准，不能直接复制原授权。

后台授权对账会扫描没有活动或未知尝试的 Task，包括等待提供者的 Task。发现原委托、Workflow 权限或任一 ready 步骤的冻结授权失效时，对账将 Task 暂停并保留步骤和尝试历史。整体期限已到时按期限对账；领取步骤时仍复核该步骤的执行授权。
