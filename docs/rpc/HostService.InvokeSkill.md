# HostService.InvokeSkill

[RPC 目录](README.md) · [通用校验](../communication/grpc.md) · [错误](../communication/errors.md)

> 规格性设计；消息的全部字段及嵌套类型以 Protobuf 为准，字段出现和语义校验两者都必须满足。

`rpc InvokeSkill(SkillInvokeRequest) returns (InvokeResponse);`

- 完整方法：`/xelab.v1.HostService/InvokeSkill`
- 允许对端：`plugin`；工作负载身份从通道验证，禁止正文自报。
- 授权：skill.invoke ∩ 目标原动作 ∩ 插件代理权限 ∩ 当前主体/委托。
- 期限上限：300000ms；仍取调用整体 deadline 的更小值。
- 幂等：不保证方法无副作用，按业务契约和稳定幂等键判断，禁止 SDK 默认自动重放。

## 前置条件、执行及失败语义

核心锁定定义摘要及plugin_id/契约，验证input_json<=4MiB和输入Blob白名单，再执行实例级并发准入。不接受任意URL；返回InvokeResponse.output_json为业务输出，调用记录保留Skill元数据。 MPR1.3或其他ExtensionHost处理器路径必须另有当前宿主安装已批准的skill.invoke代理规则；可选申请未批准时skill模式拒绝，不能由extension.host.use替代。当前Call若为extension，只允许身份闭包中固定handler_skill_id/definition_digest，重查handler目标/输入Schema/副作用/权限且禁止路径重入；MPR的普通micro Call没有泛化InvokeSkill桥，即使父安装有可选代理规则也不得借用。 调用者可在可选call_id预先给出新的规范UUID；省略或空值由核心分配。相同父Call/幂等键/请求指纹保留同一下游Call，不重新执行。已准入后的业务失败通过xelab-error-bin中ErrorDetail.resource_id返回调用者仍可见的持久Call；未准入的字段/授权错误不填该引用。传输完全丢失时无法依赖错误元数据，预先提供的call_id用于查询核实；省略该字段的旧调用不能把缺引用当作未执行。unknown及non_repeatable不得自动重发。

## 请求字段

| 字段号 | 字段 | Proto 类型 | 出现规则 |
|---|---|---|---|
| 1 | `context` | `RpcContext` | 按业务校验必填/默认值 |
| 2 | `skill_id` | `string` | 按业务校验必填/默认值 |
| 3 | `input_json` | `bytes` | 按业务校验必填/默认值 |
| 4 | `input_digest` | `string` | 按业务校验必填/默认值 |
| 5 | `call_id` | `string` | optional |

## 响应字段

| 字段号 | 字段 | Proto 类型 | 出现规则 |
|---|---|---|---|
| 1 | `call_id` | `string` | 按业务校验必填/默认值 |
| 2 | `output_json` | `bytes` | 按业务校验必填/默认值 |
| 3 | `output_digest` | `string` | 按业务校验必填/默认值 |
| 4 | `terminal_failure` | `InvokeFailure` | 留空，失败通过 gRPC 状态返回 |

嵌套消息、enum、oneof 及字段注释见 [Proto](../contracts/proto/xelab/v1/host.proto)。公共上下文见 [common.proto](../contracts/proto/xelab/v1/common.proto)。所有字符串标识、期限、摘要和 JSON 大小均执行通用校验；仅在 method 说明允许时可为空。

## 错误与取消

校验失败 INVALID_ARGUMENT；无有效身份 UNAUTHENTICATED；越权 PERMISSION_DENIED；契约/状态冲突 FAILED_PRECONDITION；无资源 RESOURCE_EXHAUSTED；期限到期 DEADLINE_EXCEEDED；对端中断 UNAVAILABLE。细节通过 xelab-error-bin 返回，稳定码见错误目录。

任何有外部副作用的中断不能仅靠 gRPC status 断言未执行；先查询/核实，再按幂等与任务恢复规则处理。
