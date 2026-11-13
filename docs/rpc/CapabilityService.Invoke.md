# CapabilityService.Invoke

[RPC 目录](README.md) · [通用校验](../communication/grpc.md) · [错误](../communication/errors.md)

> 规格性设计；消息的全部字段及嵌套类型以 Protobuf 为准，字段出现和语义校验两者都必须满足。

`rpc Invoke(InvokeRequest) returns (InvokeResponse);`

- 完整方法：`/xelab.v1.CapabilityService/Invoke`
- 允许对端：`kernel`；工作负载身份从通道验证，禁止正文自报。
- 授权：capability.invoke + 有效用户/服务委托。
- 期限上限：300000ms；仍取调用整体 deadline 的更小值。
- 幂等：不保证方法无副作用，按业务契约和稳定幂等键判断，禁止 SDK 默认自动重放。

## 前置条件、执行及失败语义

校验 call_id、契约和 input_digest，input_json<=4MiB，output_json<=16MiB。side_effect 决定去重和重试；不能仅因方法为 unary 就自动重放。成功结果和键映射持久化要求随契约声明。

## 请求字段

| 字段号 | 字段 | Proto 类型 | 出现规则 |
|---|---|---|---|
| 1 | `context` | `RpcContext` | 按业务校验必填/默认值 |
| 2 | `call_id` | `string` | 按业务校验必填/默认值 |
| 3 | `contract` | `ContractRef` | 按业务校验必填/默认值 |
| 4 | `input_json` | `bytes` | 按业务校验必填/默认值 |
| 5 | `input_digest` | `string` | 按业务校验必填/默认值 |
| 6 | `binding_id` | `string` | 按业务校验必填/默认值 |
| 7 | `terminal_failure_version` | `uint32` | 内核发送 1 协商终态失败，0 使用原响应格式 |

## 响应字段

| 字段号 | 字段 | Proto 类型 | 出现规则 |
|---|---|---|---|
| 1 | `call_id` | `string` | 按业务校验必填/默认值 |
| 2 | `output_json` | `bytes` | 按业务校验必填/默认值 |
| 3 | `output_digest` | `string` | 按业务校验必填/默认值 |
| 4 | `terminal_failure` | `InvokeFailure` | 已完成的业务拒绝使用此字段，两个输出字段留空 |

嵌套消息、enum、oneof 及字段注释见 [Proto](../contracts/proto/xelab/v1/capability.proto)。公共上下文见 [common.proto](../contracts/proto/xelab/v1/common.proto)。所有字符串标识、期限、摘要和 JSON 大小均执行通用校验；仅在 method 说明允许时可为空。

## 错误与取消

校验失败 INVALID_ARGUMENT；无有效身份 UNAUTHENTICATED；越权 PERMISSION_DENIED；契约/状态冲突 FAILED_PRECONDITION；无资源 RESOURCE_EXHAUSTED；期限到期 DEADLINE_EXCEEDED；对端中断 UNAVAILABLE。细节通过 xelab-error-bin 返回，稳定码见错误目录。

内核对一元业务错误核对单个有界 `xelab-error-bin` 中的稳定码及对应 gRPC 状态。
错误消息、重试策略和持久引用由内核生成。已准入的 gRPC 状态错误保留原 Call 与活动预约，
由现有核实和围栏流程处理。客户端用原幂等键或 Call UUID 查询结果。

协商版本 1 后，提供者确认该 Call 的工作已结束时，可在正常 gRPC 响应中设置
`terminal_failure`。响应绑定原 `call_id`，`InvokeFailure` 携版本 1、原
`ContractRef` 和业务码 `INVALID_ARGUMENT`、`PERMISSION_DENIED`、
`RESOURCE_NOT_FOUND`、`STATE_CONFLICT` 或 `RESOURCE_EXHAUSTED`。
内核在结算时复核当前授权、签名能力及已认证实例代次，保存 `failed`、撤销委托并释放预约。
同键复查返回原 Call 和已保存的错误。工作结果未知时沿用 gRPC 错误和物理围栏。

任何有外部副作用的中断不能仅靠 gRPC status 断言未执行；先查询/核实，再按幂等与任务恢复规则处理。
