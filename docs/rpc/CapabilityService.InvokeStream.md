# CapabilityService.InvokeStream

[RPC 目录](README.md) · [通用校验](../communication/grpc.md) · [错误](../communication/errors.md)

> 规格性设计；消息的全部字段及嵌套类型以 Protobuf 为准，字段出现和语义校验两者都必须满足。

`rpc InvokeStream(InvokeRequest) returns (stream InvokeChunk);`

- 完整方法：`/xelab.v1.CapabilityService/InvokeStream`
- 允许对端：`kernel`；工作负载身份从通道验证，禁止正文自报。
- 授权：capability.invoke + 有效委托。
- 期限上限：300000ms；仍取调用整体 deadline 的更小值。
- 幂等：不保证方法无副作用，按业务契约和稳定幂等键判断，禁止 SDK 默认自动重放。

## 前置条件、执行及失败语义

契约必须有 stream_item_schema；sequence 从1连续，body oneof 必须恰有一项。item<=1MiB，completed/failed/canceled 恰一终帧。流断后不自动重新生成或切换提供者。

## 请求字段

| 字段号 | 字段 | Proto 类型 | 出现规则 |
|---|---|---|---|
| 1 | `context` | `RpcContext` | 按业务校验必填/默认值 |
| 2 | `call_id` | `string` | 按业务校验必填/默认值 |
| 3 | `contract` | `ContractRef` | 按业务校验必填/默认值 |
| 4 | `input_json` | `bytes` | 按业务校验必填/默认值 |
| 5 | `input_digest` | `string` | 按业务校验必填/默认值 |
| 6 | `binding_id` | `string` | 按业务校验必填/默认值 |
| 7 | `terminal_failure_version` | `uint32` | 固定为 0，流式失败使用 `failed` 帧 |

## 响应字段

| 字段号 | 字段 | Proto 类型 | 出现规则 |
|---|---|---|---|
| 1 | `call_id` | `string` | 按业务校验必填/默认值 |
| 2 | `sequence` | `uint64` | 按业务校验必填/默认值 |
| 3 | `item_json` | `bytes` | oneof body |
| 4 | `completed` | `InvokeResponse` | oneof body |
| 5 | `failed` | `ErrorDetail` | oneof body |
| 6 | `canceled` | `Ack` | oneof body |

嵌套消息、enum、oneof 及字段注释见 [Proto](../contracts/proto/xelab/v1/capability.proto)。公共上下文见 [common.proto](../contracts/proto/xelab/v1/common.proto)。所有字符串标识、期限、摘要和 JSON 大小均执行通用校验；仅在 method 说明允许时可为空。

## 错误与取消

校验失败 INVALID_ARGUMENT；无有效身份 UNAUTHENTICATED；越权 PERMISSION_DENIED；契约/状态冲突 FAILED_PRECONDITION；无资源 RESOURCE_EXHAUSTED；期限到期 DEADLINE_EXCEEDED；对端中断 UNAVAILABLE。细节通过 xelab-error-bin 返回，稳定码见错误目录。

任何有外部副作用的中断不能仅靠 gRPC status 断言未执行；先查询/核实，再按幂等与任务恢复规则处理。
