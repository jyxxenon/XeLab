# Rust SDK 与 mTLS 接入

[插件目录](README.md) · [启动环境](bootstrap.md) · [RPC 语义](../communication/grpc.md)

`xelab-plugin-sdk` 从仓库的 `xelab.v1` Proto 生成 PluginLifecycle、CapabilityService、HostService 和 DataMigration 类型。内核通过 `xelab_kernel::rpc` 重导出同一组类型。源码检出中可以独立构建和测试 SDK。

```sh
cargo build -p xelab-plugin-sdk --locked
cargo test -p xelab-plugin-sdk --locked
```

## 提供生命周期和能力

为插件实现生成的 `PluginLifecycle` 和 `CapabilityService` trait。运行时从挂载的工作负载身份文件建立 mTLS。SDK 每次握手读取当前证书和私钥，并在把连接交给 gRPC 服务前校验平台 CA 和内核的 SPIFFE URI。

```rust,ignore
use xelab_plugin_sdk::{
    rpc::{
        capability_service_server::CapabilityServiceServer,
        plugin_lifecycle_server::PluginLifecycleServer,
    },
    transport::{WorkloadIdentity, MAX_RPC_MESSAGE_BYTES, PLUGIN_RPC_LISTEN},
};

let identity = WorkloadIdentity::from_env()?;
let listener = tokio::net::TcpListener::bind(PLUGIN_RPC_LISTEN).await?;
let lifecycle = PluginLifecycleServer::new(plugin.clone())
    .max_decoding_message_size(MAX_RPC_MESSAGE_BYTES)
    .max_encoding_message_size(MAX_RPC_MESSAGE_BYTES);
let capabilities = CapabilityServiceServer::new(plugin)
    .max_decoding_message_size(MAX_RPC_MESSAGE_BYTES)
    .max_encoding_message_size(MAX_RPC_MESSAGE_BYTES);
tonic::transport::Server::builder()
    .add_service(lifecycle)
    .add_service(capabilities)
    .serve_with_incoming(identity.plugin_incoming(listener)?)
    .await?;
```

各处理器仍需按固定契约校验业务字段、限制字段大小、实现初始化和排空状态。仓库中的参考 Echo 使用同一套 SDK 监听器。[Echo 源码](../../crates/kernel/src/bin/xelab-echo.rs)

## 调用 HostService

`identity.connect_host().await?` 返回生成的 HostService 客户端。连接目标取自运行时注入的 `XELAB_HOST_RPC_ENDPOINT`，握手验证工作负载 CA、`kernel.xelab.local` 与内核 SPIFFE URI。建立新连接时读取当前工作负载证书。

通过本次 Call 的受限委托构造 `RpcContext`，并按方法上限和剩余期限设置 Tonic 请求超时。取消及流终帧由调用方和处理器按相同 RPC 契约处理。HostService 逐次核对当前实例和委托，插件应用应保留原调用标识并按方法语义处理结果。[HostService 方法](../rpc/README.md#hostservice)
