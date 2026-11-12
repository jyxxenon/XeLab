# C++ SDK 与跨语言一致性测试

[插件目录](README.md) · [启动环境](bootstrap.md) · [RPC 语义](../communication/grpc.md)

`sdk/cpp` 从仓库的 Proto 生成 C++ 的 PluginLifecycle、CapabilityService、HostService 和 DataMigration 绑定。插件可链接 CMake 目标 `xelab_plugin_sdk` 并引入 `<xelab/sdk.h>`。参考插件复用 Rust Echo 的一元和流式契约文件。[C++ Echo 源码](../../examples/echo-cpp/main.cc)

## 构建和实现

在 Ubuntu 24.04 安装 C++17 编译器、CMake、Protobuf、gRPC C++、OpenSSL、nlohmann-json 和 bubblewrap。

```sh
sudo apt-get install g++ cmake make libprotobuf-dev libgrpc++-dev \
  protobuf-compiler-grpc libssl-dev nlohmann-json3-dev bubblewrap
cmake -S sdk/cpp -B target/cpp-sdk -DCMAKE_BUILD_TYPE=Release
cmake --build target/cpp-sdk --parallel
cargo build -p xelab-kernel --bin xelab-echo --locked
```

为插件实现生成的生命周期和能力服务，使用 `ConfigurePluginServer` 注册固定 mTLS 监听器。SDK 核验工作负载 CA 与内核 SPIFFE URI，限制单条 gRPC 消息大小，并通过证书文件监视器更新新连接的证书。实现方仍需验证业务 Schema 和摘要，并协作处理取消、排空和流终帧。C++ Echo 支持一元及正常流式调用，Rust 专用故障夹具在 C++ 端返回参数错误。

`ConnectHost` 返回固定宿主入口的 HostService stub，核验内核 DNS 名称和 SPIFFE URI。`HostCallContext` 继承当前 gRPC 调用的取消状态，取传输期限、`RpcContext` 期限及方法上限的最小值。调用方使用当前委托填充 Proto 请求，并可从完成后的调用读取 `xelab-error-bin`。HostService 逐调用确认当前实例与委托。[HostService 方法](../rpc/README.md#hostservice)

## 离线一致性测试

```sh
python3 tools/acceptance/sdk-conformance.py \
  --rust target/debug/xelab-echo \
  --cpp target/cpp-sdk/xelab-echo-cpp \
  --client target/cpp-sdk/xelab-sdk-conformance
```

同一个生成的 RPC 客户端在隔离回环网络中驱动两个参考二进制。脚本核对两端的原始契约，使用临时 CA 测试内核身份、生命周期、输入校验、期限、取消、流终帧和错误。C++ HostService 客户端另有 mTLS、委托拒绝及父调用取消传播的回环测试。本地使用 Linux 用户命名空间，CI 使用仅有回环接口的 Docker 容器。

## 签名 OCI 验收

CI 在独立的 Ubuntu runner 构建最终镜像，按平台 manifest 的不可变摘要导入 containerd。验收通过平台 API 拒绝绑定到其他摘要的签名，再安装正确签名的镜像。启用获批的部署后，经 mTLS 执行一元能力调用和 Skill SSE 流式调用，并核对调用记录对应同一个容器实例。停用部署后检查容器已移除，CPU 和内存预留已释放。[验收工作流](../../.github/workflows/plugin-sdk.yml)

## 生成制品并提交

用实际发布者 UUID 替换 `PUBLISHER_ID`，生成清单和契约后构建镜像。

```sh
python3 examples/echo/build_artifact.py --implementation cpp \
  --publisher-id "$PUBLISHER_ID" --output examples/echo-cpp/generated
docker build -f examples/echo-cpp/Dockerfile -t docker.io/local/xelab-echo-cpp:1.0.0 .
```

取平台对应的不可变 OCI manifest 摘要，按制品文档签名并走现有发布者信任、安装和批准流程。提交 PR 时记录制品版本、共用契约摘要、离线测试和单独执行的签名 OCI 验收。[制品与签名](artifacts.md) · [仓库贡献流程](../../CONTRIBUTING.md)
