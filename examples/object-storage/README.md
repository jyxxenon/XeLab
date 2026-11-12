# 对象存储插件

本目录实现 [对象存储预设](../../docs/preset-plugins/object-storage/README.md) 的六项卷上操作。使用 SQLite WAL 保存可见对象、修订水位、写入预留和调用结果，内容通过最多 256 KiB 的连续帧流入流出。逻辑 key 仅用于索引，文件位置由可信主体 UUID 和服务端生成的内容 UUID 决定。

RPC 服务从通过 mTLS 核验的内核通道取得主体、Call ID 和业务键，并向注入的 HostService 地址转发当前委托。写入完成 fsync 后才发布对象与结果。进程重启时释放尚未发布的导入预留，导出中断则保留未知结果。分页游标绑定主体、查询及部署代次。

在 Linux 上使用 Python 3.10 及以上版本和 SQLite 3.37 及以上版本运行卷组件测试。

```sh
python3 -m unittest discover -s examples/object-storage -p test_store.py -v
```

Kernel M1 的组件测试入口也会发现同一套件。

用发布者 UUID 生成制品并构建镜像。构建器核对清单中的六份原始契约摘要。

```sh
python3 examples/object-storage/build_artifact.py --publisher-id "$PUBLISHER_ID"
docker build --target release -f examples/object-storage/Dockerfile -t xelab-object-storage:local .
docker build --target conformance -f examples/object-storage/Dockerfile -t xelab-object-storage-rpc:local .
docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777 xelab-object-storage-rpc:local
```

正式入口从当前 XFS 项目卷获取容量，Initialize 需要可写挂载，Plan 和 Verify 需要只读挂载。Verify 检查 SQLite、配额账本和实际内容摘要，并核对原操作对应的计划 ID。现有格式为 `1`，Apply 无格式转换可执行。

专项 CI 构建并签验导入 containerd 的发行镜像。在隔离网络中使用内核及 Blob RPC 夹具验证 mTLS 和 Proto，并在独立 XFS 项目上执行写入、只读验证和容量不足拒绝。公开安装仍受版本化卷、版本化 HostService 权限和队列 profile 限制。真实平台 Skill 安装与调用、核心授权链和生产恢复仍需集成验收。[存储协议](../../docs/preset-plugins/object-storage/storage.md) · [格式监督器](../../docs/implementation/m2-schema-bootstrap.md)
