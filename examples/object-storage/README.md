# 对象存储卷组件

本目录实现 [对象存储预设](../../docs/preset-plugins/object-storage/README.md) 的六项卷上操作。使用 SQLite WAL 保存可见对象、修订水位、写入预留和调用结果，内容通过最多 256 KiB 的连续帧流入流出。逻辑 key 仅用于索引，文件位置由可信主体 UUID 和服务端生成的内容 UUID 决定。

调用适配层须从可信内核通道取得主体、Call ID 和业务键，并提供当前调用已授权的 Blob 读写迭代器。写入完成 fsync 后才发布对象与结果。进程重启时释放尚未发布的导入预留，导出中断则保留未知结果。分页游标绑定主体、查询及部署代次。

在 Linux 上使用支持 SQLite 3.37 及以上版本的 Python 3 运行组件测试。

```sh
python3 -m unittest discover -s examples/object-storage -v
```

Kernel M1 的组件测试入口也会发现同一套件。

组件测试使用临时卷、实际 SQLite 与独立进程退出夹具。签名 OCI、内核 Skill 与 HostService Blob 接入、实际 XFS 卷配额及生产恢复属于后续验收。当前公开制品 profile 仍限制版本化卷和等待队列。[存储协议](../../docs/preset-plugins/object-storage/storage.md) · [格式监督器](../../docs/implementation/m2-schema-bootstrap.md)
