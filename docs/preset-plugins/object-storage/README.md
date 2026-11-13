# 对象存储预设插件

[预设目录](../README.md) · [文档总目录](../../README.md)

> 规格版本：2.8.0；状态：设计契约，尚未实现或实测。

插件ID为`org.xelab.object-storage`，插件版本1.0.0。它是普通OCI容器插件，提供按用户隔离的持久文件存储；核心通过固定Skill转发元数据请求，文件字节通过受控核心Blob传递。

每个用户拥有独立逻辑命名空间；同一用户的API Key使用该用户的命名空间，子账户使用自己的命名空间。客户端不能传入owner_id切换用户。具体隔离边界见[授权](authorization.md)。

## 数据路径

上传文件时，先通过核心上传接口创建Blob，再调用object-put将其持久复制到插件卷。源Blob默认24h过期不影响已经提交的对象。

下载文件时，先调用object-stat获得当前revision，再调用object-export生成当前用户所有的临时核心Blob，最后通过核心下载接口获取字节。导出Blob过期后可以使用新业务键再次导出；持久对象不会因此过期。

单对象允许0..67108864字节，即最多64MiB。JSON请求只携带Blob引用与元数据，不能通过base64等方式把文件塞入业务JSON。本版不提供分片上传、S3兼容接口、公共下载URL或任意宿主路径访问。

## 默认建议

单副本1000mCPU、1GiB内存、256MiB临时盘、pids128；活动请求4、排队32、最长排队5000ms。独占single_writer卷挂载到`/data/objects`，建议容量20GiB；对象存储部署预算16GiB，为SQLite WAL、幂等结果及GC留出余量。

每用户默认逻辑内容配额1GiB、最多10000个可见对象。以上均为未实测的初始建议，实际准入还受核心插件池、账户调用额度和卷硬配额约束，不借用所选 profile 的内核预留。

## 文档与契约

六个能力都是一元 RPC。各契约目录中的 `stream.schema.json` 包含字面量 `null`，对应清单的 `stream_item_schema: null`，表示该能力不提供流式输出。

- [接口、对象模型与错误](interfaces.md)
- [配置与容量预算](configuration.md)
- [持久化、CAS、幂等与GC](storage.md)
- [用户隔离与权限](authorization.md)
- [待实现验收](acceptance.md)
- [清单](manifest.json)、[默认配置](defaults.json)、[部署模板](deployment.template.json)、[私有存储结构](storage.sql)
- [逐项Skill文档](../../skills/object-storage/README.md)

批量导入、导出和删除使用[核心异步batch](../../skills/batches.md)，每项仍是有界单对象操作；一个批次可以部分成功，不提供跨项事务。
