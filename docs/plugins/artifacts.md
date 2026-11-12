# 制品、签名与供应链

[文档总目录](../README.md)

> 规格版本：2.8.0；状态：待实现的规范性设计。MUST/必须表示实现及验收要求，不能理解为现有功能。

## 镜像引用

安装必须使用 `registry/path@sha256:<64 hex>`；禁止只传可变 tag。下载临时区须限制空间、时间和层大小，镜像内容最终摘要必须一致。支持 linux/amd64、linux/arm64，实际选择的 manifest digest 需写入安装记录。

## v1 签名信封

签名算法为 Ed25519。签名对象为以下精确 UTF-8 文本（包括最后换行），不是任意重新序列化 JSON：

```text
xelab-artifact-v1
<publisher UUID>
<plugin_id>
<SemVer>
<sha256:image manifest digest>
<sha256:raw /xelab/plugin.json bytes>
```

所有占位值单行、禁止 CR/LF；字段摘要为小写。InstallRequest.signature 为对该字节序列签名结果的标准 Base64。publisher_id/key_id 从受信记录读取，禁止镜像自带公钥自动建立信任。

先验证镜像摘要，再在不执行镜像的情况下读取清单并验证签名，之后才可批准安装。清单中的发布者、插件与版本必须与签名信封一致。

## 本地制品检查

开发者可用 `xelabctl validate-artifact` 检查已准备好的目录、签名安装请求与发布者公钥。目录应包含与镜像一致的 `xelab/plugin.json` 及相应契约文件，公钥由独立渠道取得。打包和签名步骤见[内核运行指南](../../crates/kernel/README.md)。

```sh
xelabctl validate-artifact --artifact-root examples/generated \
  --install-request ./install.json --publisher-key ./publisher.pub.pem
```

命令复用内核的安装请求、签名、普通插件清单和 RPC／HTTP 契约校验，可由普通用户离线运行。成功时输出清单原始字节的摘要和签名绑定的镜像摘要。输出中的 `image_content_verified` 为 `false`，安装时仍由内核核对 OCI 内容及发布者信任状态。

## 信任变更

撤销发布者阻止后续安装及升级；已有容器不会自动销毁，产生告警并等待明确处置。安装前进行恶意内容扫描、契约检查和配置安全检查；签名仅证明来源和完整性。

镜像 GC 只移除未被安装、操作、回滚保留点引用的内容。下载凭证由宿主配置，不能下发到普通插件。仓库实现更换不改变插件 ID、契约或签名语义。

接口见 [发布者及安装目录](../api/operations/plugins/README.md)。

## 扩展制品来源

扩展使用独立ExtensionManifest与包/内容摘要登记所有者和发布来源，不是宿主OCI签名或MPR镜像签名自动覆盖的内容。mode=data的contribution.json为严格UTF-8 JSON，最多256KiB；拒绝重复键、非有限数、越界深度与额外文件执行入口。mode=skill固定已注册handler_skill_id及definition_digest，不装入任意JS、原生库、shell或可变URL。

改变贡献、扩展点、处理器定义或制品内容须发布新扩展版本；宿主支持扩展须本身发布显式新清单。旧清单没有extension_points时不回写或重算包摘要。跨宿主类型的完整验证和样例见[扩展制品](../extensions/README.md)。
