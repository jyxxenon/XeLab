# 插件开发规范

[文档总目录](../README.md)

> 规格版本：2.8.0；状态：待实现的规范。

- [独立预设插件目录](../preset-plugins/README.md)
- [核心Skill层与业务入口](../skills/README.md)

- [制品、签名与供应链](artifacts.md)
- [依赖解析与绑定](dependencies.md)
- [插件安装、启停与健康](lifecycle.md)
- [插件清单字段与校验](manifest.md)
- [升级、迁移与回滚](upgrades.md)
- [版本、能力契约与扩展](versioning.md)
- [WebUI 插件与可信登录边界](webui.md)
- [插件启动环境与传输绑定](bootstrap.md)

- [插件可选iframe窗口与桌面组件](ui-contributions.md)
- [C++ SDK 与跨语言一致性测试](cpp-sdk.md)

- [Micro Plugin Runtime与微插件](../preset-plugins/micro-plugin-runtime/README.md)

## 扩展插件开发

[Extension Plugin目录](../extensions/README.md)定义第三类插件的制品、宿主扩展点、绑定和调用。扩展可依赖普通插件、微插件或扩展插件；它不是把任意代码注入现有容器的通道。宿主须发布明确扩展点及兼容契约，再由核心建立固定扩展部署。
