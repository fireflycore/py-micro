# py-micro

`py-micro` 是 Firefly Python 微服务公共包，当前按单个 Python 项目独立使用 `uv` 管理。

PyPI 分发名为 `firefly-micro`，业务代码通过 `firefly.micro` 导入。

```bash
uv sync
uv run pytest
uv build --no-sources
```

## 模块边界

- `firefly.micro.constants`: Firefly HTTP header / gRPC metadata 常量。
- `firefly.micro.metadata`: 出站 metadata 白名单清洗与 service authority 注入。
- `firefly.micro.authz`: `x-firefly-authz-sign` compact JWS 验签与 service token 缓存刷新。
- `firefly.micro.service_context`: 入站 metadata 到进程内服务上下文的结构化映射。
- `firefly.micro.invocation`: 远程服务 DNS/target 与出站调用 metadata 准备。
- `firefly.micro.config`: 配置 Key/Raw、payload 编解码和 watch 事件模型。

Go 版 `go-micro` 是语义参考，不是逐行翻译；Python 版优先保留跨语言必须一致的 header、claim、错误语义和生命周期约束。
