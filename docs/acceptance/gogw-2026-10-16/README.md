# gogw × mock Grayling 验收记录

状态：本地 mock 闭环验收通过；不代表生产 Grayling 或 issue #1 的全部 GA 验收。

实现与复现方式见 [开发指南](../../content/contributing/gogw.md)。基线、SDK 固定版本、代码文件摘要与执行命令见 [manifest.json](manifest.json)。

| 检查 | 结果 | 证据 |
| --- | --- | --- |
| mock WSS → SDK → 签名 Bundle → Prepared/Activate/Applied | PASS | [功能测试](focused.txt) |
| 本地/跨版本、用户/租户/IP 定向、20%→60% 稳定放量 | PASS | 功能测试 |
| 同 build 多实例 WRR、缩容、无可选实例 | PASS | 功能测试 |
| mTLS 绑定、boot/build/Bundle/generation/请求语义/票据失效拒绝 | PASS | 功能测试 |
| 旧更新拒绝、缓存损坏、冷启动、快照过期、应用健康 | PASS | 功能测试 |
| 结果未知的写入不自动重放、请求体流式透传 | PASS | 功能测试 |
| SSE 首事件 flush、取消传播、视图更新保留旧流、排空拒绝新请求 | PASS | 功能测试，启用 race detector |
| 真实 gogw 二进制、单端口 TLS、HTTP/2、离线控制面时 file-provider 重载 | PASS | [进程测试](process.txt) |
| 真实 SIGTERM 带活动 SSE 排空、超时回收和退出 | PASS | 进程测试 |
| 全仓短单元测试 | PASS | [包级结果](unit-packages.txt) |
| 全仓 lint、带进程测试标签的新增代码 lint | PASS | [检查输出](lint.txt) |
| 模块 tidy 幂等、拼写及 shell 检查 | PASS | 以临时 Git 索引运行 make validate-files，见下文 |

全仓测试的首轮失败包括代理环境截获 `[::]:port` 测试连接，以及高并发任务影响 Redis 限流吞吐阈值。移除代理环境变量并使用 `-p=2` 后全部通过，未修改相关官方实现或测试。

使用 golangci-lint v2.14.0 检查 Go 1.27.2。原工具 v2.13.2 无法读取该工具链的导出格式；配置只关闭了会要求重写官方旧代码的 `modernize/embedlit` 提示，其他规则保留。

`validate-files` 的模块检查比较工作区与 Git 索引。由于 SDK 引入的依赖变化尚未提交，直接执行会报告预期 diff。因此创建独立的临时索引记录当前工作内容，再运行该目标，确认 tidy 无额外变化，并执行拼写及 shell 检查。实际暂存区和提交历史未改动。

未运行生产注册中心、发布 quorum、跨节点可达性、证书轮换、容器 supervisor、持久化安全撤销或容量 profile。mock 的 endpoint Prepared 字段和自动 Activate 仅用于验证数据面；这些生产验收项不能记为通过。
