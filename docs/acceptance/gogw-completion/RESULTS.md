# gogw 完成验收：结果、复现步骤与环境

**结论**：需求矩阵（见 `STATUS.md`）中的八组需求全部实现并有对应测试；聚焦验收（`-race` 单元 + 真实二进制进程验收）、构建、`go vet`、`make lint`、`make validate-files` 全部通过；全量单元测试 111 个包通过、0 失败。验收过程中观察到一次与本次改动无关的上游并发 flake，机制已定位并在同一代码树上原样复现，记录在 §4。

## 1. 环境

完整快照见同目录 `environment.txt`。要点：

- Go 1.27.2（`go.mod` 的 `go` 指令为 1.27.2），golangci-lint v2.14.0，misspell、shellcheck 0.9.0 位于 `/tmp/gogw-tools`。
- 工作树 `/home/vipas/workspace/saker-ai/gogw/.claude/worktrees/gogw-completion`（分支 `gogw-completion`），基线提交 `82671d1af`。
- SDK 固定为 `github.com/saker-ai/grayling v0.5.2-0.20261016030758-805a6969c25e`，`go.mod` 中没有任何指向该 SDK 的 `replace`。
- 运行验收时必须清除代理变量：本地 mock 控制面、负载均衡入口与回环应用都在 `127.0.0.1`，走代理会失败。
- 未引入任何新的模块依赖，也未改动 `go.mod` / `go.sum`（见 §6）。

## 2. 命令与结果

每一步的原始输出都在同目录 `logs/` 下。全部命令在工作树根目录执行。

| 步骤 | 命令 | 结果 | 日志 |
| --- | --- | --- | --- |
| 1 | `go build ./...` | EXIT=0 | `logs/build.txt` |
| 2 | `go vet -tags=gogwprocess ./pkg/gogw/... ./cmd/gogw-mock/...` | EXIT=0 | `logs/build.txt` |
| 3 | `make test-gogw`（`-race -count=1`） | EXIT=0：`pkg/gogw` 104.6s、`pkg/gogw/mock` 6.2s、`pkg/server/service` 1.2s | `logs/focused.txt` |
| 4 | `make test-gogw-process`（真实二进制、TLS、HTTP/2、SSE） | EXIT=0：`pkg/gogw` 8.7s | `logs/process.txt` |
| 5 | `make test-unit TESTFLAGS='-short -timeout=3m -p=2 -count=1'` | EXIT=0：111 个包 `ok`，0 个 `FAIL` | `logs/unit.txt`、`logs/unit-packages.txt` |
| 6 | `make lint` | EXIT=0：`0 issues.` | `logs/lint.txt` |
| 7 | `golangci-lint run --build-tags=gogwprocess ./pkg/gogw/... ./cmd/gogw-mock/... .` | EXIT=0：`0 issues.` | `logs/lint.txt` |
| 8 | `make validate-files`（vendor、misspell、shellcheck） | EXIT=0 | `logs/validate-files.txt` |
| 9 | `git diff --check` | EXIT=0 | `logs/worktree.txt` |

`-count=1` 是刻意加的：`make test-unit` 的 recipe 带 `-v` 且默认会复用测试缓存，加上它才能保证这一步的结果对应本工作树的代码，而不是上一次运行的缓存。

## 3. 测试规模

- `pkg/gogw` 29 个顶层测试（`gateway_test.go`、`routing_test.go`、`process_test.go`），`pkg/gogw/mock` 14 个。
- 覆盖率（`make test-unit` 的 `-cover` 输出）：`pkg/gogw` 75.4%，`pkg/gogw/mock` 80.7%。
- 需求 → 实现 → 测试的逐项对应关系见 `STATUS.md` 的需求矩阵；`logs/unit-packages.txt` 是第 5 步的包级摘要。

## 4. 一次与本次改动无关的上游 flake（如实记录）

第 5 步第一次运行时失败，唯一失败的包是**未改动的上游包** `pkg/middlewares/ingressnginx/snippet`：其 `Test_Directives` 的部分并行子测试返回 500（期望 200 或 302），根因错误为 `net/http: HTTP/1.x transport connection broken: http: CloseIdleConnections called`。机制、标准库出处、原始日志摘录与复现命令见 `logs/upstream-snippet-flake.txt`，要点：

- 该包的约百个子测试都带 `t.Parallel()`，各自 `defer` 关闭自己的 `httptest.Server`；而 `httptest.Server.Close()` 会关闭进程级共享的 `http.DefaultTransport`，并取消其它子测试仍在进行的拨号（`net/http/httptest/server.go`），于是 forward-auth 返回 500。并发时序决定结果。
- 与该包无关的旁证：该包及其依赖（`pkg/middlewares/ingressnginx`、`pkg/middlewares/forwardauth`、`pkg/proxy`）在本工作树中 `git status` 为空，最后一次改动它的提交是 `759515bec`（合入的上游提交）；该包与 `pkg/gogw` 不在同一个测试进程内。
- 独立复现：`go test -count=1 <该包>` 连续三次通过，`GOMAXPROCS=1 go test -count=5 <该包>` 通过，`go test -count=10 <该包>` 稳定复现同一错误——即不涉及任何 gogw 代码也能复现。
- 处置：没有跳过该测试、没有加 `//nolint`、没有删除断言。在原样不变的代码树上重跑整套命令（第 5 步），111 个包通过、0 失败，`pkg/gogw` 与 `pkg/gogw/mock` 均通过；提交的 `logs/unit.txt` 即这次通过运行的日志。

## 5. 复现步骤

```bash
cd /home/vipas/workspace/saker-ai/gogw/.claude/worktrees/gogw-completion
export PATH=/tmp/gogw-tools:$PATH
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy

go build ./...
go vet -tags=gogwprocess ./pkg/gogw/... ./cmd/gogw-mock/...
make test-gogw
make test-gogw-process
TESTFLAGS='-short -timeout=3m -p=2 -count=1' make test-unit
make lint
golangci-lint run --build-tags=gogwprocess ./pkg/gogw/... ./cmd/gogw-mock/... .
make validate-files
git diff --check
```

`make test-gogw` 与 `make test-gogw-process` 自带 `-race -count=1`；后者会先把 `cmd/traefik` 与 `cmd/gogw-mock` 编译成 `dist/` 下的真实二进制再驱动验收矩阵。

第 4 步的现象可用下面两条命令单独观察（不涉及 gogw 代码）：

```bash
go test -count=1  ./pkg/middlewares/ingressnginx/snippet/   # 通过
go test -count=10 ./pkg/middlewares/ingressnginx/snippet/   # 复现 CloseIdleConnections called
```

`logs/unit.txt` 是约 2 MB 的逐测试 verbose 输出（上游 `test-unit` recipe 带 `-v`），因此随仓库提交的是它的包级摘要 `logs/unit-packages.txt`；完整日志可用上面的命令按原样复现。

## 6. 约束遵守情况

- **未改动模块路径**；**未新增或修改任何依赖**：`go.mod`、`go.sum` 与基线 `82671d1af` 完全一致（`script/validate-vendor.sh` 通过）。网关与 mock 用 Go 1.27.2 标准库的 `uuid` 生成不透明的 operation ID，因此没有把 `github.com/google/uuid` 从 indirect 提升为直接依赖。
- **未手改生成文件**：`git status` 中没有 `**/zz_generated*.go`、`pkg/provider/kubernetes/crd/generated/`、`webui/static/` 或任何 `.pb.go`。
- **未触及兄弟仓库**：`/home/vipas/workspace/saker-ai/grayling` 的 HEAD 正是锁定伪版本对应的提交 `805a6969c25e`，其工作区存在 140 项他人未提交的改动，本次工作没有读取其未发布 API、没有修改其任何文件，也没有把它接入 `go.mod`。
- **未发布任何外部消息**：没有创建或评论 issue/PR，没有发送邮件或其它外部消息；`godeps/gogw` issue #1 全程只读。
- **无占位实现**：`pkg/gogw`、`cmd/gogw-mock`、`cmd/traefik` 中没有 `TODO`/`FIXME`/未实现分支，没有 `t.Skip`/`testing.Short()`，没有 `//nolint`。
- **协议扩展如实标注**：SDK 未定义的三个资源 payload 由本 fork 以版本化扩展补足（`pkg/gogw/protocol.go`，`schema=1`），`docs/content/contributing/gogw.md` 与 `STATUS.md` 都明确标注为 fork 自有契约，并列出无法在本仓库验证的互操作边界，没有声称真实服务端已支持这些字段。

## 7. 交付物

- `docs/acceptance/gogw-completion/STATUS.md`：需求矩阵、协议边界、外部硬阻塞、验收命令。
- `docs/acceptance/gogw-completion/RESULTS.md`：本文件。
- `docs/acceptance/gogw-completion/environment.txt`：环境快照。
- `docs/acceptance/gogw-completion/logs/`：每一步的原始输出、包级摘要、上游 flake 的机制与复现证据。
- `docs/content/contributing/gogw.md`：面向使用者的网关文档，含协议契约、配置项、观测接口与真实 Grayling 互操作边界。