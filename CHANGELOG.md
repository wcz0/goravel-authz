# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 和[语义化版本](https://semver.org/lang/zh-CN/)。

## 版本对应关系

从 v1.18.0 起，版本号对齐 Goravel 次版本，不同版本线独立发布：

| goravel-authz | Goravel |
| --- | --- |
| v1.18.x | v1.18.x |
| v1.17.x | v1.17.x |
| v1.16.x | v1.16.x |
| v1.15.x | v1.15.x |

v0.x 为旧命名，历史记录保留在下方。

## [1.15.0] - 2026-10-23

### Added

- 新增 Goravel 1.15 版本线，`go get github.com/wcz0/goravel-authz@v1.15.0` 安装。
- 与其余版本线相同的 Casbin 能力：Adapter 批量增删、单条/批量更新、按条件更新与过滤加载，以及事务回滚。
- 与其余版本线相同的 HTTP 中间件、Gate 接入、Artisan 策略命令和 Goravel 日志集成。

### Changed

- `package:install` 按 1.15 的约定注册资源：provider 写入 `config/app.go`，迁移写入 `database/kernel.go`，配置、模型与迁移文件直接生成。
- 命令改为读取 `ctx.Arguments()`，1.15 的 console 没有 `command.Argument`。
- 日志统一通过 `log.Writer` 输出，1.15 的 `Log.Channel()` 返回 `Writer` 而不是 `Log`。
- 依赖 Goravel framework v1.15.12，Go 1.24+。

### Notes

- 本版本线不包含 SQLite 集成测试：官方 `goravel/sqlite` 驱动依赖 framework 1.16。Adapter 的批量、更新与过滤逻辑仍由内存事务 Store 完整覆盖。

## [1.17.1] - 2026-10-23

### Added

- 增加 CI：gofmt、`go vet`、`go test -race` 覆盖 Go 1.25 与最新版本，并校验 `goravel/framework` 与 `goravel/sqlite` 始终在同一版本线、`goravel-1.x` 分支与所依赖的框架次版本一致。
- 补齐 Enforcer 生命周期测试：默认模型解析、模型未定义、配置项不是 `adapters.Rule`、不支持的 `Model()` 类型、`Reload` 创建与刷新、`Reset`，以及并发首次加载只构建一次。
- 补齐 `package:install` 模板测试：生成的配置与迁移文件必须是合法 Go，内置 RBAC 模型必须能被 Casbin 解析。

### Changed

- 按模型名加锁创建 enforcer：首次加载策略期间的数据库查询不再持有全局锁，一个模型的慢查询不会阻塞其他模型的首次访问。

## [1.17.0] - 2026-10-23

### Added

- 与 v1.18.0 相同的 Casbin Adapter 能力：批量增删、单条/批量更新、按条件更新和过滤加载，以及事务回滚。
- 与 v1.18.0 相同的 HTTP 中间件能力：`WithGuards` 多模型任一放行、`WithTokens`、`Ability` 固定能力检查，以及 Goravel Auth 与 Gate 接入。

### Changed

- 适配 Goravel 1.17 的中间件类型：`Authz` 和 `Ability` 返回 `func(http.Context)`。
- `authz:policy:list` 在控制台中自行渲染对齐表格，因为 Goravel 1.17 的 `console.Context` 没有 `Table` 方法。
- 适配 Goravel 1.17 的日志、ORM 构造参数与数据库连接池重置接口。

## [1.18.0] - 2026-10-23

### Added

- Adapter 实现 Casbin 的 `BatchAdapter`、`UpdatableAdapter` 和 `FilteredAdapter` 接口：批量增删、单条/批量更新、按条件更新和过滤加载。
- 新增 `adapters.Filter` 与 `adapters.FilterFunc`；过滤加载后的策略禁止 `SavePolicy`，避免误删未加载的数据。
- 默认 ORM 存储支持事务，批量写入失败时自动回滚。
- HTTP 中间件默认从 Goravel Auth 读取当前用户 ID，并新增 `WithGuards` 多模型任一放行、`WithTokens` 和 `Ability` 固定能力检查。
- 接入 Goravel Gate：逗号能力（如 `articles,read`）直接交给 Casbin，`casbin.gate.enabled` 可关闭。

### Changed

- 中间件的 subject 解析顺序改为先取 `SetSubject`，再回退到 Goravel Auth。
- 升级 Casbin 到 v2.135.0、testify 到 v1.12.1，并适配 `GetPolicy`/`GetGroupingPolicy` 新的 `([][]string, error)` 返回值。
- 版本号从 v0.5.0 起改为对齐 Goravel 次版本：v1.18.x 支持 Goravel v1.18，v1.17.x 支持 Goravel v1.17。

## [0.5.0] - 2026-10-23

### Added

- 接入 Goravel 日志：授权决策、enforcer 生命周期和 Casbin 内部诊断统一写入 Goravel 日志通道。
- 新增 `casbin.log` 配置：`enabled`、`channel`、`allowed`、`denied`、`casbin`。拒绝请求默认以 warning 记录，放行请求需显式开启。
- `package:install` 生成的配置模板包含日志配置，README 增加日志章节。

## [0.4.0] - 2026-10-23

### Added

- 新增 Artisan 命令管理授权策略。

## [0.3.0] - 2026-10-23

### Added

- HTTP 授权中间件。
- 支持通过 `package:install` 安装配置文件和迁移。
- 多 enforcer 生命周期管理与按模型缓存。
- 支持 Goravel v1.18。

### Changed

- 重写策略持久化实现。
- 规则表增加主键。

## [0.2.0] - 2024-04-24

### Changed

- 调整授权逻辑。

### Fixed

- 修复若干问题。

## [0.1.6] - 2024-04-24

### Fixed

- 修复若干问题。

## [0.1.5] - 2024-04-23

### Fixed

- 修复 guard 相关问题。

## [0.1.4] - 2024-04-23

### Fixed

- 修复迁移文件名问题。

## [0.1.3] - 2024-04-23

### Changed

- 更新包名。

## [0.1.2] - 2024-04-22

### Fixed

- 修复 vendor 错误。

## [0.1.1] - 2024-04-22

### Changed

- 更新包名。

## [0.1.0] - 2024-04-22

### Added

- 初始版本，完成基于 Casbin 的基础授权功能。
