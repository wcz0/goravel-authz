# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 和[语义化版本](https://semver.org/lang/zh-CN/)。

## 版本对应关系

从 v1.18.0 起，版本号对齐 Goravel 次版本，不同版本线独立发布：

| goravel-authz | Goravel |
| --- | --- |
| v1.18.x | v1.18.x |
| v1.17.x | v1.17.x |

v0.x 为旧命名，历史记录保留在下方。

## [1.18.1] - 2026-10-23

### Added

- 增加 CI：gofmt、`go vet`、`go test -race` 覆盖 Go 1.25 与最新版本，并校验 `goravel/framework` 与 `goravel/sqlite` 始终在同一版本线、`goravel-1.x` 分支与所依赖的框架次版本一致。
- 补齐 Enforcer 生命周期测试：默认模型解析、模型未定义、配置项不是 `adapters.Rule`、不支持的 `Model()` 类型、`Reload` 创建与刷新、`Reset`，以及并发首次加载只构建一次。
- 补齐 `package:install` 模板测试：生成的配置与迁移文件必须是合法 Go，内置 RBAC 模型必须能被 Casbin 解析。

### Changed

- 按模型名加锁创建 enforcer：首次加载策略期间的数据库查询不再持有全局锁，一个模型的慢查询不会阻塞其他模型的首次访问。

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
