# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 和[语义化版本](https://semver.org/lang/zh-CN/)。

## [0.5.0] - 2026-10-23

### Added

- 接入 Goravel 日志：授权决策、enforcer 生命周期和 Casbin 内部诊断。

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
