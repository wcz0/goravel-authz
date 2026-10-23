# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Release lines

Since v1.18.0 the version number follows the Goravel minor version, and every line is
released independently from its own branch:

| goravel-authz | Branch | Goravel |
| --- | --- | --- |
| v1.18.x | `main` | v1.18.x |
| v1.17.x | `goravel-1.17` | v1.17.x |
| v1.16.x | `goravel-1.16` | v1.16.x |
| v1.15.x | `goravel-1.15` | v1.15.x |

v0.x used the previous naming scheme; that history is kept below.

## [1.18.2] - 2026-10-23

### Fixed

- Fixed the `config/casbin.go` and migration files written by `package:install`: their imports now point at the application module (`<app>/app/facades`, `<app>/database/migrations`) instead of this package, which left the installed project unable to compile. Outside an application directory the installer falls back to the framework facades.

## [1.18.1] - 2026-10-23

### Added

- Added CI: gofmt, `go vet` and `go test -race` on every release line, plus a check that `goravel/framework` and `goravel/sqlite` stay on the same line and that a `goravel-1.x` branch matches the framework minor version it depends on.
- Added the remaining Enforcer lifecycle tests: default model resolution, an undefined model, a config entry that is not an `adapters.Rule`, an unsupported `Model()` type, `Reload` creating and refreshing, `Reset`, and a concurrent first load that builds the enforcer only once.
- Added tests for the `package:install` templates: the generated config and migration must be valid Go, and the built-in RBAC model must parse in Casbin.

### Changed

- Enforcers are created under a per-model lock: the database query during the first policy load no longer holds the global lock, so a slow model cannot block the first access to another one.

## [1.18.0] - 2026-10-23

### Added

- The adapter implements Casbin's `BatchAdapter`, `UpdatableAdapter` and `FilteredAdapter` interfaces: batch add and remove, single and batch update, update by filter, and filtered loading.
- Added `adapters.Filter` and `adapters.FilterFunc`; `SavePolicy` is rejected while a filtered policy is loaded, so rows that were not loaded are never deleted.
- The default ORM store is transactional, so a failed batch write rolls back.
- The HTTP middleware reads the current user ID from Goravel Auth by default, and adds `WithGuards` to allow a request when any model allows it, `WithTokens` and `Ability` for fixed ability checks.
- Integrated with Goravel Gate: abilities that contain a comma (such as `articles,read`) are handed to Casbin, and `casbin.gate.enabled` turns the hook off.

### Changed

- The middleware now resolves the subject from `SetSubject` first and falls back to Goravel Auth.
- Upgraded Casbin to v2.135.0 and testify to v1.12.1, and adapted to the new `([][]string, error)` return values of `GetPolicy` and `GetGroupingPolicy`.
- From v0.5.0 the version number follows the Goravel minor version: v1.18.x targets Goravel v1.18 and v1.17.x targets Goravel v1.17.

## [0.5.0] - 2026-10-23

### Added

- Integrated with the Goravel logger: authorization decisions, the enforcer lifecycle and Casbin diagnostics all go to the configured Goravel channel.
- Added the `casbin.log` settings: `enabled`, `channel`, `allowed`, `denied` and `casbin`. Denied requests are logged as warnings by default, allowed requests have to be enabled explicitly.
- The config written by `package:install` includes the logging settings, and the README gained a logging section.

## [0.4.0] - 2026-10-23

### Added

- Added Artisan commands to manage authorization policies.

## [0.3.0] - 2026-10-23

### Added

- HTTP authorization middleware.
- `package:install` installs the config file and the migration.
- Multiple enforcer lifecycle management with per-model caching.
- Support for Goravel v1.18.

### Changed

- Rewrote the policy persistence.
- Added a primary key to the rules table.

## [0.2.0] - 2024-04-24

### Changed

- Adjusted the authorization logic.

### Fixed

- Fixed several issues.

## [0.1.6] - 2024-04-24

### Fixed

- Fixed several issues.

## [0.1.5] - 2024-04-23

### Fixed

- Fixed guard related issues.

## [0.1.4] - 2024-04-23

### Fixed

- Fixed the migration file name.

## [0.1.3] - 2024-04-23

### Changed

- Updated the package name.

## [0.1.2] - 2024-04-22

### Fixed

- Fixed a vendoring error.

## [0.1.1] - 2024-04-22

### Changed

- Updated the package name.

## [0.1.0] - 2024-04-22

### Added

- Initial release with the core Casbin based authorization.

[1.18.2]: https://github.com/wcz0/goravel-authz/compare/v1.18.1...v1.18.2
[1.18.1]: https://github.com/wcz0/goravel-authz/compare/v1.18.0...v1.18.1
[1.18.0]: https://github.com/wcz0/goravel-authz/compare/v0.5.0...v1.18.0
[0.5.0]: https://github.com/wcz0/goravel-authz/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/wcz0/goravel-authz/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/wcz0/goravel-authz/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/wcz0/goravel-authz/compare/v0.1.6...v0.2.0
[0.1.6]: https://github.com/wcz0/goravel-authz/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/wcz0/goravel-authz/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/wcz0/goravel-authz/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/wcz0/goravel-authz/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/wcz0/goravel-authz/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/wcz0/goravel-authz/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/wcz0/goravel-authz/releases/tag/v0.1.0
