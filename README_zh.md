# Goravel Authz

[![CI](https://github.com/wcz0/goravel-authz/actions/workflows/ci.yml/badge.svg?branch=goravel-1.17)](https://github.com/wcz0/goravel-authz/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/wcz0/goravel-authz.svg)](https://pkg.go.dev/github.com/wcz0/goravel-authz)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

[English](./README.md) · **简体中文** · [更新日志](./CHANGELOG.md)

基于 [Casbin](https://casbin.org) 的 [Goravel](https://github.com/goravel/goravel) 授权扩展库。策略存放在你自己的数据库表中，每套模型拥有独立的 Enforcer、数据表与缓存，再由路由中间件把策略变成 HTTP 决策。

- **Casbin 模型** — 支持 ACL、RBAC、ABAC，模型文本由你提供；安装时会生成一份可直接使用的 RBAC 模型，开箱即可生效。
- **互相独立的 Enforcer** — 一套模型一个实例，各自拥有数据表、数据库连接、模型文本和缓存；首次使用时创建，可并发使用。
- **完整的 Adapter 能力** — 实现了 Casbin 的 `BatchAdapter`、`UpdatableAdapter` 和 `FilteredAdapter`，批量、更新与过滤操作无需额外代码即可持久化。
- **事务写入** — 所有多行写入都在事务中执行，批量操作失败时数据表保持不变。
- **策略缓存** — 走 Goravel 缓存（内存、文件或 Redis），每次写入后自动失效。
- **原生 Goravel 集成** — 路由中间件、`Gate` 能力、`Auth` 用户、日志与 Artisan 命令。

## 目录

- [环境要求](#环境要求)
- [安装](#安装)
- [配置](#配置)
- [使用](#使用)
- [中间件](#中间件)
- [策略管理](#策略管理)
- [日志](#日志)
- [测试](#测试)
- [参与贡献](#参与贡献)
- [许可证](#许可证)

## 环境要求

- Go 1.24 或更高版本
- Goravel 1.17.x —— 本分支即 v1.17.x 版本线

版本号对齐 Goravel 次版本，每条版本线由独立分支发布，请选择与框架匹配的版本线：

| goravel-authz | 分支 | Goravel |
| --- | --- | --- |
| v1.18.x | `main` | v1.18.x |
| v1.17.x | `goravel-1.17` | v1.17.x |
| v1.16.x | `goravel-1.16` | v1.16.x |
| v1.15.x | `goravel-1.15` | v1.15.x |

## 安装

```shell
go get github.com/wcz0/goravel-authz@v1.17.2
```

安装扩展资源并执行迁移：

```shell
go run . artisan package:install github.com/wcz0/goravel-authz
go run . artisan migrate
```

`package:install` 会在应用启动文件中注册 `&authz.ServiceProvider{}`，生成 `config/casbin.go` 与 `config/casbin-rbac-model.conf`，并创建、注册 `casbin_rules` 迁移。`package:uninstall` 会把以上内容全部撤销。

## 配置

```go
// config/casbin.go
func init() {
    config := facades.Config()
    config.Add("casbin", map[string]any{
        "default": "basic",
        "models": map[string]any{
            "basic": models.NewRule(),
        },
        "log": map[string]any{
            "enabled": true,
            "channel": "",
            "allowed": false,
            "denied":  true,
            "casbin":  false,
        },
        "gate": map[string]any{
            "enabled": true,
        },
    })
}
```

`models` 下的每一项就是一套模型：它拥有自己的数据表、数据库连接、Casbin 模型与缓存。这正是同一个应用里可以同时运行多套 Enforcer 的原因。

```go
import "github.com/wcz0/goravel-authz/models"

type AdminRule struct {
    *models.Rule
}

func NewAdminRule() *AdminRule {
    return &AdminRule{Rule: &models.Rule{}}
}

func (r *AdminRule) TableName() string {
    return "admin_casbin_rules"
}

// 可选：指定数据库连接，留空表示使用默认连接。
func (r *AdminRule) Connection() string {
    return "mysql"
}

// Casbin 模型："file" 从 config 目录解析，"text" 按原样解析。
func (r *AdminRule) Model() (string, string) {
    return "file", "casbin-rbac-model.conf"
}

// 缓存：是否启用、缓存驱动名、缓存键。键留空时按表名生成，
// 因此不同 Enforcer 不会共用同一条缓存。
func (r *AdminRule) Cache() (bool, string, string) {
    return true, "redis", "goravel-authz:admin"
}

// 可选：覆盖默认的 5 分钟过期时间。
func (r *AdminRule) CacheTTL() time.Duration {
    return 10 * time.Minute
}
```

```go
config.Add("casbin", map[string]any{
    "default": "basic",
    "models": map[string]any{
        "basic":  models.NewRule(),
        "admin":  NewAdminRule(),
    },
})
```

### 缓存

缓存走 Goravel 缓存，任何已配置的驱动都可以使用。在 `Cache()` 中指定驱动名（例如 `redis`），并在 `config/cache.go` 中保持同一驱动配置即可。策略行以 JSON 存储，内存、文件与 Redis 驱动都兼容。

每次策略写入（`AddPolicy`、`AddPolicies`、`RemovePolicy`、`RemovePolicies`、`RemoveFilteredPolicy`、各更新方法与 `SavePolicy`）以及模型事件都会刷新缓存。默认缓存 5 分钟，也可以实现 `CacheTTL()` 自定义。

### Gate

服务提供者启动后，带逗号的 Gate 能力会转交给 Casbin：

```go
allowed := facades.Gate().WithContext(ctx).Allows("articles,read", map[string]any{
    "guard": "admin", // 可选，默认取 casbin.default
})
```

它会被求值为 `Enforce(subject, "articles", "read")`。subject 取 `middleware.SetSubject` 写入的值；该值为空时回退到已登录的 Goravel Auth 用户 ID。不带逗号的能力仍交给 Gate 原有实现。把 `casbin.gate.enabled` 设为 `false` 可关闭该钩子。

## 使用

```go
import authz "github.com/wcz0/goravel-authz/facades"

e := authz.Enforcer()            // casbin.default
admin := authz.Enforcer("admin") // 第二套互相独立的 Enforcer

e.AddPolicy("admin", "/admin-api/users", "GET")
admin.AddPolicy("admin", "/api/users", "GET")

allowed, err := e.Enforce("alice", "/admin-api/users", "GET")
```

Enforcer 在首次使用时创建，按模型名缓存，并且可以并发使用（`casbin.SyncedEnforcer`）。创建过程按模型加锁，某套模型的首次加载再慢也不会阻塞其他模型。

### 批量、更新与过滤操作

Adapter 实现了 Casbin 的批量、可更新与可过滤接口，对应的 Enforcer 方法会自动持久化：

```go
e.AddPolicies([][]string{{"editor", "/articles", "GET"}, {"editor", "/articles", "POST"}})
e.RemovePolicies([][]string{{"editor", "/articles", "POST"}})

e.UpdatePolicy([]string{"editor", "/articles", "GET"}, []string{"editor", "/articles", "read"})
e.UpdatePolicies(oldRules, newRules)
e.UpdateFilteredPolicies([][]string{{"editor", "/articles", "read"}}, 1, "/articles")
```

`LoadFilteredPolicy` 只加载存储中的一部分策略：

```go
import "github.com/wcz0/goravel-authz/adapters"

err := e.LoadFilteredPolicy(adapters.Filter{P: []string{"alice"}})
```

`adapters.Filter` 对应 Casbin 的文件过滤器（`P`、`G`、`G1` 到 `G5`），`adapters.FilterFunc` 接收任意判定函数。处于过滤加载状态时 `SavePolicy` 会被拒绝，否则保存会删除那些未被加载的行。默认 ORM 存储把每次多行写入放在事务中，批量失败时数据表保持原样。

当其他进程修改了策略，需要显式重载当前 Enforcer：

```go
import "github.com/wcz0/goravel-authz"

err := authz.Reload("basic")
```

## 中间件

`middleware.Authz` 用你的策略保护路由，请注册在认证中间件之后：

```go
import (
    "github.com/goravel/framework/contracts/route"
    "github.com/wcz0/goravel-authz/middleware"
)

facades.Route().Middleware(middleware.Authz()).Group(func(router route.Router) {
    router.Get("/admin/users", UserController{}.Index)
})
```

默认行为：

- **guard**：`casbin.default`。用 `middleware.WithGuard("admin")` 指定其他模型，或用 `middleware.WithGuards("basic", "admin")` 让任一模型放行即可通过；
- **subject**：`middleware.SetSubject` 写入请求上下文的值，为空时回退到已登录的 Goravel Auth 用户 ID；
- **object**：路由模式 `OriginPath()`（例如 `/users/{id}`），为空时回退到 `Path()`；
- **action**：HTTP 方法。

当 subject 不是 Goravel Auth 用户 ID 时，由认证中间件写入：

```go
func Authenticate(ctx contractshttp.Context) {
    middleware.SetSubject(ctx, currentUserID(ctx))
    ctx.Request().Next()
}
```

默认解析方式不适用时可以替换：

```go
middleware.Authz(
    middleware.WithGuard("admin"),
    middleware.WithSubject(func(ctx contractshttp.Context) (string, error) {
        return claimsFrom(ctx).Subject, nil
    }),
    middleware.WithObject(func(ctx contractshttp.Context) string {
        return ctx.Request().Path()
    }),
    middleware.WithDenied(func(ctx contractshttp.Context, decision middleware.Decision) {
        ctx.Response().Json(403, contractshttp.Json{"message": "Forbidden"}).Abort()
    }),
)
```

`Enforce(subject, object, action)` 返回 true 即放行。subject 缺失、解析出错或没有匹配策略时返回 `403` 与 JSON 消息；Enforcer 自身出错返回 `500`。其他进程修改策略后，调用 `authz.Reload` 刷新本地 Enforcer。

一个请求可能被多套模型授权时，可以同时启用多个模型：

```go
middleware.Authz(middleware.WithGuards("basic", "admin"))
```

中间件会依次检查，任一模型放行即通过。如果全部拒绝且其中有 Enforcer 出错，返回 `500`；全部正常拒绝则返回 `403`。`middleware.WithGuard` 与 `middleware.WithGuards` 互相覆盖，以最后一个选项为准。

### 固定能力

`middleware.Ability` 用固定的 Casbin 请求值代替路径与方法：

```go
facades.Route().Get("/articles", ArticleController{}.Index).Middleware(
    middleware.Ability("articles", "read"),
)
```

它会被求值为 `Enforce(subject, "articles", "read")`。在 `Authz` 内部可以用 `middleware.WithTokens(...)` 达到同样效果；这些 token 会替换 object 与 action，因此请求参数更多的模型同样适用。

## 策略管理

服务提供者为每套模型注册了 Artisan 命令：

```shell
go run . artisan authz:policy:list
go run . artisan authz:policy:add admin /admin/users GET
go run . artisan authz:policy:remove admin /admin/users GET
go run . artisan authz:group:add alice admin
go run . artisan authz:group:remove alice admin
go run . artisan authz:enforce alice /admin/users GET
```

所有命令都支持 `--guard`（或 `-g`）指定其他模型：

```shell
go run . artisan authz:policy:add admin /api/users GET --guard=admin
go run . artisan authz:enforce admin /api/users GET --guard=admin
```

参数会原样传给 Casbin，因此带更多参数（例如域）的模型同样可用。命令会按模型校验参数个数，因为 Casbin 对参数不足的规则会静默接受。

写入会落到数据库并刷新策略缓存。其他进程仍持有自己的内存策略，需要调用 `authz.Reload` 或重启才能生效。

## 日志

授权事件通过 Goravel 日志输出，因此沿用 `config/logging.go` 中配置的通道、级别与格式：

```go
"log": map[string]any{
    "enabled": true,  // 总开关
    "channel": "",    // 留空使用 logging.default
    "allowed": false, // 以 info 级别记录放行请求
    "denied":  true,  // 以 warning 级别记录拒绝请求
    "casbin":  false, // 以 debug 级别转发 Casbin 内部诊断
},
```

拒绝请求会带上 guard、subject、object、action 以及 `reason`（`policy` 或 `missing subject`）。subject 解析与 Enforcer 出错会以 error 级别连同错误一起记录。Enforcer 创建和 `authz.Reload` 以 info 级别记录。

把 `casbin` 设为 `true` 可以把 Casbin 的模型、策略与判定输出以 debug 级别转发到同一通道，默认关闭是因为内容较多。在没有启动 Goravel 应用的环境里，本包保持静默，因此单元测试和独立工具不需要配置日志。

## 测试

```shell
go test ./...
```

适配器测试通过 Goravel ORM 跑在真实的 SQLite 数据库上，包含缓存往返测试，不需要 Docker 或外部数据库。CI 还会用 `-race` 跑一遍完整测试。

## 参与贡献

欢迎提交 issue 和 pull request。提交前请先执行：

```shell
gofmt -l .
go vet ./...
go test ./...
```

CI 会在每条版本线上执行同样的检查并额外运行 `go test -race`；如果分支名与所依赖的 Goravel 版本不一致，CI 会直接拒绝。

## 许可证

[MIT](./LICENSE) © 2024 wcz0
