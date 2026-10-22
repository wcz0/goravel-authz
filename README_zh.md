# Goravel Authz

基于 [Casbin](https://casbin.org) 的 [Goravel](https://github.com/goravel/goravel) 授权扩展库：支持 ACL、RBAC、ABAC 模型，策略存放在你自己的数据库表中，可以同时运行多套互相独立的 Enforcer，通过 Goravel 缓存加速策略加载，并提供路由中间件。

[English](./README.md)

## 环境要求

- Go 1.25+
- Goravel 1.18+

## 安装

```shell
go get github.com/wcz0/goravel-authz
```

在 `bootstrap/providers.go` 中注册服务提供者：

```go
import "github.com/wcz0/goravel-authz"

// ...
"providers": []foundation.ServiceProvider{
    // ...
    &authz.ServiceProvider{},
},
```

发布配置文件与迁移文件，然后执行迁移：

```shell
go run . artisan vendor:publish --package=github.com/wcz0/goravel-authz
go run . artisan migrate
```

`vendor:publish` 会生成 `config/casbin.go`、`config/casbin-rbac-model.conf` 和 `casbin_rules` 表的迁移文件。

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
    })
}
```

`models` 中的每一项就是一套模型。每套模型拥有自己的数据表、数据库连接、Casbin 模型和缓存，因此同一个应用里可以并存多个 Enforcer：

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

// 可选：指定数据库连接。返回空字符串表示使用默认连接。
func (r *AdminRule) Connection() string {
    return "mysql"
}

// Casbin 模型："file" 从配置目录解析，"text" 按原样解析。
func (r *AdminRule) Model() (string, string) {
    return "file", "casbin-rbac-model.conf"
}

// 缓存：是否启用、缓存 store 名称、键名。键名为空时根据表名自动生成，
// 不同 Enforcer 因此不会共用同一条缓存。
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

缓存完全使用 Goravel 的缓存，任意已配置的 store 都可以。在 `Cache()` 中填写 store 名称（例如 `redis`），并在 `config/cache.go` 中配置同名的 store 即可。策略记录以 JSON 形式存储，内存、文件、Redis 驱动都可以直接使用。

每次写入策略（`AddPolicy`、`RemovePolicy`、`RemoveFilteredPolicy`、`SavePolicy`）以及模型事件触发时都会自动清除缓存。默认缓存 5 分钟，也可以通过可选的 `CacheTTL()` 方法自定义。

## 使用

```go
import authz "github.com/wcz0/goravel-authz/facades"

e := authz.Enforcer()            // casbin.default 对应的 Enforcer
admin := authz.Enforcer("admin") // 第二套独立的 Enforcer

e.AddPolicy("admin", "/admin-api/users", "GET")
admin.AddPolicy("admin", "/api/users", "GET")

allowed, err := e.Enforce("alice", "/admin-api/users", "GET")
```

Enforcer 在第一次使用时创建，按模型名称缓存，并且是并发安全的（`casbin.SyncedEnforcer`）。

当其他进程修改了策略，需要显式重载当前进程的 Enforcer：

```go
import "github.com/wcz0/goravel-authz"

err := authz.Reload("basic")
```

## 中间件

`middleware.Authz` 用策略保护路由，需要注册在认证中间件之后：

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

- **guard**：`casbin.default`，可用 `middleware.WithGuard("admin")` 切换到其他模型；
- **subject**：由 `middleware.SetSubject` 写入请求上下文的值；
- **object**：路由模板 `OriginPath()`（例如 `/users/{id}`），为空时回退到 `Path()`；
- **action**：HTTP 方法。

认证中间件先运行，并写入 subject：

```go
func Authenticate(ctx contractshttp.Context) {
    middleware.SetSubject(ctx, currentUserID(ctx))
    ctx.Request().Next()
}
```

默认行为不适用时可以替换解析逻辑：

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

当 `Enforce(subject, object, action)` 返回 true 时放行。subject 缺失、解析器报错或策略未命中时返回 `403` 和 JSON 消息；Enforcer 出错时返回 `500`。其他进程修改策略后，调用 `authz.Reload` 让当前进程的 Enforcer 重新加载。

## 测试

```shell
go test ./...
```

适配器测试通过 Goravel ORM 直接跑在真实的 SQLite 数据库上，包含缓存往返测试，不需要 Docker 或外部数据库。

## 路线图

- Artisan 命令管理策略
- 接入 Goravel 日志
