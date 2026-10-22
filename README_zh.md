# Goravel Authz

基于 [Casbin](https://casbin.org) 的 [Goravel](https://github.com/goravel/goravel) 授权扩展库：支持 ACL、RBAC、ABAC 模型，策略存放在你自己的数据库表中，可以同时运行多套互相独立的 Enforcer，通过 Goravel 缓存加速策略加载，并提供路由中间件。

[English](./README.md) · [更新日志](./CHANGELOG.md)

## 环境要求

- Go 1.25+
- Goravel 1.18+

## 安装

```shell
go get github.com/wcz0/goravel-authz
```

安装资源并执行数据库迁移：

```shell
go run . artisan package:install github.com/wcz0/goravel-authz
go run . artisan migrate
```

`package:install` 会把 `&authz.ServiceProvider{}` 注册到 `bootstrap/providers.go`，生成 `config/casbin.go`、`config/casbin-rbac-model.conf`，并创建、注册 `casbin_rules` 表的迁移文件。安装器需要 v0.3.0 或更高版本。

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

## 命令行管理策略

服务提供者会为每个模型注册 Artisan 命令：

```shell
go run . artisan authz:policy:list
go run . artisan authz:policy:add admin /admin/users GET
go run . artisan authz:policy:remove admin /admin/users GET
go run . artisan authz:group:add alice admin
go run . artisan authz:group:remove alice admin
go run . artisan authz:enforce alice /admin/users GET
```

所有命令都支持 `--guard`（或 `-g`）切换到其他模型：

```shell
go run . artisan authz:policy:add admin /api/users GET --guard=admin
go run . artisan authz:enforce admin /api/users GET --guard=admin
```

参数会原样传给 Casbin，因此带 domain 等更多 token 的模型同样适用。由于 Casbin 会静默接受缺少字段的规则，命令会先按模型校验参数数量。

写入会立即落库并刷新策略缓存。其他进程仍持有内存中的策略，需要调用 `authz.Reload` 或重启后才能看到变更。

## 日志

授权事件通过 Goravel 日志写入，沿用 `config/logging.go` 中配置的通道、级别和格式：

```go
"log": map[string]any{
    "enabled": true,  // 总开关
    "channel": "",    // 留空使用 logging.default
    "allowed": false, // 放行的请求以 info 级别记录
    "denied":  true,  // 拒绝的请求以 warning 级别记录
    "casbin":  false, // 把 Casbin 内部日志以 debug 级别交给 Goravel
},
```

拒绝记录包含 guard、subject、object、action 和 `reason`（`policy` 或 `missing subject`）。subject 解析失败以及 enforcer 创建、执行失败会以 error 级别记录并附带错误。enforcer 首次创建和 `authz.Reload` 以 info 级别记录。

`casbin` 设为 true 后，Casbin 的 model、policy 和 enforce 输出会以 debug 级别写入同一通道；默认关闭，因为内容较多。在未启动 Goravel 应用的环境里包不会写日志，单元测试和独立工具无需配置 logger。

## 测试

```shell
go test ./...
```

适配器测试通过 Goravel ORM 直接跑在真实的 SQLite 数据库上，包含缓存往返测试，不需要 Docker 或外部数据库。
