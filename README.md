# Goravel Authz

Authorization for [Goravel](https://github.com/goravel/goravel) built on [Casbin](https://casbin.org): ACL, RBAC and ABAC models backed by your own database table, with multiple independent enforcers, policy caching through the Goravel cache and route middleware.

[中文文档](./README_zh.md) · [Changelog](./CHANGELOG.md)

## Requirements

- Go 1.25+
- Goravel 1.17.x for this v1.17.x line; the other lines are listed below

Release lines follow the Goravel minor version. Pick the line that matches your framework:

| goravel-authz | Goravel |
| --- | --- |
| v1.18.x | v1.18.x |
| v1.17.x | v1.17.x |
| v1.16.x | v1.16.x |
| v1.15.x | v1.15.x |

## Installation

```shell
go get github.com/wcz0/goravel-authz@v1.17.2
```

Install the package resources and migrate:

```shell
go run . artisan package:install github.com/wcz0/goravel-authz
go run . artisan migrate
```

`package:install` registers `&authz.ServiceProvider{}` in `bootstrap/providers.go`, writes `config/casbin.go` and `config/casbin-rbac-model.conf`, and creates and registers the `casbin_rules` migration.

## Configuration

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

Each entry is a model. Every model owns its table, its database connection, its casbin model and its cache, which is how several enforcers can live in the same application:

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

// Optional: use a specific connection. Empty means the default connection.
func (r *AdminRule) Connection() string {
    return "mysql"
}

// Casbin model: "file" is resolved from the config directory, "text" is
// parsed as is.
func (r *AdminRule) Model() (string, string) {
    return "file", "casbin-rbac-model.conf"
}

// Cache: enabled, store name, key. An empty key is generated from the table
// name, so enforcers never share an entry.
func (r *AdminRule) Cache() (bool, string, string) {
    return true, "redis", "goravel-authz:admin"
}

// Optional: override the default 5 minute TTL.
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

### Caching

Caching uses the Goravel cache, so any configured store works. Set the store name in `Cache()` — for example `redis` — and keep the same store configured in `config/cache.go`. Policy rows are stored as JSON, which works with in-memory, file and Redis drivers.

The cache is flushed after every policy write (`AddPolicy`, `AddPolicies`, `RemovePolicy`, `RemovePolicies`, `RemoveFilteredPolicy`, the update methods and `SavePolicy`) and by the model events. Policies are cached for 5 minutes by default, or for the duration returned by an optional `CacheTTL()` method.

### Gate

When the service provider boots, Gate abilities that contain a comma are routed to Casbin:

```go
allowed := facades.Gate().WithContext(ctx).Allows("articles,read", map[string]any{
    "guard": "admin", // optional, defaults to casbin.default
})
```

This is evaluated as `Enforce(subject, "articles", "read")`. The subject is the value stored by `middleware.SetSubject` or, when that is empty, the ID of the authenticated Goravel Auth user. Abilities without a comma are left to the normal Gate implementation. Set `casbin.gate.enabled` to `false` to disable the hook.

## Usage

```go
import authz "github.com/wcz0/goravel-authz/facades"

e := authz.Enforcer()          // casbin.default
admin := authz.Enforcer("admin") // a second, independent enforcer

e.AddPolicy("admin", "/admin-api/users", "GET")
admin.AddPolicy("admin", "/api/users", "GET")

allowed, err := e.Enforce("alice", "/admin-api/users", "GET")
```

Enforcers are created on first use, cached per model name and safe for concurrent use (`casbin.SyncedEnforcer`).

### Batch, update and filtered operations

The adapter implements Casbin's batch, updatable and filtered interfaces, so the matching enforcer methods persist automatically:

```go
e.AddPolicies([][]string{{"editor", "/articles", "GET"}, {"editor", "/articles", "POST"}})
e.RemovePolicies([][]string{{"editor", "/articles", "POST"}})

e.UpdatePolicy([]string{"editor", "/articles", "GET"}, []string{"editor", "/articles", "read"})
e.UpdatePolicies(oldRules, newRules)
e.UpdateFilteredPolicies([][]string{{"editor", "/articles", "read"}}, 1, "/articles")
```

`LoadFilteredPolicy` loads a subset of the stored policies:

```go
import "github.com/wcz0/goravel-authz/adapters"

err := e.LoadFilteredPolicy(adapters.Filter{P: []string{"alice"}})
```

`adapters.Filter` mirrors Casbin's file filter (`P`, `G`, `G1` to `G5`); `adapters.FilterFunc` accepts an arbitrary predicate. While a filtered policy is loaded, `SavePolicy` is rejected because saving would delete the rows that were not loaded. The default ORM store runs every multi-row write in a transaction, so a failed batch leaves the table untouched.

When another process changes the policies, reload the current enforcer explicitly:

```go
import "github.com/wcz0/goravel-authz"

err := authz.Reload("basic")
```

## Middleware

`middleware.Authz` protects routes with your policies. Register it after your authentication middleware:

```go
import (
    "github.com/goravel/framework/contracts/route"
    "github.com/wcz0/goravel-authz/middleware"
)

facades.Route().Middleware(middleware.Authz()).Group(func(router route.Router) {
    router.Get("/admin/users", UserController{}.Index)
})
```

The defaults are:

- **guard**: `casbin.default` — use `middleware.WithGuard("admin")` for another model, or `middleware.WithGuards("basic", "admin")` to allow the request when any model allows it;
- **subject**: the value stored in the request context by `middleware.SetSubject`, falling back to the ID of the authenticated Goravel Auth user;
- **object**: the route pattern, `OriginPath()` (for example `/users/{id}`), falling back to `Path()`;
- **action**: the HTTP method.

An authentication middleware stores the subject when it is not the Goravel Auth ID:

```go
func Authenticate(ctx contractshttp.Context) {
    middleware.SetSubject(ctx, currentUserID(ctx))
    ctx.Request().Next()
}
```

Resolvers can be replaced when the defaults do not fit:

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

A request is allowed when `Enforce(subject, object, action)` returns true. A missing subject, a resolver error or a policy miss returns `403` with a JSON message; an enforcer error returns `500`. After another process changes the policies, call `authz.Reload` to refresh the local enforcer.

Use several models when a request may be authorized by any of them:

```go
middleware.Authz(middleware.WithGuards("basic", "admin"))
```

Every model is checked until one allows the request. If none allows and one enforcer failed, the middleware returns `500`; if every enforcer denied cleanly, it returns `403`. `middleware.WithGuard` and `middleware.WithGuards` replace each other, so the last option wins.

### Abilities

`middleware.Ability` checks fixed Casbin request values instead of the path and method:

```go
facades.Route().Get("/articles", ArticleController{}.Index).Middleware(
    middleware.Ability("articles", "read"),
)
```

This evaluates `Enforce(subject, "articles", "read")`. `middleware.WithTokens(...)` provides the same behavior inside `Authz`; the tokens replace the object and action, so models with extra request tokens can use it as well.

## Managing policies

The service provider registers Artisan commands for every model:

```shell
go run . artisan authz:policy:list
go run . artisan authz:policy:add admin /admin/users GET
go run . artisan authz:policy:remove admin /admin/users GET
go run . artisan authz:group:add alice admin
go run . artisan authz:group:remove alice admin
go run . artisan authz:enforce alice /admin/users GET
```

Every command accepts `--guard` (or `-g`) to target another model:

```shell
go run . artisan authz:policy:add admin /api/users GET --guard=admin
go run . artisan authz:enforce admin /api/users GET --guard=admin
```

Values are passed straight to Casbin, so models with more tokens (domains, for example) work as well. The commands validate the value count against the model, because Casbin accepts shorter rules silently.

Writes go to the database and refresh the policy cache. Other processes keep their in-memory policies; call `authz.Reload` or restart them to pick up the change.

## Logging

Authorization events are written through the Goravel logger, so they use the channels, level and formatter configured in `config/logging.go`:

```go
"log": map[string]any{
    "enabled": true,  // master switch
    "channel": "",    // empty uses logging.default
    "allowed": false, // log allowed requests at info level
    "denied":  true,  // log denied requests at warning level
    "casbin":  false, // forward Casbin diagnostics at debug level
},
```

Denied requests carry the guard, subject, object, action and a `reason` (`policy` or `missing subject`). Subject resolver and enforcer failures are logged at error level with the error attached. Enforcer creation and `authz.Reload` are logged at info level.

Set `casbin` to `true` to forward Casbin's model, policy and enforce output to the same channel at debug level. It is off by default because it is verbose. Outside a booted Goravel application the package stays silent, so unit tests and standalone tools need no logger.

## Testing

```shell
go test ./...
```

The adapter tests run against a real SQLite database through the Goravel ORM, including the cache round trip, so no Docker or external database is required.
