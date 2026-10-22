# Goravel Authz

Authorization for [Goravel](https://github.com/goravel/goravel) built on [Casbin](https://casbin.org): ACL, RBAC and ABAC models backed by your own database table, with multiple independent enforcers and policy caching through the Goravel cache.

[中文文档](./README_zh.md)

## Requirements

- Go 1.25+
- Goravel 1.18+

## Installation

```shell
go get github.com/wcz0/goravel-authz
```

Register the service provider in `bootstrap/providers.go`:

```go
import "github.com/wcz0/goravel-authz"

// ...
"providers": []foundation.ServiceProvider{
    // ...
    &authz.ServiceProvider{},
},
```

Publish the configuration and the migration, then migrate:

```shell
go run . artisan vendor:publish --package=github.com/wcz0/goravel-authz
go run . artisan migrate
```

`vendor:publish` creates `config/casbin.go`, `config/casbin-rbac-model.conf` and the `casbin_rules` migration.

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

The cache is flushed after every policy write (`AddPolicy`, `RemovePolicy`, `RemoveFilteredPolicy`, `SavePolicy`) and by the model events. Policies are cached for 5 minutes by default, or for the duration returned by an optional `CacheTTL()` method.

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

When another process changes the policies, reload the current enforcer explicitly:

```go
import "github.com/wcz0/goravel-authz"

err := authz.Reload("basic")
```

## Testing

```shell
go test ./...
```

The adapter tests run against a real SQLite database through the Goravel ORM, including the cache round trip, so no Docker or external database is required.

## Roadmap

- HTTP middleware
- Artisan commands to manage policies
- Goravel logger integration
