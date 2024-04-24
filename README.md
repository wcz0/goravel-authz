# Goravel Authorization

Goravel-authz is an authorization extension library for Goravel. It is built upon Casbin, which supports various access control models such as ACL (Access Control List), RBAC (Role-Based Access Control), and ABAC (Attribute-Based Access Control).

Before using Goravel-authz, you should first familiarize yourself with all aspects of working with Casbin.

[中文文档](./README_zh.md)

## Installation

Install the Go package:

```shell
go get -u github.com/wcz0/goravel-authz
```

Register the provider in your config/app.go file:

```go
// config/app.go
import "github.com/wcz0/goravel-authz"

// ...

"providers": []foundation.ServiceProvider{
    // ...
    &authz.ServiceProvider{},
},
```

Execute the command to publish resources:

```shell
go run . artisan vendor:publish --package=github.com/wcz0/goravel-authz
```

Run the migration command for the database:

```shell
go run . artisan migrate
```


## Usage

Accessing policies through the facade:

facades.Enforcer().GetPolicy()

```go
import authz "github.com/wcz-/goravel-authz/facades"

e := authz.Enforcer()
// Second enforcer
e2 := authz.Enforcer("second")

e.AddPolicy("admin", "/admin-api/users", "GET")
e2.AddPolicy("admin", "/api/users", "GET")
policy := e.GetPolicy()

```

### Multiple Enforcers

casbin.go

```go
//...
config.Add("casbin", map[string]any{
    "default": "basic", // Casbin default
    "models": map[string]any{
        "basic": models.NewRule(),
        "second": "", // Second adapter
    },
})
```

For the second model, the key is second. The model needs to inherit from models.Rule.

```go
import "github.com/wcz0/goravel-authz/models"

type AdminRule struct {
    *models.Rule
}

func NewAdminRule() *AdminRule {
    return &AdminRule{
        Rule: &models.Rule{},
    }
}

func (r *Rule) TableName() string {
    return "casbin_rules"
}

func (r *Rule) Connection() string {
    return "mysql"
}

// Cache configuration
func (r *Rule) Cache() (bool, string, string) {
    return true, "memory", "casbin-key"
    // To disable cache, return false, "", ""
}

// Casbin model configuration
func (r *Rule) Model() (string, string) {
    return "file", "casbin-rbac-model.conf"
    // To use text model, return "text", `[request_definition]
    // r = sub, obj, act
    // [policy_definition]
    // p = sub, obj, act
    // [role_definition]
    // g = _, _
    // [policy_effect]
    // e = some(where (p.eft == allow))
    // [matchers]
    // m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act`
}
```



## Future Developments:

- Command-line creation of policies
- Middleware implementation
- Logging handling
- Unit test caes