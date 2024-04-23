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
policy := e.GetPolicy()

```

## Future Developments:

- Command-line creation of policies
- Middleware implementation
- Logging handling
- Unit test caes