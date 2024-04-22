# aGoravel Authorization

Goravel-authz is an authorization extension library for Goravel. It is built upon Casbin, which supports various access control models such as ACL (Access Control List), RBAC (Role-Based Access Control), and ABAC (Attribute-Based Access Control).

Before using Goravel-authz, you should first familiarize yourself with all aspects of working with Casbin.

## Installation

Install the Go package:

```shell
go get -u github.com/wcz0/goravel-authz
```

Execute the command to publish resources:

```shell
go run . artisan vendor:publish --package=github.com/wcz0/goravel-authz
```

Run the migration command for the database:

```shell
go run . artisan migrate
```

Register the provider in your config/app.go file:

```go
// config/app.go
import "github.com/wcz0/goravel-authz"

// ...

"providers": []foundation.ServiceProvider{
    // ...
    &goravel_authz.ServiceProvider{},
},
```

## Usage

Accessing policies through the facade:

```go
import gauthz "github.com/wcz0/goravel-authz/facades"

// Get the enforcer instance
e := gauthz.Enforcer()
policy := e.GetPolicy()

// Alternatively, retrieve the enforcer instance from the service container
e := app.Make("casbin")
```

## Future Developments:

- Command-line creation of policies
- Middleware implementation
- Logging handling
- Unit test caes
