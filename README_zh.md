# Goravel Authorization

Goravel-authz is 是 goravel 的授权扩展库.

它基于 [Casbin](https://github.com/casbin/casbin), 它支持 ACL, RBAC, ABAC 等访问控制模型的授权库.

你需要先学习如何使用 Casbin 的所有内容

## 安装

安装go包

```shell
go get -u github.com/wcz0/goravel-authz
```

在 config/app.goproviders 注册 provider

```go
// config/app.go
import "github.com/wcz0/goravel-authz"

"providers": []foundation.ServiceProvider{
    ...
    &authz.ServiceProvider{},
}
```

执行命令, 发布资源

```shell
go run . artisan vendor:publish --package=github.com/wcz0/goravel-authz
```

执行命令, 数据库迁移

```shell
go run . artisan migrate
```


## 使用

facades.Enforcer().GetPolicy()

```go
import authz "github.com/wcz-/goravel-authz/facades"

e := authz.Enforcer()
// second enforcer
e2 := authz.Enforcer("second")

e.AddPolicy("admin", "/admin-api/users", "GET")
e2.AddPolicy("admin", "/api/users", "GET")
policy := e.GetPolicy()

```

多个Enforcer

casbin.go
```go
//...
config.Add("casbin", map[string]any{
		// Casbin default
		"default": "basic",

		// 多个模型实现多个适配器
		"models": map[string]any{
			"basic": models.NewRule(),
			// second adapter
			"second": "",
		},
	})
```

second 是 第二个 模型 的 key
模型需要继承 models.Rule

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

/**
 * Cache
 */
func (r *Rule) Cache() (bool, string, string) {
	return true, "memory", "casbin-key"
	// return false, "", ""
}

/**
 * casbin model
 */
func (r *Rule) Model() (string, string) {
	return "file", "casbin-rbac-model.conf"
	// return "text", `[request_definition]
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



## 路线:

- 命令行创建策略
- 中间件实现
- 日志处理
- 单元测试 编写
