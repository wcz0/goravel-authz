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
import gauthz "github.com/wcz0/goravel-authz"

"providers": []foundation.ServiceProvider{
    ...
    &gauthz.ServiceProvider{},
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

facades.enforcer().GetPolicy()

```go
import gauthz "github.com/wcz-/goravel-authz/facades"

e := gauthz.Enforcer()
policy := e.GetPolicy()

// get enforce instance
e := app.Make('casbin')


```

## 未来:

- 命令行创建策略
- 中间件实现
- 日志处理
- 单元测试 编写
