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
policy := e.GetPolicy()

```

## 路线:

- 命令行创建策略
- 中间件实现
- 日志处理
- 单元测试 编写
- 多个 adapter 支持
