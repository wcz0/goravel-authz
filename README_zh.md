# Goravel Authorization

Goravel-authz is an authorization library for the goravel framework.

It's based on [Casbin](https://github.com/casbin/casbin), an authorization library that supports access control models like ACL, RBAC, ABAC.

All you need to learn to use Casbin first

- Installation

## 安装

use

```shell
go get -u github.com/wcz0/goravel-authz
```

执行命令, 发布资源

```shell
go run . artisan vendor:publish --package=github.com/wcz0/goravel-authz
```

执行命令, 数据库迁移

```shell
go run . artisan migrate
```


## 未来:

- 命令行创建策略
- 中间件实现
