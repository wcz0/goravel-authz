package goravelcasbin

import "github.com/goravel/framework/contracts/foundation"

const Binding = "goravelcasbin"

var App foundation.Application

type ServiceProvider struct {
}

// Register the service provider.
func (receiver *ServiceProvider) Register(app foundation.Application) {
	App = app

	app.Bind(Binding, func(app foundation.Application) (any, error) {
		return nil, nil
	})
}

func (receiver *ServiceProvider) Boot(app foundation.Application) {
	// 配置文件&模型配置文件
	app.Publishes("github.com/wcz0/goravel-casbin", map[string]string{
		"config": app.ConfigPath(""),
	})
	// 数据库迁移文件
	app.Publishes("github.com/wcz0/goravel-casbin", map[string]string{
		"database": app.DatabasePath("migrations"),
	})
}
