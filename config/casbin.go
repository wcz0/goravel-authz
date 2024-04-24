package config

import (
	"github.com/goravel/framework/facades"
	"github.com/wcz0/goravel-authz/models"
)

func init() {
	config := facades.Config()
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
}
