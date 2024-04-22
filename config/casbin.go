package config

import (
	"github.com/goravel/framework/facades"
	"github.com/goravel/framework/support/path"
)

func init() {
	config := facades.Config()
	config.Add("casbin", map[string]any{
		// Casbin default
		"default": "basic",

		"basic": map[string]any{
			"model": map[string]any{
				// TODO: Casbin model text
				"config_type":      "file",
				"config_file_path": path.Config() + "casbin-rbac-model.conf",
				// TODO: Casbin model text
				// "config_text":      "",
			},
			// TODO: Casbin adapter . it is default adapter
			"adapter": "",

			// goravel database type
			"database": map[string]any{
				"connection":  "mysql",
				"rules_table": "casbin_rules",
			},

			// TODO: Casbin Logger
			// "log": map[string]any{
			//     "enabled": false,
			//     "logger": "log",
			// },

			// store cache for goravel cache
			"cache": map[string]any{
				"enabled": true,
				// goravel cache store
				"store": "memory",
				"key":   "casbin",
				"ttl":   60 * 60,
			},
		},
		// 第二个 Casbin 配置, 注意!, 需要自己创建对应的数据库表
		"second": map[string]any{
			"model": map[string]any{
				"config_type":      "file",
				"config_file_path": path.Config() + "casbin-rbac-model.conf",
			},


			"database": map[string]any{
				"connection":  "mysql",
				"rules_table": "casbin_rules_second",
			},


			"cache": map[string]any{
				"enabled": false,
				"store":   "default",
				"key":     "casbin",
				"ttl":     24 * 60,
			},
		},
	})
}
