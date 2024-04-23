package authz

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/goravel/framework/facades"
	"github.com/goravel/framework/support/path"
	"github.com/wcz0/goravel-authz/adapters"
)

// 创建 enforcer 实例
type EnforcerManager struct {
	*casbin.Enforcer
}

func NewEnforcer(g string) *casbin.Enforcer {
	if g == "" {
		g = facades.Config().GetString("casbin.default")
	}

	var m model.Model
	configType := config(g, "model.config_type").(string)
	if configType == "file" {
		filename := config(g, "model.config_file_path").(string)
		path := path.Config(filename)
		model, err := model.NewModelFromFile(path)
		if err != nil {
			panic("加载 model 文件失败")
		}
		m = model
	} else if configType == "text" {
		model, err := model.NewModelFromString(config(g, "model.config_text").(string))
		if err != nil {
			panic("加载 model 文本失败")
		}
		m = model
	}
	e, err := casbin.NewEnforcer(m, adapters.NewAdapter())
	if err != nil {
		panic("创建 enforcer 失败")
	}
	return e
}

func config(guard string, key string) any {
	return facades.Config().Get("casbin."+guard+"."+key, "")
}
