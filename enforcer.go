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
	config := facades.Config()
	if g == "" {
		g = config.GetString("casbin.default")
	}
	ruleImpl := config.Get("casbin.models." + g)
	var rule adapters.Rule = ruleImpl.(adapters.Rule)
	configType, contextArg := rule.Model()
	var m model.Model
	if configType == "file" {
		path := path.Config(contextArg)
		modelInstance, err := model.NewModelFromFile(path)
		if err != nil {
			panic("加载 model 文件失败: " + err.Error())
		}
		m = modelInstance
	} else if configType == "text" {
		modelInstance, err := model.NewModelFromString(contextArg)
		if err != nil {
			panic("加载 model 文本失败: " + err.Error())
		}
		m = modelInstance
	}
	a := adapters.NewAdapter(rule)
	e, err := casbin.NewEnforcer(m, a)
	if err != nil {
		panic("创建 enforcer 失败: " + err.Error())
	}
	return e
}
