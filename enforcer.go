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
	var rule adapters.Rule
	if ruleImpl == nil {
		panic("casbin: model " + g + " is not defined in the casbin.models configuration")
	}
	rule, ok := ruleImpl.(adapters.Rule)
	if !ok {
		panic("casbin: model " + g + " must implement adapters.Rule")
	}
	configType, contextArg := rule.Model()
	var m model.Model
	switch configType {
	case "file":
		modelPath := path.Config(contextArg)
		modelInstance, err := model.NewModelFromFile(modelPath)
		if err != nil {
			panic("加载 model 文件失败: " + err.Error())
		}
		m = modelInstance
	case "text":
		modelInstance, err := model.NewModelFromString(contextArg)
		if err != nil {
			panic("加载 model 文本失败: " + err.Error())
		}
		m = modelInstance
	default:
		panic("casbin: model " + g + " has an unsupported Model() type: " + configType)
	}
	a := adapters.NewAdapter(rule)
	e, err := casbin.NewEnforcer(m, a)
	if err != nil {
		panic("创建 enforcer 失败: " + err.Error())
	}
	return e
}
