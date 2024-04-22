package authz

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/goravel/framework/facades"
	"github.com/wcz0/goravel-authz/adapters"
	"github.com/wcz0/goravel-authz/models"
)

var Guards = make(map[string]*casbin.Enforcer)

// 创建 enforcer 实例
type EnforcerManager struct {
}

func NewEnforcer() *casbin.Enforcer {
	return guard("")
}

func (e *EnforcerManager) Guard(g string) *casbin.Enforcer {
	return  guard(g)
}

func guard(g string) *casbin.Enforcer {
	if g == "" {
		g = facades.Config().GetString("casbin.default")
	}
	if _, ok := Guards[g]; !ok {
		var m model.Model
		configType := config(g, "model.config_type").(string)
		if configType == "file" {
			m, _ = model.NewModelFromFile(config(models.Guard, "model.config_file_path").(string))
		} else if configType == "text" {
			m, _ = model.NewModelFromString(config(g, "model.config_text").(string))
		}
		rule := models.NewRule(g)
		Guards[g], _ = casbin.NewEnforcer(m, adapters.NewAdapter(rule))
	}
	return Guards[g]
}

func config(guard string, key string) any {
	return facades.Config().GetString("casbin."+guard+"."+key, "")
}
