package goravelcasbin

import "github.com/goravel/framework/facades"



// func NewEnforcerManager() *EnforcerManager {
// 	return &EnforcerManager{}
// }

// 获取配置信息
func GetConfig(name string) any {
	return facades.Config().Get("casbin." + name)
}

func GetDefaultGuard() string {
	return facades.Config().GetString("casbin.default")
}

