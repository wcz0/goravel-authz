package adapters

import (

	"time"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/goravel/framework/facades"
)

type Rule interface {
	SetPtype(value string)
	GetPtype() string
	SetV0(value string)
	GetV0() string
	SetV1(value string)
	GetV1() string
	SetV2(value string)
	GetV2() string
	SetV3(value string)
	GetV3() string
	SetV4(value string)
	GetV4() string
	SetV5(value string)
	GetV5() string
	// model 类型, model 值
	Model() (string, string)
	// 是否从缓存中获取, 缓存store, 缓存key
	Cache() (bool, string, string)
	// 刷新缓存方式
	RefreshCache()
}

type Adapter struct {
	eloquent Rule
}

func NewAdapter(r Rule) *Adapter {
	return &Adapter{
		eloquent: r,
	}
}

// SavePolicy saves
func (a *Adapter) SavePolicy(model model.Model) error {
	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			err := a.savePolicyLine(ptype, rule)
			if err != nil {
				return err
			}
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			err := a.savePolicyLine(ptype, rule)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) savePolicyLine(ptype string, rule []string) error {
	a.eloquent.SetPtype(ptype)
	if len(rule) > 0 {
		a.eloquent.SetV0(rule[0])
	}
	if len(rule) > 1 {
		a.eloquent.SetV1(rule[1])
	}
	if len(rule) > 2 {
		a.eloquent.SetV2(rule[2])
	}
	if len(rule) > 3 {
		a.eloquent.SetV3(rule[3])
	}
	if len(rule) > 4 {
		a.eloquent.SetV4(rule[4])
	}
	if len(rule) > 5 {
		a.eloquent.SetV5(rule[5])
	}
	// Save the rule to the database
	err := facades.Orm().Query().Create(a.eloquent)
	if err != nil {
		return err
	}
	return nil
}

/**
 * Loads all policy rules from the storage.
 */
func (a *Adapter) LoadPolicy(model model.Model) error {
	// var row []Rule
	// 是否从缓存中获取
	row, err := a.getAllFromCache()
	if err != nil {
		return err
	}
	for _, rule := range row {
		err := a.loadPolicyLine(rule, model)
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *Adapter) getAllFromCache() ([]Rule, error) {
	// 是否从缓存中获取
	if ok, store, key := a.eloquent.Cache(); ok {
		cache := facades.Cache().Store(store)
		ttl := 5 * 60 * time.Second
		result, err := cache.Remember(key, ttl, func() (any, error) {
			return a.getPolicy(), nil
		})
		if err != nil {
			return nil, err
		}
		return result.([]Rule), nil
	} else {
		// 从数据库中获取
		return a.getPolicy(), nil
	}
}

// func (a *Adapter) (value string) {
// 	a.eloquent.SetPtype(value)
// }

func (a *Adapter) getPolicy() []Rule {
	var rules = []Rule{}
	facades.Orm().Query().Select("ptype", "v0", "v1", "v2", "v3", "v4", "v5").Get(&rules)
	return rules
}

func (a *Adapter) loadPolicyLine(rule Rule, model model.Model) error {
	var p = []string{
		rule.GetPtype(),
		rule.GetV0(),
		rule.GetV1(),
		rule.GetV2(),
		rule.GetV3(),
		rule.GetV4(),
		rule.GetV5(),
	}
	i := len(p) - 1
	for p[i] == "" {
		i--
	}
	i += 1
	p = p[:i]
	err := persist.LoadPolicyArray(p, model)
	if err != nil {
		return err
	}
	return nil
}

/**
 * Adds a policy rule to the storage.
 */
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	err := a.savePolicyLine(ptype, rule)
	if err != nil {
		return err
	}
	return nil
}

/**
 * Removes a policy rule from the storage.
 */
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	query := facades.Orm().Query().Where("p_type", ptype)
	for i, v := range rule {
		query = query.Where("v"+string(rune(i)), v)
	}
	_, err := query.Delete(a.eloquent)
	if err != nil {
		return err
	}
	return nil
}

/**
 * Removes policy rules that match the filter from the storage.
 */
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	// var rules []models.Rule
	query := facades.Orm().Query().Where("p_type", ptype)
	// var removeRules []map[string]any
	for i := range make([]int, 5) {
		if fieldIndex <= i && i < fieldIndex+len(fieldValues) {
			if fieldValues[i-fieldIndex] != "" {
				query = query.Where("v"+string(rune(i)), fieldValues[i-fieldIndex])
			}
		}
	}

	// 保存删除的规则, 不知有何用意
	// err := query.Get(a.eloquent)
	// if err != nil {
	// 	return err
	// }
	// for _, rule := range rules {
	// 	removeRules = append(removeRules, map[string]any{"p_type": rule.PType, "v0": rule.V0, "v1": rule.V1, "v2": rule.V2, "v3": rule.V3, "v4": rule.V4, "v5": rule.V5})
	// }
	_, err := query.Delete(a.eloquent)
	if err != nil {
		return err
	}
	return nil
}