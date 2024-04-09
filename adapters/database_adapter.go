package adapters

import (
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/goravel/framework/facades"
	"github.com/wcz0/goravel-authz/models"
)

// func savePolicyLine(ptype string, rule []string) error {
// 	return nil
// }

// func loadPolicyLine(line string, model Model) {

// }
type Adapter struct {
	eloquent models.Rule
}

func NewAdapter() *Adapter {
	return &Adapter{
		eloquent: models.Rule{}, // Replace models.Rule with a valid expression that represents an instance of the models.Rule type
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
	a.eloquent = models.Rule{PType: ptype}
	if len(rule) > 0 {
		a.eloquent.V0 = rule[0]
	}
	if len(rule) > 1 {
		a.eloquent.V1 = rule[1]
	}
	if len(rule) > 2 {
		a.eloquent.V2 = rule[2]
	}
	if len(rule) > 3 {
		a.eloquent.V3 = rule[3]
	}
	if len(rule) > 4 {
		a.eloquent.V4 = rule[4]
	}
	if len(rule) > 5 {
		a.eloquent.V5 = rule[5]
	}
	// Save the rule to the database
	err := facades.Orm().Query().Create(&a.eloquent)
	if err != nil {
		return err
	}
	return nil
}

/**
 * Loads all policy rules from the storage.
 */
func (a *Adapter) LoadPolicy(model model.Model) error {
	row, _ := a.eloquent.GetAllFromCache()
	for _, rule := range row {
		err := a.loadPolicyLine(rule, model)
		if err != nil {
			return err
		}
	}
	return nil
}


func (a *Adapter) loadPolicyLine(rule models.Rule, model model.Model) error {
	var p = []string{rule.PType, rule.V0, rule.V1, rule.V2, rule.V3, rule.V4, rule.V5}
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
	_, err := query.Delete(&a.eloquent)
	if err != nil {
		return err
	}
	return nil
}

func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	query := facades.Orm().Query().Where("p_type", ptype)
	var removeRules []map[string]any
	for _, v := range fieldValues {
		// if fieldIndex <=
	}
	return nil
}


func (a *Adapter) loadFilteredPolicy(model model.Model, filter any) error {
	return nil
}

