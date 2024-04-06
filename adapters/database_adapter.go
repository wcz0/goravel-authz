package adapters

import (
	"github.com/casbin/casbin/v2/model"
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
func (a *Adapter) SavePolicy(model model.Model) {
	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			a.savePolicyLine(ptype, rule)
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			a.savePolicyLine(ptype, rule)
		}
	}
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) savePolicyLine(ptype string, rule []string) {
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
	facades.Orm().Query().Create(&a.eloquent)
}

func (a *Adapter) LoadPolicy(model model.Model) {
	// TODO: 从缓存读取


	// return nil
}

func (a *Adapter) loadPolicyLine(sec string, ptype string, rule []string) {
	// return nil
}

func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	return nil
}

func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	return nil
}

func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return nil
}

