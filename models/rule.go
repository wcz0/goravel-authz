package models

import (
	contracts "github.com/goravel/framework/contracts/database/orm"

	"github.com/goravel/framework/facades"
)

type Rule struct {
	Id    uint `gorm:"primaryKey"`
	Ptype string
	V0    string
	V1    string
	V2    string
	V3    string
	V4    string
	V5    string
}

func NewRule() *Rule {
	return &Rule{}
}

func (r *Rule) TableName() string {
	return "casbin_rules"
}

func (r *Rule) Connection() string {
	return "mysql"
}

/**
 * Cache
 */
func (r *Rule) Cache() (bool, string, string) {
	return true, "memory", "casbin-key"
	// return false, "", ""
}

/**
 * casbin model
 */
func (r *Rule) Model() (string, string) {
	return "file", "casbin-rbac-model.conf"
	// return "text", `[request_definition]
	// r = sub, obj, act

	// [policy_definition]
	// p = sub, obj, act

	// [role_definition]
	// g = _, _

	// [policy_effect]
	// e = some(where (p.eft == allow))

	// [matchers]
	// m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act`
}

/**
 * Refresh Cache
 */
func (r *Rule) RefreshCache() {
	if ok, store, key := r.Cache(); !ok {
		return
	} else {
		cache := facades.Cache().Store(store)
		cache.Forget(key)
	}
}

/**
 * Dispatches events.
 */
func (r *Rule) DispatchesEvents() map[contracts.EventType]func(contracts.Event) error {
	return map[contracts.EventType]func(contracts.Event) error{

		contracts.EventSaved: func(event contracts.Event) error {
			r.RefreshCache()
			return nil
		},

		contracts.EventDeleted: func(event contracts.Event) error {
			r.RefreshCache()
			return nil
		},
	}
}

func (r *Rule) GetPtype() string {
	return r.Ptype
}

func (r *Rule) SetPtype(value string) {
	r.Ptype = value
}

func (r *Rule) GetV0() string {
	return r.V0
}

func (r *Rule) SetV0(value string) {
	r.V0 = value
}

func (r *Rule) GetV1() string {
	return r.V1
}

func (r *Rule) SetV1(value string) {
	r.V1 = value
}

func (r *Rule) GetV2() string {
	return r.V2
}

func (r *Rule) SetV2(value string) {
	r.V2 = value
}

func (r *Rule) GetV3() string {
	return r.V3
}

func (r *Rule) SetV3(value string) {
	r.V3 = value
}

func (r *Rule) GetV4() string {
	return r.V4
}

func (r *Rule) SetV4(value string) {
	r.V4 = value
}

func (r *Rule) GetV5() string {
	return r.V5
}

func (r *Rule) SetV5(value string) {
	r.V5 = value
}
