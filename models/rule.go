package models

import (
	"sync"
	"time"

	contractsorm "github.com/goravel/framework/contracts/database/orm"

	"github.com/goravel/framework/contracts/cache"
	"github.com/goravel/framework/database/orm"
	"github.com/goravel/framework/facades"
)

type Rule struct {
	orm.Model
	Id    uint
	PType string
	V0    string
	V1    string
	V2    string
	V3    string
	V4    string
	V5    string
}

var (
	Store      cache.Driver
	Guard      string
	Table      string
	Connection string
)

func NewRule() *Rule {
	Guard = facades.Config().GetString("casbin.default")
	Connection = config("database.connection", "").(string)
	Table = config("database.rules_table", "").(string)
	initCache()
	return &Rule{}
}

func (r *Rule) Guard(guard string) {
	var once sync.Once
	once.Do(func() {
		if guard == "" {
			Guard = facades.Config().GetString("casbin.default")
		} else {
			Guard = guard
		}
		Connection = func(a, b string) string {
			if a != "" {
				return a
			}
			return b
		}(config("database.connection", "").(string), facades.Config().GetString("database.default"))
		Table = config("database.rules_table", "").(string)
		initCache()
	})
}

// get policy from cache
func (r *Rule) GetAllFromCache() ([]Rule, error) {
	if !facades.Config().GetBool("casbin.basic.cache.enabled") {
		return getPolicy(), nil
	} else {
		result, err := Store.Remember(config("cache.key", "").(string), time.Duration(config("cache.ttl", 60).(int))*time.Second, func() (any, error) {
			return getPolicy(), nil
		})
		if err != nil {
			return nil, err
		}
		return result.([]Rule), nil
	}
}

// get policy from orm
func getPolicy() []Rule {
	var rules = []Rule{}
	err := facades.Orm().Query().Select("pyte", "v0", "v1", "v2", "v3", "v4", "v5").Get(&rules)
	if err != nil {
		return nil
	}
	return rules
}

func (r *Rule) TableName() string {
	return Table
}

func (r *Rule) Connection() string {
	return Connection
}

/**
 * Gets config value by key.
 */
func config(key string, defaultValue any) any {
	return facades.Config().GetString("casbin."+Guard+"."+key, defaultValue)
}

/**
 * forget Cache
 */
func forgetCache() {
	facades.Cache().Forget(config("cache.key", "").(string))
}

/**
 * Initialize the cache store.
 */
func initCache() {
	Store = facades.Cache().Store(config("cache.store", "memory").(string))
}

/**
 * Refresh Cache
 */
func (r *Rule) RefreshCache() {
	if !config("cache.enabled", false).(bool) {
		return
	}
	forgetCache()
	r.GetAllFromCache()
}

/**
 * Dispatches events.
 */
func (r *Rule) DispatchesEvents() map[contractsorm.EventType]func(contractsorm.Event) error {
	return map[contractsorm.EventType]func(contractsorm.Event) error{

		contractsorm.EventSaved: func(event contractsorm.Event) error {
			r.RefreshCache()
			return nil
		},

		contractsorm.EventDeleted: func(event contractsorm.Event) error {
			r.RefreshCache()
			return nil
		},
	}
}
