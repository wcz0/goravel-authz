package models

import (
	"sync"

	"github.com/goravel/framework/cache"
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

func NewRule(guard string) *Rule {
	var once sync.Once
	once.Do(func() {
		if guard == "" {
			Guard = facades.Config().GetString("casbin.default")
		} else {
			Guard = guard
		}
	})
	// 返回表名
	return &Rule{}
}

// get policy from cache
func GetAllFromCache() []Rule {
	var rules = []Rule{}
	get := func() {
		facades.Orm().Query().Select("pyte", "v0", "v1", "v2", "v3", "v4", "v5").Get(&rules)
	}
	if !facades.Config().GetBool("casbin.basic.cache.enabled") {
		get()
	}
	return Store.Remember(config("cache.key", "").(string), config("cache.ttl", 60).(int), get())
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
	Store = (facades.Cache().Store(config("cache.store", "memory").(string))).(cache.Driver)
}

/**
 * Refresh Cache
 */
func refreshCache() {
	if !config("cache.enabled", false).(bool) {
		return
	}
	forgetCache()
	GetAllFromCache()
}
