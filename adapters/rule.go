package adapters

import "time"

// Rule describes a policy row and the casbin configuration of an enforcer.
//
// models.Rule is the default implementation. Applications may embed it to
// customize the table name or the database connection used by an enforcer.
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
	// Model returns the casbin model type ("file" or "text") and its value.
	Model() (string, string)
	// Cache reports whether policies should be cached, the cache store name
	// and the cache key. The key must be unique per enforcer.
	Cache() (bool, string, string)
	// RefreshCache flushes the cached policies.
	RefreshCache()
}

// CacheTTL is an optional interface a Rule can implement to override the
// default policy cache TTL.
type CacheTTL interface {
	CacheTTL() time.Duration
}
