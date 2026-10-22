package adapters

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/goravel/framework/facades"
)

// DefaultCacheTTL is used when the Rule does not implement CacheTTL.
const DefaultCacheTTL = 5 * time.Minute

var (
	// ErrEmptyCacheKey is returned when caching is enabled without a key.
	ErrEmptyCacheKey = errors.New("goravel-authz: cache is enabled but the cache key is empty")
	// ErrUnexpectedCachedValue is returned when the cache driver returns an
	// unexpected value type.
	ErrUnexpectedCachedValue = errors.New("goravel-authz: unexpected cached policy value")
)

// policyCache is the subset of a Goravel cache store used by the adapter.
type policyCache interface {
	Remember(key string, ttl time.Duration, callback func() (any, error)) (any, error)
	Forget(key string) bool
}

// Adapter is a casbin persist.Adapter backed by a Store. It can optionally
// cache policy rows in a Goravel cache store.
type Adapter struct {
	rule      Rule
	store     Store
	cacheOpen func(name string) policyCache
	ttl       time.Duration
}

var _ persist.Adapter = (*Adapter)(nil)

// NewAdapter creates an Adapter for the given rule.
func NewAdapter(rule Rule) *Adapter {
	return &Adapter{
		rule:  rule,
		store: NewORMStore(rule),
		cacheOpen: func(name string) policyCache {
			return facades.Cache().Store(name)
		},
		ttl: cacheTTL(rule),
	}
}

// SetStore replaces the persistence backend, mainly useful for tests or for
// applications that store policies somewhere else than the default table.
func (a *Adapter) SetStore(store Store) *Adapter {
	a.store = store
	return a
}

// SetCache replaces the cache factory, mainly useful for tests.
func (a *Adapter) SetCache(open func(name string) policyCache) *Adapter {
	a.cacheOpen = open
	return a
}

// LoadPolicy loads every policy row into the casbin model.
func (a *Adapter) LoadPolicy(m model.Model) error {
	rows, err := a.loadRows()
	if err != nil {
		return err
	}

	for _, row := range rows {
		if err := persist.LoadPolicyArray(row.Line(), m); err != nil {
			return err
		}
	}

	return nil
}

// SavePolicy replaces every stored policy with the content of the model.
func (a *Adapter) SavePolicy(m model.Model) error {
	if err := a.store.DeleteAll(); err != nil {
		return fmt.Errorf("goravel-authz: clear policies: %w", err)
	}

	for _, section := range []string{"p", "g"} {
		for ptype, assertion := range m[section] {
			for _, values := range assertion.Policy {
				row, err := NewPolicyRow(ptype, values)
				if err != nil {
					return err
				}
				if err := a.store.Insert(row); err != nil {
					return fmt.Errorf("goravel-authz: save policy %q: %w", ptype, err)
				}
			}
		}
	}

	return a.RefreshCache()
}

// AddPolicy stores a single policy rule.
func (a *Adapter) AddPolicy(_ string, ptype string, rule []string) error {
	row, err := NewPolicyRow(ptype, rule)
	if err != nil {
		return err
	}

	if err := a.store.Insert(row); err != nil {
		return err
	}

	return a.RefreshCache()
}

// RemovePolicy removes a single policy rule.
func (a *Adapter) RemovePolicy(_ string, ptype string, rule []string) error {
	if err := a.store.DeleteExact(ptype, rule); err != nil {
		return err
	}

	return a.RefreshCache()
}

// RemoveFilteredPolicy removes the rules matching the non-empty field values.
func (a *Adapter) RemoveFilteredPolicy(_ string, ptype string, fieldIndex int, fieldValues ...string) error {
	if err := a.store.DeleteFiltered(ptype, fieldIndex, fieldValues); err != nil {
		return err
	}

	return a.RefreshCache()
}

// RefreshCache flushes the cached policies of this adapter's rule.
func (a *Adapter) RefreshCache() error {
	enabled, storeName, key := a.rule.Cache()
	if !enabled || key == "" {
		return nil
	}

	if a.cacheOpen == nil {
		return nil
	}

	a.cacheOpen(storeName).Forget(key)

	return nil
}

func (a *Adapter) loadRows() ([]PolicyRow, error) {
	enabled, storeName, key := a.rule.Cache()
	if !enabled {
		return a.store.Load()
	}
	if key == "" {
		return nil, ErrEmptyCacheKey
	}
	if a.cacheOpen == nil {
		return a.store.Load()
	}

	value, err := a.cacheOpen(storeName).Remember(key, a.ttl, func() (any, error) {
		rows, err := a.store.Load()
		if err != nil {
			return nil, err
		}

		encoded, err := json.Marshal(rows)
		if err != nil {
			return nil, err
		}

		return string(encoded), nil
	})
	if err != nil {
		return nil, err
	}

	return decodeRows(value)
}

func decodeRows(value any) ([]PolicyRow, error) {
	var encoded []byte

	switch cached := value.(type) {
	case string:
		encoded = []byte(cached)
	case []byte:
		encoded = cached
	case []PolicyRow:
		return cached, nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnexpectedCachedValue, value)
	}

	var rows []PolicyRow
	if err := json.Unmarshal(encoded, &rows); err != nil {
		return nil, fmt.Errorf("goravel-authz: decode cached policies: %w", err)
	}

	return rows, nil
}

func cacheTTL(rule Rule) time.Duration {
	if provider, ok := rule.(CacheTTL); ok {
		if ttl := provider.CacheTTL(); ttl > 0 {
			return ttl
		}
	}

	return DefaultCacheTTL
}
