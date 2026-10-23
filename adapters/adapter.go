package adapters

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/goravel/framework/facades"
)

// DefaultCacheTTL is used when the Rule does not implement CacheTTL.
const DefaultCacheTTL = 5 * time.Minute

var (
	// ErrUnexpectedCachedValue is returned when the cache driver returns an
	// unexpected value type.
	ErrUnexpectedCachedValue = errors.New("goravel-authz: unexpected cached policy value")
	// ErrFilteredPolicy is returned when a filtered policy set is saved. The
	// missing rows would otherwise be deleted from the database.
	ErrFilteredPolicy = errors.New("goravel-authz: cannot save a filtered policy")
	// ErrRuleCountMismatch is returned by UpdatePolicies when the old and new
	// rule lists differ in length.
	ErrRuleCountMismatch = errors.New("goravel-authz: update policies requires the same number of old and new rules")
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
	filtered  atomic.Bool
}

var (
	_ persist.Adapter          = (*Adapter)(nil)
	_ persist.BatchAdapter     = (*Adapter)(nil)
	_ persist.UpdatableAdapter = (*Adapter)(nil)
	_ persist.FilteredAdapter  = (*Adapter)(nil)
)

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

	a.filtered.Store(false)

	return nil
}

// LoadFilteredPolicy loads only the rows matching filter into the model.
//
// filter accepts Filter, *Filter, FilterFunc or func(PolicyRow) bool. A nil
// filter loads every row. Unlike LoadPolicy, the model is expected to be empty;
// casbin's Enforcer clears it before calling this method.
func (a *Adapter) LoadFilteredPolicy(m model.Model, filter any) error {
	if filter == nil {
		return a.LoadPolicy(m)
	}

	rows, err := a.loadRows()
	if err != nil {
		return err
	}

	rows, err = filterRows(rows, filter)
	if err != nil {
		return err
	}

	for _, row := range rows {
		if err := persist.LoadPolicyArray(row.Line(), m); err != nil {
			return err
		}
	}

	a.filtered.Store(true)

	return nil
}

// IsFiltered reports whether the loaded policy was filtered. A filtered policy
// cannot be saved, because saving would delete the rows that were not loaded.
func (a *Adapter) IsFiltered() bool {
	return a.filtered.Load()
}

// SavePolicy replaces every stored policy with the content of the model.
func (a *Adapter) SavePolicy(m model.Model) error {
	if a.IsFiltered() {
		return ErrFilteredPolicy
	}

	rows, err := modelRows(m)
	if err != nil {
		return err
	}

	if err := a.withStore(func(store Store) error {
		if err := store.DeleteAll(); err != nil {
			return fmt.Errorf("goravel-authz: clear policies: %w", err)
		}

		return insertRows(store, rows)
	}); err != nil {
		return err
	}

	return a.RefreshCache()
}

// AddPolicy stores a single policy rule.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	return a.AddPolicies(sec, ptype, [][]string{rule})
}

// AddPolicies stores several policy rules in one transaction when the store
// supports transactions.
func (a *Adapter) AddPolicies(_ string, ptype string, rules [][]string) error {
	rows, err := newPolicyRows(ptype, rules)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}

	if err := a.withStore(func(store Store) error {
		return insertRows(store, rows)
	}); err != nil {
		return err
	}

	return a.RefreshCache()
}

// RemovePolicy removes a single policy rule.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	return a.RemovePolicies(sec, ptype, [][]string{rule})
}

// RemovePolicies removes several policy rules in one transaction when the
// store supports transactions.
func (a *Adapter) RemovePolicies(_ string, ptype string, rules [][]string) error {
	if len(rules) == 0 {
		return nil
	}

	for _, rule := range rules {
		if _, err := NewPolicyRow(ptype, rule); err != nil {
			return err
		}
	}

	if err := a.withStore(func(store Store) error {
		for _, rule := range rules {
			if err := store.DeleteExact(ptype, rule); err != nil {
				return fmt.Errorf("goravel-authz: remove policy %q: %w", ptype, err)
			}
		}

		return nil
	}); err != nil {
		return err
	}

	return a.RefreshCache()
}

// RemoveFilteredPolicy removes the rules matching the non-empty field values.
func (a *Adapter) RemoveFilteredPolicy(_ string, ptype string, fieldIndex int, fieldValues ...string) error {
	if err := a.withStore(func(store Store) error {
		if err := store.DeleteFiltered(ptype, fieldIndex, fieldValues); err != nil {
			return fmt.Errorf("goravel-authz: remove filtered policy %q: %w", ptype, err)
		}

		return nil
	}); err != nil {
		return err
	}

	return a.RefreshCache()
}

// UpdatePolicy replaces oldRule with newRule.
func (a *Adapter) UpdatePolicy(_ string, ptype string, oldRule, newRule []string) error {
	if _, err := NewPolicyRow(ptype, oldRule); err != nil {
		return err
	}

	row, err := NewPolicyRow(ptype, newRule)
	if err != nil {
		return err
	}

	if err := a.withStore(func(store Store) error {
		return replacePolicies(store, ptype, [][]string{oldRule}, []PolicyRow{row})
	}); err != nil {
		return err
	}

	return a.RefreshCache()
}

// UpdatePolicies replaces every old rule with the new rule at the same index.
// All old rules are deleted before the new ones are inserted, so rules can be
// reordered or swapped without violating the unique constraint.
func (a *Adapter) UpdatePolicies(_ string, ptype string, oldRules, newRules [][]string) error {
	if len(oldRules) != len(newRules) {
		return fmt.Errorf("%w: %d old rules, %d new rules", ErrRuleCountMismatch, len(oldRules), len(newRules))
	}
	if len(oldRules) == 0 {
		return nil
	}

	for _, oldRule := range oldRules {
		if _, err := NewPolicyRow(ptype, oldRule); err != nil {
			return err
		}
	}

	rows, err := newPolicyRows(ptype, newRules)
	if err != nil {
		return err
	}

	if err := a.withStore(func(store Store) error {
		return replacePolicies(store, ptype, oldRules, rows)
	}); err != nil {
		return err
	}

	return a.RefreshCache()
}

// UpdateFilteredPolicies removes the stored rules matching the filter and adds
// newRules. It returns the removed rules, which casbin needs to update its
// in-memory model.
func (a *Adapter) UpdateFilteredPolicies(_ string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	rows, err := a.loadRows()
	if err != nil {
		return nil, err
	}

	oldRules := make([][]string, 0)
	for _, row := range rows {
		if row.Ptype != ptype || !matchRowFilter(row, fieldIndex, fieldValues) {
			continue
		}

		oldRules = append(oldRules, append([]string(nil), row.Values...))
	}

	newRows, err := newPolicyRows(ptype, newRules)
	if err != nil {
		return nil, err
	}

	if err := a.withStore(func(store Store) error {
		if err := store.DeleteFiltered(ptype, fieldIndex, fieldValues); err != nil {
			return fmt.Errorf("goravel-authz: update filtered policy %q: %w", ptype, err)
		}

		return insertRows(store, newRows)
	}); err != nil {
		return nil, err
	}

	if err := a.RefreshCache(); err != nil {
		return nil, err
	}

	return oldRules, nil
}

// withStore runs fn inside a transaction when the store supports one.
func (a *Adapter) withStore(fn func(Store) error) error {
	if transactional, ok := a.store.(TransactionalStore); ok {
		return transactional.Transaction(fn)
	}

	return fn(a.store)
}

func newPolicyRows(ptype string, rules [][]string) ([]PolicyRow, error) {
	rows := make([]PolicyRow, 0, len(rules))
	for _, rule := range rules {
		row, err := NewPolicyRow(ptype, rule)
		if err != nil {
			return nil, err
		}

		rows = append(rows, row)
	}

	return rows, nil
}

func modelRows(m model.Model) ([]PolicyRow, error) {
	rows := make([]PolicyRow, 0)
	for _, section := range []string{"p", "g"} {
		for ptype, assertion := range m[section] {
			for _, values := range assertion.Policy {
				row, err := NewPolicyRow(ptype, values)
				if err != nil {
					return nil, err
				}

				rows = append(rows, row)
			}
		}
	}

	return rows, nil
}

func insertRows(store Store, rows []PolicyRow) error {
	for _, row := range rows {
		if err := store.Insert(row); err != nil {
			return fmt.Errorf("goravel-authz: save policy %q: %w", row.Ptype, err)
		}
	}

	return nil
}

func replacePolicies(store Store, ptype string, oldRules [][]string, rows []PolicyRow) error {
	for _, oldRule := range oldRules {
		if err := store.DeleteExact(ptype, oldRule); err != nil {
			return fmt.Errorf("goravel-authz: update policy %q: %w", ptype, err)
		}
	}

	return insertRows(store, rows)
}

// RefreshCache flushes the cached policies of this adapter's rule.
func (a *Adapter) RefreshCache() error {
	enabled, storeName, key := cacheSettings(a.rule)
	if !enabled {
		return nil
	}

	if a.cacheOpen == nil {
		return nil
	}

	a.cacheOpen(storeName).Forget(key)

	return nil
}

func (a *Adapter) loadRows() ([]PolicyRow, error) {
	enabled, storeName, key := cacheSettings(a.rule)
	if !enabled || a.cacheOpen == nil {
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

// cacheSettings returns the effective cache configuration. When caching is
// enabled without an explicit key, a stable key is derived from the model's
// table name (or its type) so every enforcer gets its own cache entry.
func cacheSettings(rule Rule) (bool, string, string) {
	enabled, storeName, key := rule.Cache()
	if !enabled {
		return false, "", ""
	}
	if key == "" {
		key = autoCacheKey(rule)
	}

	return true, storeName, key
}

func autoCacheKey(rule Rule) string {
	if named, ok := rule.(interface{ TableName() string }); ok {
		if table := named.TableName(); table != "" {
			return "goravel-authz:" + table
		}
	}

	return fmt.Sprintf("goravel-authz:%T", rule)
}

func cacheTTL(rule Rule) time.Duration {
	if provider, ok := rule.(CacheTTL); ok {
		if ttl := provider.CacheTTL(); ttl > 0 {
			return ttl
		}
	}

	return DefaultCacheTTL
}
