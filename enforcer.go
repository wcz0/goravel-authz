package authz

import (
	"fmt"
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/goravel/framework/contracts/log"
	"github.com/goravel/framework/facades"
	"github.com/goravel/framework/support/path"
	"github.com/wcz0/goravel-authz/adapters"
	"github.com/wcz0/goravel-authz/internal/logging"
)

var (
	enforcersMu sync.RWMutex
	enforcers   = make(map[string]*casbin.SyncedEnforcer)

	// adapterFactory is swapped by tests to inject a store.
	adapterFactory = func(rule adapters.Rule) *adapters.Adapter {
		return adapters.NewAdapter(rule)
	}
)

// NewEnforcer returns the shared enforcer of the given model name.
//
// Enforcers are created on first use and kept in memory, so calling this on
// every request only performs a map lookup. An empty name resolves to
// casbin.default. Use Reload to pick up policies written by another process.
func NewEnforcer(name string) (*casbin.SyncedEnforcer, error) {
	name = resolveName(name)
	if name == "" {
		return nil, fmt.Errorf("casbin: no default model is configured")
	}

	if instance, ok := lookup(name); ok {
		return instance, nil
	}

	rule, err := resolveRule(name)
	if err != nil {
		return nil, err
	}

	return enforcerFor(name, rule)
}

// Reload refreshes the policies of an existing enforcer, bypassing its
// policy cache. It creates the enforcer when it was not loaded yet.
func Reload(name string) error {
	name = resolveName(name)
	if name == "" {
		return fmt.Errorf("casbin: no default model is configured")
	}

	instance, ok := lookup(name)
	if !ok {
		_, err := NewEnforcer(name)
		return err
	}

	if adapter, ok := instance.GetAdapter().(*adapters.Adapter); ok {
		if err := adapter.RefreshCache(); err != nil {
			return err
		}
	}

	if err := instance.LoadPolicy(); err != nil {
		return err
	}

	if logger := logging.Load().Logger(); logger != nil {
		logger.With(map[string]any{"guard": name}).Info("authz: policies reloaded")
	}

	return nil
}

// Reset forgets every cached enforcer. It is mainly useful in tests and after
// the casbin configuration changed at runtime.
func Reset() {
	enforcersMu.Lock()
	defer enforcersMu.Unlock()

	enforcers = make(map[string]*casbin.SyncedEnforcer)
}

func lookup(name string) (*casbin.SyncedEnforcer, bool) {
	enforcersMu.RLock()
	defer enforcersMu.RUnlock()

	instance, ok := enforcers[name]
	return instance, ok
}

func enforcerFor(name string, rule adapters.Rule) (*casbin.SyncedEnforcer, error) {
	enforcersMu.Lock()
	defer enforcersMu.Unlock()

	if instance, ok := enforcers[name]; ok {
		return instance, nil
	}

	m, err := buildModel(name, rule)
	if err != nil {
		return nil, err
	}

	instance, err := casbin.NewSyncedEnforcer(m, adapterFactory(rule))
	if err != nil {
		return nil, fmt.Errorf("casbin: create enforcer %q: %w", name, err)
	}

	settings := logging.Load()
	if logger := settings.Logger(); logger != nil {
		attachLogger(instance, name, logger, settings.Casbin)
		logger.With(map[string]any{"guard": name}).Info("authz: enforcer loaded")
	}

	enforcers[name] = instance

	return instance, nil
}

// attachLogger routes Casbin's own diagnostics through the Goravel logger.
// They stay disabled until casbin.log.casbin is enabled or the application
// calls EnableLog at runtime.
func attachLogger(instance *casbin.SyncedEnforcer, name string, logger log.Log, enabled bool) {
	instance.SetLogger(logging.NewCasbinLogger(name, logger, enabled))
}

func resolveName(name string) string {
	if name != "" {
		return name
	}

	return facades.Config().GetString("casbin.default")
}

func resolveRule(name string) (adapters.Rule, error) {
	entry := facades.Config().Get("casbin.models." + name)
	if entry == nil {
		return nil, fmt.Errorf("casbin: model %q is not defined under casbin.models", name)
	}

	rule, ok := entry.(adapters.Rule)
	if !ok {
		return nil, fmt.Errorf("casbin: model %q must implement adapters.Rule", name)
	}

	return rule, nil
}

func buildModel(name string, rule adapters.Rule) (model.Model, error) {
	kind, value := rule.Model()

	switch kind {
	case "file":
		m, err := model.NewModelFromFile(path.Config(value))
		if err != nil {
			return nil, fmt.Errorf("casbin: load model file of %q: %w", name, err)
		}

		return m, nil
	case "text":
		m, err := model.NewModelFromString(value)
		if err != nil {
			return nil, fmt.Errorf("casbin: parse model text of %q: %w", name, err)
		}

		return m, nil
	default:
		return nil, fmt.Errorf("casbin: model %q has an unsupported Model() type %q (want file or text)", name, kind)
	}
}
