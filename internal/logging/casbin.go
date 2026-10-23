package logging

import (
	"strings"
	"sync/atomic"

	casbinlog "github.com/casbin/casbin/v2/log"
	"github.com/goravel/framework/contracts/log"
)

// CasbinLogger sends Casbin's own diagnostics to a Goravel logger. Model,
// policy, role and enforce messages are written at debug level, errors at
// error level.
type CasbinLogger struct {
	guard   string
	logger  log.Writer
	enabled atomic.Bool
}

var _ casbinlog.Logger = (*CasbinLogger)(nil)

// NewCasbinLogger creates a logger for the given guard. enabled controls the
// initial state; it can be changed at runtime through EnableLog.
func NewCasbinLogger(guard string, logger log.Writer, enabled bool) *CasbinLogger {
	instance := &CasbinLogger{guard: guard, logger: logger}
	instance.enabled.Store(enabled)

	return instance
}

// EnableLog turns Casbin diagnostics on or off.
func (l *CasbinLogger) EnableLog(enable bool) {
	l.enabled.Store(enable)
}

// IsEnabled reports whether Casbin diagnostics are written.
func (l *CasbinLogger) IsEnabled() bool {
	return l.enabled.Load()
}

func (l *CasbinLogger) with(data map[string]any) log.Writer {
	if data == nil {
		data = make(map[string]any, 1)
	}
	if l.guard != "" {
		data["guard"] = l.guard
	}

	return l.logger.With(data)
}

// LogModel logs the loaded casbin model.
func (l *CasbinLogger) LogModel(model [][]string) {
	if !l.IsEnabled() {
		return
	}

	l.with(map[string]any{"model": model}).Debug("casbin: model loaded")
}

// LogEnforce logs an enforcement request, its result and the matched policies.
func (l *CasbinLogger) LogEnforce(_ string, request []any, result bool, explains [][]string) {
	if !l.IsEnabled() {
		return
	}

	l.with(map[string]any{
		"request":  request,
		"result":   result,
		"policies": explains,
	}).Debug("casbin: enforce")
}

// LogRole logs the roles of a role manager operation.
func (l *CasbinLogger) LogRole(roles []string) {
	if !l.IsEnabled() {
		return
	}

	l.with(map[string]any{"roles": roles}).Debug("casbin: roles")
}

// LogPolicy logs the loaded policies.
func (l *CasbinLogger) LogPolicy(policy map[string][][]string) {
	if !l.IsEnabled() {
		return
	}

	l.with(map[string]any{"policy": policy}).Debug("casbin: policy loaded")
}

// LogError logs a Casbin error with the optional context passed by Casbin.
func (l *CasbinLogger) LogError(err error, msg ...string) {
	if !l.IsEnabled() {
		return
	}

	if context := strings.Join(msg, " "); context != "" {
		l.with(nil).Errorf("casbin: %s: %v", context, err)
		return
	}

	l.with(nil).Errorf("casbin: %v", err)
}
