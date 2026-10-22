package logging

import (
	"errors"
	"fmt"
	"testing"

	"github.com/goravel/framework/contracts/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type entry struct {
	level   string
	message string
	fields  map[string]any
}

type recorder struct {
	entries []entry
}

// testLogger implements the parts of log.Log used by CasbinLogger. The embedded
// interface keeps the remaining Writer methods satisfied.
type testLogger struct {
	log.Log
	recorder *recorder
	fields   map[string]any
}

func newTestLogger() *testLogger {
	return &testLogger{recorder: &recorder{}}
}

func (l *testLogger) With(data map[string]any) log.Writer {
	fields := make(map[string]any, len(l.fields)+len(data))
	for key, value := range l.fields {
		fields[key] = value
	}
	for key, value := range data {
		fields[key] = value
	}

	return &testLogger{recorder: l.recorder, fields: fields}
}

func (l *testLogger) Debug(args ...any)                 { l.add("debug", fmt.Sprint(args...)) }
func (l *testLogger) Debugf(format string, args ...any) { l.add("debug", fmt.Sprintf(format, args...)) }
func (l *testLogger) Info(args ...any)                  { l.add("info", fmt.Sprint(args...)) }
func (l *testLogger) Infof(format string, args ...any)  { l.add("info", fmt.Sprintf(format, args...)) }
func (l *testLogger) Warning(args ...any)               { l.add("warning", fmt.Sprint(args...)) }
func (l *testLogger) Warningf(format string, args ...any) {
	l.add("warning", fmt.Sprintf(format, args...))
}
func (l *testLogger) Error(args ...any)                 { l.add("error", fmt.Sprint(args...)) }
func (l *testLogger) Errorf(format string, args ...any) { l.add("error", fmt.Sprintf(format, args...)) }

func (l *testLogger) add(level, message string) {
	l.recorder.entries = append(l.recorder.entries, entry{
		level:   level,
		message: message,
		fields:  l.fields,
	})
}

func TestCasbinLoggerIsDisabledUntilEnabled(t *testing.T) {
	logger := newTestLogger()
	casbin := NewCasbinLogger("basic", logger, false)

	assert.False(t, casbin.IsEnabled())

	casbin.LogEnforce("m", []any{"alice", "data", "read"}, true, nil)
	assert.Empty(t, logger.recorder.entries)

	casbin.EnableLog(true)
	assert.True(t, casbin.IsEnabled())

	casbin.LogEnforce("m", []any{"alice", "data", "read"}, true, nil)
	require.Len(t, logger.recorder.entries, 1)

	got := logger.recorder.entries[0]
	assert.Equal(t, "debug", got.level)
	assert.Equal(t, "casbin: enforce", got.message)
	assert.Equal(t, "basic", got.fields["guard"])
	assert.Equal(t, []any{"alice", "data", "read"}, got.fields["request"])
	assert.Equal(t, true, got.fields["result"])
}

func TestCasbinLoggerRoutesMessages(t *testing.T) {
	logger := newTestLogger()
	casbin := NewCasbinLogger("admin", logger, true)

	casbin.LogModel([][]string{{"r", "r", "sub"}})
	casbin.LogPolicy(map[string][][]string{"p": {{"admin", "data", "read"}}})
	casbin.LogRole([]string{"admin"})
	casbin.LogEnforce("m", []any{"alice"}, false, [][]string{{"admin", "data", "read"}})
	casbin.LogError(errors.New("boom"), "has link")

	require.Len(t, logger.recorder.entries, 5)

	model, policy, roles, enforce, failure := logger.recorder.entries[0], logger.recorder.entries[1], logger.recorder.entries[2], logger.recorder.entries[3], logger.recorder.entries[4]

	assert.Equal(t, "debug", model.level)
	assert.Equal(t, "casbin: model loaded", model.message)
	assert.Equal(t, "admin", model.fields["guard"])

	assert.Equal(t, "debug", policy.level)
	assert.Equal(t, "casbin: policy loaded", policy.message)

	assert.Equal(t, "debug", roles.level)
	assert.Equal(t, "casbin: roles", roles.message)
	assert.Equal(t, []string{"admin"}, roles.fields["roles"])

	assert.Equal(t, "debug", enforce.level)
	assert.Equal(t, "casbin: enforce", enforce.message)
	assert.Equal(t, false, enforce.fields["result"])

	assert.Equal(t, "error", failure.level)
	assert.Equal(t, "casbin: has link: boom", failure.message)
	assert.Equal(t, "admin", failure.fields["guard"])
}

func TestCasbinLoggerOmitsEmptyGuardAndContext(t *testing.T) {
	logger := newTestLogger()
	casbin := NewCasbinLogger("", logger, true)

	casbin.LogError(errors.New("boom"))
	require.Len(t, logger.recorder.entries, 1)

	got := logger.recorder.entries[0]
	assert.Equal(t, "error", got.level)
	assert.Equal(t, "casbin: boom", got.message)
	assert.NotContains(t, got.fields, "guard")
}
