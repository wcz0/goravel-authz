package authz

import (
	"fmt"
	"testing"

	"github.com/goravel/framework/contracts/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wcz0/goravel-authz/adapters"
	"github.com/wcz0/goravel-authz/models"
)

type casbinLogRecorder struct {
	debugs []string
	errors []string
}

// casbinLogSink implements the subset of the Goravel log contract used by
// CasbinLogger. The embedded interface satisfies the remaining methods.
type casbinLogSink struct {
	log.Log
	recorder *casbinLogRecorder
}

func (l *casbinLogSink) With(map[string]any) log.Writer {
	return l
}

func (l *casbinLogSink) Debug(args ...any) {
	l.recorder.debugs = append(l.recorder.debugs, fmt.Sprint(args...))
}

func (l *casbinLogSink) Debugf(format string, args ...any) {
	l.recorder.debugs = append(l.recorder.debugs, fmt.Sprintf(format, args...))
}

func (l *casbinLogSink) Error(args ...any) {
	l.recorder.errors = append(l.recorder.errors, fmt.Sprint(args...))
}

func (l *casbinLogSink) Errorf(format string, args ...any) {
	l.recorder.errors = append(l.recorder.errors, fmt.Sprintf(format, args...))
}

func TestAttachLoggerRoutesCasbinDiagnostics(t *testing.T) {
	withStore(t, &memoryStore{rows: []adapters.PolicyRow{
		{Ptype: "p", Values: []string{"admin", "data1", "read"}},
	}})

	instance, err := enforcerFor("basic", &textRule{Rule: models.NewRule(), rule: rbacModel})
	require.NoError(t, err)

	recorder := &casbinLogRecorder{}
	attachLogger(instance, "basic", &casbinLogSink{recorder: recorder}, true)

	allowed, err := instance.Enforce("admin", "data1", "read")
	require.NoError(t, err)
	assert.True(t, allowed)
	require.Len(t, recorder.debugs, 1)
	assert.Equal(t, "casbin: enforce", recorder.debugs[0])

	instance.EnableLog(false)

	allowed, err = instance.Enforce("admin", "data1", "read")
	require.NoError(t, err)
	assert.True(t, allowed)
	assert.Len(t, recorder.debugs, 1, "disabling casbin logging must silence the sink")
}
