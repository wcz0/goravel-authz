package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/casbin/casbin/v2"
	contractshttp "github.com/goravel/framework/contracts/http"
	contractslog "github.com/goravel/framework/contracts/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type logEntry struct {
	level   string
	message string
	fields  map[string]any
}

type logRecorder struct {
	entries []logEntry
}

// recordingLogger implements the parts of the Goravel log contract used by the
// middleware. The embedded interface satisfies the remaining methods.
type recordingLogger struct {
	contractslog.Log
	recorder *logRecorder
	fields   map[string]any
}

func newRecordingLogger() *recordingLogger {
	return &recordingLogger{recorder: &logRecorder{}}
}

func (l *recordingLogger) With(data map[string]any) contractslog.Writer {
	fields := make(map[string]any, len(l.fields)+len(data))
	for key, value := range l.fields {
		fields[key] = value
	}
	for key, value := range data {
		fields[key] = value
	}

	return &recordingLogger{recorder: l.recorder, fields: fields}
}

func (l *recordingLogger) Debug(args ...any) { l.add("debug", fmt.Sprint(args...)) }
func (l *recordingLogger) Debugf(format string, args ...any) {
	l.add("debug", fmt.Sprintf(format, args...))
}
func (l *recordingLogger) Info(args ...any) { l.add("info", fmt.Sprint(args...)) }
func (l *recordingLogger) Infof(format string, args ...any) {
	l.add("info", fmt.Sprintf(format, args...))
}
func (l *recordingLogger) Warning(args ...any) { l.add("warning", fmt.Sprint(args...)) }
func (l *recordingLogger) Warningf(format string, args ...any) {
	l.add("warning", fmt.Sprintf(format, args...))
}
func (l *recordingLogger) Error(args ...any) { l.add("error", fmt.Sprint(args...)) }
func (l *recordingLogger) Errorf(format string, args ...any) {
	l.add("error", fmt.Sprintf(format, args...))
}

func (l *recordingLogger) add(level, message string) {
	l.recorder.entries = append(l.recorder.entries, logEntry{level: level, message: message, fields: l.fields})
}

func TestAuthzLogsAllowedRequest(t *testing.T) {
	logger := newRecordingLogger()
	mw := Authz(WithGuard("admin")).(*authzMiddleware)
	mw.logger = logger
	mw.logAllowed = true
	mw.logDenied = true
	mw.open = func(name string) (*casbin.SyncedEnforcer, error) {
		assert.Equal(t, "admin", name)
		return newTestEnforcer(t, []string{"alice", "/admin/users", "GET"}), nil
	}

	ctx, request, _ := newMockContext(t)
	ctx.EXPECT().Value(SubjectKey).Return("alice")
	request.EXPECT().OriginPath().Return("/admin/users")
	request.EXPECT().Method().Return("GET")
	request.EXPECT().Next()

	mw.Handle(ctx)

	require.Len(t, logger.recorder.entries, 1)
	got := logger.recorder.entries[0]
	assert.Equal(t, "info", got.level)
	assert.Equal(t, "authz: access allowed", got.message)
	assert.Equal(t, "admin", got.fields["guard"])
	assert.Equal(t, "alice", got.fields["subject"])
	assert.Equal(t, "/admin/users", got.fields["object"])
	assert.Equal(t, "GET", got.fields["action"])
}

func TestAuthzLogsDeniedRequest(t *testing.T) {
	logger := newRecordingLogger()
	mw := Authz(WithGuard("admin")).(*authzMiddleware)
	mw.logger = logger
	mw.logAllowed = true
	mw.logDenied = true
	mw.open = func(string) (*casbin.SyncedEnforcer, error) {
		return newTestEnforcer(t, []string{"alice", "/admin/users", "GET"}), nil
	}

	ctx, request, response := newMockContext(t)
	ctx.EXPECT().Value(SubjectKey).Return("bob")
	request.EXPECT().OriginPath().Return("/admin/users")
	request.EXPECT().Method().Return("GET")
	expectDenied(t, response, http.StatusForbidden, DefaultDeniedMessage)

	mw.Handle(ctx)

	require.Len(t, logger.recorder.entries, 1)
	got := logger.recorder.entries[0]
	assert.Equal(t, "warning", got.level)
	assert.Equal(t, "authz: access denied", got.message)
	assert.Equal(t, "policy", got.fields["reason"])
	assert.Equal(t, "bob", got.fields["subject"])
	assert.Equal(t, "admin", got.fields["guard"])
}

func TestAuthzLogsMissingSubject(t *testing.T) {
	logger := newRecordingLogger()
	mw := Authz().(*authzMiddleware)
	mw.logger = logger
	mw.logDenied = true
	mw.open = func(string) (*casbin.SyncedEnforcer, error) {
		t.Fatal("the enforcer must not be opened without a subject")
		return nil, nil
	}

	ctx, _, response := newMockContext(t)
	ctx.EXPECT().Value(SubjectKey).Return(nil)
	expectDenied(t, response, http.StatusForbidden, DefaultDeniedMessage)

	mw.Handle(ctx)

	require.Len(t, logger.recorder.entries, 1)
	got := logger.recorder.entries[0]
	assert.Equal(t, "warning", got.level)
	assert.Equal(t, "authz: access denied", got.message)
	assert.Equal(t, "missing subject", got.fields["reason"])
	assert.Empty(t, got.fields["subject"])
}

func TestAuthzLogsSubjectResolverFailure(t *testing.T) {
	logger := newRecordingLogger()
	mw := Authz(WithSubject(func(ctx contractshttp.Context) (string, error) {
		return "", errors.New("token expired")
	})).(*authzMiddleware)
	mw.logger = logger

	ctx, _, response := newMockContext(t)
	expectDenied(t, response, http.StatusForbidden, DefaultDeniedMessage)

	mw.Handle(ctx)

	require.Len(t, logger.recorder.entries, 1)
	got := logger.recorder.entries[0]
	assert.Equal(t, "error", got.level)
	assert.Equal(t, "authz: subject resolver failed", got.message)
	assert.EqualError(t, got.fields["error"].(error), "token expired")
}

func TestAuthzLogsEnforcerFailure(t *testing.T) {
	logger := newRecordingLogger()
	mw := Authz().(*authzMiddleware)
	mw.logger = logger
	mw.open = func(string) (*casbin.SyncedEnforcer, error) {
		return nil, errors.New("model is broken")
	}

	ctx, request, response := newMockContext(t)
	ctx.EXPECT().Value(SubjectKey).Return("alice")
	request.EXPECT().OriginPath().Return("/admin/users")
	request.EXPECT().Method().Return("GET")
	expectDenied(t, response, http.StatusInternalServerError, DefaultUnavailableMessage)

	mw.Handle(ctx)

	require.Len(t, logger.recorder.entries, 1)
	got := logger.recorder.entries[0]
	assert.Equal(t, "error", got.level)
	assert.Equal(t, "authz: enforcer unavailable", got.message)
	assert.EqualError(t, got.fields["error"].(error), "model is broken")
	assert.Equal(t, "/admin/users", got.fields["object"])
}

func TestAuthzRespectsLogSwitches(t *testing.T) {
	logger := newRecordingLogger()
	mw := Authz().(*authzMiddleware)
	mw.logger = logger
	mw.logAllowed = false
	mw.logDenied = false
	mw.open = func(string) (*casbin.SyncedEnforcer, error) {
		return newTestEnforcer(t, []string{"alice", "/admin/users", "GET"}), nil
	}

	ctx, request, _ := newMockContext(t)
	ctx.EXPECT().Value(SubjectKey).Return("alice")
	request.EXPECT().OriginPath().Return("/admin/users")
	request.EXPECT().Method().Return("GET")
	request.EXPECT().Next()

	mw.Handle(ctx)

	assert.Empty(t, logger.recorder.entries)
}
