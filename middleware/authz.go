// Package middleware provides HTTP authorization for Goravel, backed by the
// Casbin policies managed by this package.
package middleware

import (
	"net/http"

	"github.com/casbin/casbin/v2"
	contractshttp "github.com/goravel/framework/contracts/http"

	authz "github.com/wcz0/goravel-authz"
)

const (
	// SubjectKey is the context key written by SetSubject and read by the
	// default subject resolver.
	SubjectKey = "goravel-authz:subject"

	// DefaultDeniedMessage is returned by the default denied handler.
	DefaultDeniedMessage = "This action is unauthorized."

	// DefaultUnavailableMessage is returned when the enforcer cannot be
	// created or evaluated.
	DefaultUnavailableMessage = "Authorization service is unavailable."
)

// SubjectResolver returns the subject of the request. An empty subject or an
// error denies the request.
type SubjectResolver func(ctx contractshttp.Context) (string, error)

// ObjectResolver returns the object of the request.
type ObjectResolver func(ctx contractshttp.Context) string

// ActionResolver returns the action of the request.
type ActionResolver func(ctx contractshttp.Context) string

// Decision is the request that was checked against the policies.
type Decision struct {
	// Guard is the configured model name. An empty Guard means casbin.default.
	Guard   string
	Subject string
	Object  string
	Action  string
}

// DeniedHandler writes the response of a denied request.
type DeniedHandler func(ctx contractshttp.Context, decision Decision)

// Option configures the authorization middleware.
type Option func(*authzMiddleware)

type authzMiddleware struct {
	guard   string
	subject SubjectResolver
	object  ObjectResolver
	action  ActionResolver
	denied  DeniedHandler

	// open is replaced in tests.
	open func(name string) (*casbin.SyncedEnforcer, error)
}

// Authz returns middleware that only lets a request through when the policies
// of a Casbin model allow its subject, object and action.
//
// By default the enforcer of casbin.default is used, the subject is read from
// SetSubject, the object is the route pattern (OriginPath) and the action is
// the HTTP method. Every part can be replaced with an option.
func Authz(options ...Option) contractshttp.Middleware {
	m := &authzMiddleware{
		subject: subjectFromContext,
		object:  objectFromRequest,
		action:  actionFromRequest,
		denied:  denyWithJSON,
		open:    authz.NewEnforcer,
	}

	for _, option := range options {
		option(m)
	}

	return m
}

func (m *authzMiddleware) Signature() string {
	if m.guard == "" {
		return "goravel:authz"
	}

	return "goravel:authz:" + m.guard
}

func (m *authzMiddleware) Handle(ctx contractshttp.Context) {
	decision := Decision{Guard: m.guard}

	subject, err := m.subject(ctx)
	if err != nil || subject == "" {
		m.denied(ctx, decision)
		return
	}
	decision.Subject = subject
	decision.Object = m.object(ctx)
	decision.Action = m.action(ctx)

	enforcer, err := m.open(m.guard)
	if err != nil {
		abortWithError(ctx, http.StatusInternalServerError, DefaultUnavailableMessage)
		return
	}

	allowed, err := enforcer.Enforce(subject, decision.Object, decision.Action)
	if err != nil {
		abortWithError(ctx, http.StatusInternalServerError, DefaultUnavailableMessage)
		return
	}

	if !allowed {
		m.denied(ctx, decision)
		return
	}

	ctx.Request().Next()
}

// WithGuard selects the Casbin model to check against. An empty guard uses
// casbin.default.
func WithGuard(guard string) Option {
	return func(m *authzMiddleware) {
		m.guard = guard
	}
}

// WithSubject replaces the default subject resolver, which reads the value
// stored by SetSubject.
func WithSubject(resolver SubjectResolver) Option {
	return func(m *authzMiddleware) {
		if resolver != nil {
			m.subject = resolver
		}
	}
}

// WithObject replaces the default object resolver. The default uses the route
// pattern and falls back to the request path.
func WithObject(resolver ObjectResolver) Option {
	return func(m *authzMiddleware) {
		if resolver != nil {
			m.object = resolver
		}
	}
}

// WithAction replaces the default action resolver, which returns the HTTP
// method.
func WithAction(resolver ActionResolver) Option {
	return func(m *authzMiddleware) {
		if resolver != nil {
			m.action = resolver
		}
	}
}

// WithDenied replaces the default 403 JSON response.
func WithDenied(handler DeniedHandler) Option {
	return func(m *authzMiddleware) {
		if handler != nil {
			m.denied = handler
		}
	}
}

// SetSubject stores the authenticated subject in the request context. Call it
// from an authentication middleware that runs before Authz.
func SetSubject(ctx contractshttp.Context, subject string) {
	ctx.WithValue(SubjectKey, subject)
}

// SubjectFrom returns the subject stored by SetSubject, or an empty string.
func SubjectFrom(ctx contractshttp.Context) string {
	subject, _ := ctx.Value(SubjectKey).(string)

	return subject
}

func subjectFromContext(ctx contractshttp.Context) (string, error) {
	return SubjectFrom(ctx), nil
}

func objectFromRequest(ctx contractshttp.Context) string {
	request := ctx.Request()
	if requested := request.OriginPath(); requested != "" {
		return requested
	}

	return request.Path()
}

func actionFromRequest(ctx contractshttp.Context) string {
	return ctx.Request().Method()
}

func denyWithJSON(ctx contractshttp.Context, _ Decision) {
	abortWithError(ctx, http.StatusForbidden, DefaultDeniedMessage)
}

func abortWithError(ctx contractshttp.Context, status int, message string) {
	ctx.Response().Json(status, contractshttp.Json{"message": message}).Abort()
}
