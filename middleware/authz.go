// Package middleware provides HTTP authorization for Goravel, backed by the
// Casbin policies managed by this package.
package middleware

import (
	"net/http"

	"github.com/casbin/casbin/v2"
	contractshttp "github.com/goravel/framework/contracts/http"
	contractslog "github.com/goravel/framework/contracts/log"

	authz "github.com/wcz0/goravel-authz"
	"github.com/wcz0/goravel-authz/internal/logging"
)

const (
	// SubjectKey is the context key written by SetSubject and read by the
	// default subject resolver. It is an alias of authz.SubjectKey.
	SubjectKey = authz.SubjectKey

	// DefaultDeniedMessage is returned by the default denied handler.
	DefaultDeniedMessage = authz.DefaultDeniedMessage

	// DefaultUnavailableMessage is returned when the enforcer cannot be
	// created or evaluated.
	DefaultUnavailableMessage = authz.DefaultUnavailableMessage
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
	Guard string
	// Guards holds every model of a request that was checked against several
	// models (WithGuards). It is empty for a single-guard request.
	Guards  []string
	Subject string
	Object  string
	Action  string
}

// DeniedHandler writes the response of a denied request.
type DeniedHandler func(ctx contractshttp.Context, decision Decision)

// Option configures the authorization middleware.
type Option func(*authzMiddleware)

type authzMiddleware struct {
	guard  string
	guards []string
	tokens []string

	subject SubjectResolver
	object  ObjectResolver
	action  ActionResolver
	denied  DeniedHandler

	logger     contractslog.Writer
	logAllowed bool
	logDenied  bool

	// open is replaced in tests.
	open func(name string) (*casbin.SyncedEnforcer, error)
}

// Authz returns middleware that only lets a request through when the policies
// of a Casbin model allow its subject, object and action.
//
// By default the enforcer of casbin.default is used, the subject is the value
// stored by SetSubject or, when that is empty, the ID of the authenticated
// Goravel Auth user. The object is the route pattern (OriginPath) and the
// action is the HTTP method. Every part can be replaced with an option.
func Authz(options ...Option) contractshttp.Middleware {
	return newAuthz(options...).Handle
}

// newAuthz builds the middleware. A Goravel 1.17 middleware is a plain
// function, so Authz only keeps the Handle method.
func newAuthz(options ...Option) *authzMiddleware {
	settings := logging.Load()

	m := &authzMiddleware{
		subject:    subjectFromRequest,
		object:     objectFromRequest,
		action:     actionFromRequest,
		denied:     denyWithJSON,
		logger:     settings.Logger(),
		logAllowed: settings.Allowed,
		logDenied:  settings.Denied,
		open:       authz.NewEnforcer,
	}

	for _, option := range options {
		option(m)
	}

	return m
}

// Ability returns middleware that checks fixed Casbin request values instead
// of the request path and method:
//
//	router.Get("/articles", handler).Middleware(middleware.Ability("articles", "read"))
//
// evaluates Enforce(subject, "articles", "read"). The subject is resolved like
// Authz does.
func Ability(tokens ...string) contractshttp.Middleware {
	return Authz(WithTokens(tokens...))
}

func (m *authzMiddleware) Handle(ctx contractshttp.Context) {
	decision := Decision{
		Guard:  m.guard,
		Guards: append([]string(nil), m.guards...),
	}

	subject, err := m.subject(ctx)
	if err != nil {
		m.logFailure("authz: subject resolver failed", decision, err)
		m.denied(ctx, decision)
		return
	}
	if subject == "" {
		m.logDeniedRequest(decision, "missing subject")
		m.denied(ctx, decision)
		return
	}
	decision.Subject = subject
	if len(m.tokens) > 0 {
		// Fixed request values: Enforce(subject, tokens...). The object and
		// action are not read from the request in this mode.
		decision.Object = m.tokens[0]
		if len(m.tokens) > 1 {
			decision.Action = m.tokens[1]
		}
	} else {
		decision.Object = m.object(ctx)
		decision.Action = m.action(ctx)
	}

	var failure error
	failureMessage := ""
	for _, guard := range m.guardsToCheck() {
		enforcer, err := m.open(guard)
		if err != nil {
			failure, failureMessage = err, "authz: enforcer unavailable"
			continue
		}

		allowed, err := enforcer.Enforce(m.enforceArgs(subject, decision)...)
		if err != nil {
			failure, failureMessage = err, "authz: enforce failed"
			continue
		}
		if !allowed {
			continue
		}

		m.logAllowedRequest(decision)
		ctx.Request().Next()
		return
	}

	if failure != nil {
		// Failing closed is safer than accepting a request that one of the
		// configured models could not evaluate.
		m.logFailure(failureMessage, decision, failure)
		abortWithError(ctx, http.StatusInternalServerError, DefaultUnavailableMessage)
		return
	}

	m.logDeniedRequest(decision, "policy")
	m.denied(ctx, decision)
}

func (m *authzMiddleware) guardsToCheck() []string {
	if len(m.guards) > 0 {
		return m.guards
	}

	return []string{m.guard}
}

func (m *authzMiddleware) enforceArgs(subject string, decision Decision) []any {
	if len(m.tokens) > 0 {
		args := make([]any, 0, len(m.tokens)+1)
		args = append(args, subject)
		for _, token := range m.tokens {
			args = append(args, token)
		}

		return args
	}

	return []any{subject, decision.Object, decision.Action}
}

func (m *authzMiddleware) logAllowedRequest(decision Decision) {
	if m.logger == nil || !m.logAllowed {
		return
	}

	m.logger.With(decisionFields(decision)).Info("authz: access allowed")
}

func (m *authzMiddleware) logDeniedRequest(decision Decision, reason string) {
	if m.logger == nil || !m.logDenied {
		return
	}

	fields := decisionFields(decision)
	fields["reason"] = reason
	m.logger.With(fields).Warning("authz: access denied")
}

func (m *authzMiddleware) logFailure(message string, decision Decision, err error) {
	if m.logger == nil {
		return
	}

	fields := decisionFields(decision)
	fields["error"] = err
	m.logger.With(fields).Error(message)
}

func decisionFields(decision Decision) map[string]any {
	fields := map[string]any{
		"subject": decision.Subject,
		"object":  decision.Object,
		"action":  decision.Action,
	}
	if decision.Guard != "" {
		fields["guard"] = decision.Guard
	}
	if len(decision.Guards) > 0 {
		fields["guards"] = decision.Guards
	}

	return fields
}

// WithGuard selects the Casbin model to check against. An empty guard uses
// casbin.default. It replaces a previously configured WithGuards list.
func WithGuard(guard string) Option {
	return func(m *authzMiddleware) {
		m.guard = guard
		m.guards = nil
	}
}

// WithGuards allows the request when any of the given models allows it. An
// empty name in the list means casbin.default. It replaces a previously
// configured WithGuard.
func WithGuards(guards ...string) Option {
	return func(m *authzMiddleware) {
		m.guard = ""
		m.guards = append([]string(nil), guards...)
	}
}

// WithTokens replaces the object and action with fixed Casbin request values.
// The request becomes Enforce(subject, tokens...), which is useful for models
// with custom request tokens or for ability checks that do not depend on the
// HTTP path and method:
//
//	middleware.Ability("articles", "read") // Enforce(subject, "articles", "read")
func WithTokens(tokens ...string) Option {
	return func(m *authzMiddleware) {
		m.tokens = append([]string(nil), tokens...)
	}
}

// WithSubject replaces the default subject resolver, which reads the value
// stored by SetSubject and falls back to the authenticated Goravel Auth user.
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
	return authz.SubjectFromContext(ctx)
}

// subjectFromAuth is replaced in tests.
var subjectFromAuth = authz.SubjectFromAuth

// subjectFromRequest prefers the subject stored by SetSubject and falls back
// to the ID of the authenticated Goravel Auth user.
func subjectFromRequest(ctx contractshttp.Context) (string, error) {
	if subject := SubjectFrom(ctx); subject != "" {
		return subject, nil
	}

	return subjectFromAuth(ctx)
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
