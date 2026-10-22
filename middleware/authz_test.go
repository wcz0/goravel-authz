package middleware

import (
	"errors"
	"net/http"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	contractshttp "github.com/goravel/framework/contracts/http"
	goravelhttp "github.com/goravel/framework/http"
	mockshttp "github.com/goravel/framework/mocks/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testModel = `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act`

func newTestEnforcer(t *testing.T, rules ...[]string) *casbin.SyncedEnforcer {
	t.Helper()

	m, err := model.NewModelFromString(testModel)
	require.NoError(t, err)

	e, err := casbin.NewSyncedEnforcer(m)
	require.NoError(t, err)

	for _, rule := range rules {
		_, err := e.AddPolicy(rule)
		require.NoError(t, err)
	}

	return e
}

func newMockContext(t *testing.T) (*mockshttp.Context, *mockshttp.ContextRequest, *mockshttp.ContextResponse) {
	t.Helper()

	ctx := mockshttp.NewContext(t)
	request := mockshttp.NewContextRequest(t)
	response := mockshttp.NewContextResponse(t)

	ctx.EXPECT().Request().Return(request).Maybe()
	ctx.EXPECT().Response().Return(response).Maybe()

	return ctx, request, response
}

func expectDenied(t *testing.T, response *mockshttp.ContextResponse, status int, message string) {
	t.Helper()

	abortable := mockshttp.NewAbortableResponse(t)
	response.EXPECT().Json(status, contractshttp.Json{"message": message}).Return(abortable)
	abortable.EXPECT().Abort().Return(nil)
}

func TestAuthzAllowsRequest(t *testing.T) {
	mw := Authz().(*authzMiddleware)
	mw.open = func(name string) (*casbin.SyncedEnforcer, error) {
		assert.Equal(t, "", name)
		return newTestEnforcer(t, []string{"alice", "/admin/users", "GET"}), nil
	}

	ctx, request, _ := newMockContext(t)
	ctx.EXPECT().Value(SubjectKey).Return("alice")
	request.EXPECT().OriginPath().Return("/admin/users")
	request.EXPECT().Method().Return("GET")
	request.EXPECT().Next()

	mw.Handle(ctx)
}

func TestAuthzAllowsThroughRole(t *testing.T) {
	mw := Authz().(*authzMiddleware)
	enforcer := newTestEnforcer(t, []string{"admin", "/admin/users", "GET"})
	_, err := enforcer.AddGroupingPolicy("alice", "admin")
	require.NoError(t, err)
	mw.open = func(string) (*casbin.SyncedEnforcer, error) { return enforcer, nil }

	ctx, request, _ := newMockContext(t)
	ctx.EXPECT().Value(SubjectKey).Return("alice")
	request.EXPECT().OriginPath().Return("/admin/users")
	request.EXPECT().Method().Return("GET")
	request.EXPECT().Next()

	mw.Handle(ctx)
}

func TestAuthzDeniesRequest(t *testing.T) {
	mw := Authz().(*authzMiddleware)
	mw.open = func(string) (*casbin.SyncedEnforcer, error) {
		return newTestEnforcer(t, []string{"alice", "/admin/users", "GET"}), nil
	}

	ctx, request, response := newMockContext(t)
	ctx.EXPECT().Value(SubjectKey).Return("bob")
	request.EXPECT().OriginPath().Return("/admin/users")
	request.EXPECT().Method().Return("GET")
	expectDenied(t, response, http.StatusForbidden, DefaultDeniedMessage)

	mw.Handle(ctx)
	request.AssertNotCalled(t, "Next")
}

func TestAuthzMissingSubjectIsDenied(t *testing.T) {
	mw := Authz().(*authzMiddleware)
	mw.open = func(string) (*casbin.SyncedEnforcer, error) {
		t.Fatal("the enforcer must not be opened without a subject")
		return nil, nil
	}

	ctx, _, response := newMockContext(t)
	ctx.EXPECT().Value(SubjectKey).Return(nil)
	expectDenied(t, response, http.StatusForbidden, DefaultDeniedMessage)

	mw.Handle(ctx)
}

func TestAuthzSubjectResolverErrorIsDenied(t *testing.T) {
	mw := Authz(WithSubject(func(contractshttp.Context) (string, error) {
		return "alice", errors.New("token expired")
	})).(*authzMiddleware)
	mw.open = func(string) (*casbin.SyncedEnforcer, error) {
		t.Fatal("the enforcer must not be opened when the subject resolver fails")
		return nil, nil
	}

	ctx, _, response := newMockContext(t)
	expectDenied(t, response, http.StatusForbidden, DefaultDeniedMessage)

	mw.Handle(ctx)
}

func TestAuthzFallsBackToRequestPath(t *testing.T) {
	mw := Authz().(*authzMiddleware)
	mw.open = func(string) (*casbin.SyncedEnforcer, error) {
		return newTestEnforcer(t, []string{"alice", "/users/1", "GET"}), nil
	}

	ctx, request, _ := newMockContext(t)
	ctx.EXPECT().Value(SubjectKey).Return("alice")
	request.EXPECT().OriginPath().Return("")
	request.EXPECT().Path().Return("/users/1")
	request.EXPECT().Method().Return("GET")
	request.EXPECT().Next()

	mw.Handle(ctx)
}

func TestAuthzCustomResolvers(t *testing.T) {
	var opened string
	mw := Authz(
		WithGuard("admin"),
		WithSubject(func(contractshttp.Context) (string, error) { return "bob", nil }),
		WithObject(func(contractshttp.Context) string { return "/reports" }),
		WithAction(func(contractshttp.Context) string { return "read" }),
	).(*authzMiddleware)
	mw.open = func(name string) (*casbin.SyncedEnforcer, error) {
		opened = name
		return newTestEnforcer(t, []string{"bob", "/reports", "read"}), nil
	}

	ctx, request, _ := newMockContext(t)
	request.EXPECT().Next()

	mw.Handle(ctx)
	assert.Equal(t, "admin", opened)
}

func TestAuthzEnforcerErrorReturns500(t *testing.T) {
	mw := Authz().(*authzMiddleware)
	mw.open = func(string) (*casbin.SyncedEnforcer, error) {
		return nil, errors.New("model is broken")
	}

	ctx, request, response := newMockContext(t)
	ctx.EXPECT().Value(SubjectKey).Return("alice")
	request.EXPECT().OriginPath().Return("/admin/users")
	request.EXPECT().Method().Return("GET")
	expectDenied(t, response, http.StatusInternalServerError, DefaultUnavailableMessage)

	mw.Handle(ctx)
	request.AssertNotCalled(t, "Next")
}

func TestAuthzCustomDeniedHandler(t *testing.T) {
	var got Decision
	mw := Authz(WithDenied(func(_ contractshttp.Context, decision Decision) {
		got = decision
	})).(*authzMiddleware)
	mw.open = func(string) (*casbin.SyncedEnforcer, error) {
		return newTestEnforcer(t), nil
	}

	ctx, request, _ := newMockContext(t)
	ctx.EXPECT().Value(SubjectKey).Return("bob")
	request.EXPECT().OriginPath().Return("/admin/users")
	request.EXPECT().Method().Return("DELETE")

	mw.Handle(ctx)

	assert.Equal(t, Decision{
		Guard:   "",
		Subject: "bob",
		Object:  "/admin/users",
		Action:  "DELETE",
	}, got)
	request.AssertNotCalled(t, "Next")
}

func TestAuthzSignature(t *testing.T) {
	assert.Equal(t, "goravel:authz", Authz().Signature())
	assert.Equal(t, "goravel:authz:admin", Authz(WithGuard("admin")).Signature())
}

func TestSetSubject(t *testing.T) {
	ctx := goravelhttp.NewContext()

	assert.Empty(t, SubjectFrom(ctx))

	SetSubject(ctx, "alice")
	assert.Equal(t, "alice", SubjectFrom(ctx))
}

func TestAuthzIgnoresNilOptions(t *testing.T) {
	mw := Authz(
		WithSubject(nil),
		WithObject(nil),
		WithAction(nil),
		WithDenied(nil),
	).(*authzMiddleware)

	ctx, request, _ := newMockContext(t)
	ctx.EXPECT().Value(SubjectKey).Return("alice")
	request.EXPECT().OriginPath().Return("/admin/users")
	request.EXPECT().Method().Return("GET")

	mw.open = func(string) (*casbin.SyncedEnforcer, error) {
		return newTestEnforcer(t, []string{"alice", "/admin/users", "GET"}), nil
	}
	request.EXPECT().Next()

	mw.Handle(ctx)
}
