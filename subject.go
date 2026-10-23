package authz

import (
	"context"
	"fmt"

	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
	"github.com/goravel/framework/foundation"
)

// SubjectFromContext returns the subject stored in ctx by
// middleware.SetSubject, or an empty string.
func SubjectFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}

	subject, _ := ctx.Value(SubjectKey).(string)

	return subject
}

// SubjectFromAuth returns the ID of the user authenticated by Goravel Auth.
//
// The function is safe to call in applications without the auth service
// provider, without an auth configuration or for guests: it then returns an
// empty subject and no error. Only an invalid auth configuration produces an
// error.
func SubjectFromAuth(ctx contractshttp.Context) (subject string, err error) {
	if ctx == nil || foundation.App == nil {
		return "", nil
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			subject = ""
			err = fmt.Errorf("goravel-authz: resolve the authenticated subject: %v", recovered)
		}
	}()

	config := facades.Config()
	if config == nil || config.GetString("auth.defaults.guard") == "" {
		return "", nil
	}

	auth := facades.Auth(ctx)
	if auth == nil {
		return "", nil
	}

	id, idErr := auth.ID()
	if idErr != nil {
		// A guest or a missing/expired token is not an error here: the
		// authorization layer denies the request as a missing subject.
		return "", nil
	}

	return id, nil
}
