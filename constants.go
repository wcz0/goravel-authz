package authz

// SubjectKey is the context key that stores the authorization subject. Both
// the HTTP middleware and the Gate integration read it; middleware.SetSubject
// writes it.
const SubjectKey = "goravel-authz:subject"

const (
	// DefaultDeniedMessage is returned when a request is not authorized.
	DefaultDeniedMessage = "This action is unauthorized."

	// DefaultUnavailableMessage is returned when the enforcer cannot be
	// created or evaluated.
	DefaultUnavailableMessage = "Authorization service is unavailable."
)
