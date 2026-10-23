package authz

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubjectFromContext(t *testing.T) {
	assert.Empty(t, SubjectFromContext(nil))
	assert.Empty(t, SubjectFromContext(context.Background()))

	ctx := context.WithValue(context.Background(), SubjectKey, "alice")
	assert.Equal(t, "alice", SubjectFromContext(ctx))
}

func TestSubjectFromAuthWithoutApplication(t *testing.T) {
	subject, err := SubjectFromAuth(nil)

	require.NoError(t, err)
	assert.Empty(t, subject, "an application that did not boot the framework has no auth user")
}
