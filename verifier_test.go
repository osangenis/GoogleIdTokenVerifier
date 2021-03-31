package GoogleIdTokenVerifier

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckToken(t *testing.T) {
	authToken := "XXXXXXXXXXX.XXXXXXXXXXXX.XXXXXXXXXX"
	aud := "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.apps.googleusercontent.com"
	staticProvider := NewStaticCertsProvider()
	err := staticProvider.LoadFromFile(testCertsPath)
	require.NoError(t, err)
	verifier := New(staticProvider)
	actual := verifier.Verify(authToken, aud)
	assert.NotNil(t, actual)
	// TODO: do a proper test of a token verification
}
