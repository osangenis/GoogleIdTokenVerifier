package GoogleIdTokenVerifier

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStaticCerts(t *testing.T) {
	staticProvider := NewStaticCertsProvider()
	err := staticProvider.LoadFromFile("testdata/certs.json")
	require.NoError(t, err)
	certs := staticProvider.GetCerts()
	assert.Equal(t, "RSA", certs.Keys[0].Kty)
	assert.Equal(t, "6a8ba5652a7044121d4fedac8f14d14c54e4895b", certs.Keys[0].Kid)
	assert.Equal(t, len(certs.Keys), 2)
	assert.NotEqual(t, certs.Keys[0].Kid, certs.Keys[1].Kid)

	err = staticProvider.LoadFromFile("testdata/non-existing.json")
	require.Error(t, err)
}
