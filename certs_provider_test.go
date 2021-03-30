package GoogleIdTokenVerifier

import (
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testCertsPath string = "testdata/certs.json"

func TestStaticCerts(t *testing.T) {
	staticProvider := NewStaticCertsProvider()
	err := staticProvider.LoadFromFile(testCertsPath)
	require.NoError(t, err)
	certs := staticProvider.GetCerts()
	assertCertsCorrect(t, certs)
	err = staticProvider.LoadFromFile("testdata/non-existing.json")
	require.Error(t, err)
}

func TestHappyDynamicCerts(t *testing.T) {

	var numRequests int32 = 0

	tests := []struct {
		testName       string
		handler        http.HandlerFunc
		expNumRequests int32
		expSuccess     bool
	}{
		{"Happy path dynamic cert", getHandlerFunc(http.StatusOK, time.Hour*2, &numRequests), 1, true},
		{"First request is 500. After that, 200s", appendHandlerFunc(
			getHandlerFunc(http.StatusInternalServerError, 0, nil),
			getHandlerFunc(http.StatusOK, time.Hour*2, nil),
			&numRequests),
			2, true,
		},
		{"No valid cert response", getHandlerFunc(http.StatusInternalServerError, 0, nil), 0, false},
		{"First request is 200 and expires immediately. After that, 500s", appendHandlerFunc(
			getHandlerFunc(http.StatusOK, -time.Hour, nil),
			getHandlerFunc(http.StatusInternalServerError, 0, nil),
			&numRequests),
			2, false,
		},
		{"First request is 200 and expires soon. After that, 500s", appendHandlerFunc(
			getHandlerFunc(http.StatusOK, 10*time.Minute, nil),
			getHandlerFunc(http.StatusInternalServerError, 0, nil),
			&numRequests),
			1, true,
		},
	}

	for _, tc := range tests {
		// nolint
		t.Run(tc.testName, func(t *testing.T) {
			numRequests = 0
			ts := httptest.NewServer(tc.handler)
			certProv := createDynamicCertProvider(ts.URL, defaultRefreshBefore)
			certs := certProv.GetCerts()
			if tc.expSuccess {
				assertCertsCorrect(t, certs)
				assert.LessOrEqual(t, tc.expNumRequests, numRequests)
			} else {
				assert.Nil(t, certs)
			}
			ts.Close()
		})
	}
}

func TestReduceDynamicCerts(t *testing.T) {
	// this is the shared memory where we do atomic operations to
	// calculate how many times the web handler is called
	var numRequests int32 = 0
	sleepTime := 500 * time.Millisecond
	srvFunc := appendHandlerFunc(
		getHandlerFunc(http.StatusOK, 10*time.Minute, nil),
		getSlowHandlerFunc(http.StatusOK, time.Hour*2, nil, sleepTime),
		&numRequests)
	ts := httptest.NewServer(srvFunc)
	certProv := createDynamicCertProvider(ts.URL, defaultRefreshBefore)
	var wg sync.WaitGroup
	for i := 1; i <= 10; i++ {
		wg.Add(1)
		go func(c *CachedURLCertsProvider) {
			certs := c.GetCerts()
			assertCertsCorrect(t, certs)
			wg.Done()
		}(certProv)
	}
	wg.Wait()
	// This is to avoid data races warnings even if the subroutines have already finished
	nRequests := atomic.LoadInt32(&numRequests)
	assert.Equal(t, int32(2), nRequests)
	ts.Close()
}

func assertCertsCorrect(t *testing.T, certs *Certs) {
	require.NotNil(t, certs)
	assert.Equal(t, "RSA", certs.Keys[0].Kty)
	assert.Equal(t, "6a8ba5652a7044121d4fedac8f14d14c54e4895b", certs.Keys[0].Kid)
	assert.Equal(t, len(certs.Keys), 2)
	assert.NotEqual(t, certs.Keys[0].Kid, certs.Keys[1].Kid)
}

var countMutex sync.Mutex

func incrementAndGet(requestCount *int32) int32 {
	countMutex.Lock()
	defer countMutex.Unlock()
	if requestCount != nil {
		return atomic.AddInt32(requestCount, 1)
	}
	return 1
}

func appendHandlerFunc(first http.HandlerFunc, secondOnwards http.HandlerFunc, requestCount *int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rq := incrementAndGet(requestCount)
		if rq == 1 {
			first(w, r)
			return
		}
		secondOnwards(w, r)
	}
}

func getHandlerFunc(statusCode int, expiresIn time.Duration, requestCount *int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		incrementAndGet(requestCount)

		if statusCode != http.StatusOK {
			w.WriteHeader(statusCode)
			return
		}

		file, err := ioutil.ReadFile(testCertsPath)

		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Expires", time.Now().Add(expiresIn).UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, string(file))
	}
}

func getSlowHandlerFunc(statusCode int, expiresIn time.Duration, requestCount *int32, waitTime time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(waitTime)
		getHandlerFunc(statusCode, expiresIn, requestCount)(w, r)
	}
}
