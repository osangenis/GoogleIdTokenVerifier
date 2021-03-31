package GoogleIdTokenVerifier

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"
)

const GoogleCertsURL string = "https://www.googleapis.com/oauth2/v3/certs"

type CertsProvider interface {
	GetCerts() (*Certs, error)
}

type StaticCertsProvider struct {
	certs *Certs
}

type CachedURLCertsProvider struct {
	certs         *Certs
	url           string
	expires       time.Time
	refreshBefore time.Duration
	mutex         sync.Mutex
	updating      bool
	updateMutex   sync.Mutex
}

func NewStaticCertsProvider() *StaticCertsProvider {
	return &StaticCertsProvider{}
}

func (prv *StaticCertsProvider) GetCerts() (*Certs, error) {
	return prv.certs, nil
}

// AppendFromFile expects the path of a JSON file with the Certs format
func (prv *StaticCertsProvider) LoadFromFile(certpath string) error {
	file, _ := ioutil.ReadFile(certpath)
	data := Certs{}
	err := json.Unmarshal([]byte(file), &data)
	if err != nil {
		return err
	}
	prv.certs = &data
	return nil
}

func NewCachedURLCertsProvider() *CachedURLCertsProvider {
	return createDynamicCertProvider(GoogleCertsURL, defaultRefreshBefore)
}

func createDynamicCertProvider(rawUrl string, refreshBefore time.Duration) *CachedURLCertsProvider {
	prv := &CachedURLCertsProvider{
		certs:         nil,
		url:           rawUrl,
		expires:       time.Now(),
		refreshBefore: refreshBefore,
		updating:      false}

	// try to load certs right now in sync mode, even if it fails
	_ = prv.updateCerts(context.Background())
	return prv
}

const errFormatString string = "[GoogleTokenVerifier][%v] ERROR loading certs from %s: %v\n"
const errCouldNotLoad string = "Could not retrieve a valid certificate from %s\n"
const defaultRefreshBefore time.Duration = -time.Hour

func (prv *CachedURLCertsProvider) GetCerts() (*Certs, error) {
	dNow := time.Now()

	prv.mutex.Lock()
	defer prv.mutex.Unlock()

	if dNow.After(prv.expires.Add(prv.refreshBefore)) {
		if dNow.After(prv.expires) {
			// sync
			prv.certs = nil
			prv.mutex.Unlock()
			err := prv.updateCerts(context.Background())
			prv.mutex.Lock()
			return prv.certs, err
		}
		go func() {
			_ = prv.updateCerts(context.Background())
		}()
	}

	if prv.certs == nil {
		return nil, fmt.Errorf(errCouldNotLoad, prv.url)
	}
	return prv.certs, nil
}

func (prv *CachedURLCertsProvider) logErr(err error) {
	fmt.Printf(errFormatString, time.Now().Format(time.RFC3339), prv.url, err)
}

func (prv *CachedURLCertsProvider) updateCerts(ctx context.Context) error {
	prv.updateMutex.Lock()
	if prv.updating {
		prv.updateMutex.Unlock()
		return nil
	}
	prv.updating = true
	prv.updateMutex.Unlock()
	err := prv.loadCertsFromURL(ctx)
	prv.updateMutex.Lock()
	prv.updating = false
	prv.updateMutex.Unlock()
	return err
}

func (prv *CachedURLCertsProvider) loadCertsFromURL(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", prv.url, nil)
	if err != nil {
		prv.logErr(err)
		return err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		prv.logErr(err)
		return err
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		err := fmt.Errorf("Unsuccessful status code: %v", res.StatusCode)
		prv.logErr(err)
		return err
	}

	expiresHeader, err := http.ParseTime(res.Header.Get("Expires"))
	if err != nil {
		prv.logErr(err)
		return err
	}

	bCerts, err := ioutil.ReadAll(res.Body)
	if err != nil {
		prv.logErr(err)
		return err
	}
	res.Body.Close()

	var certs *Certs
	err = json.Unmarshal(bCerts, &certs)
	if err != nil {
		prv.logErr(err)
		return err
	}

	prv.mutex.Lock()
	defer prv.mutex.Unlock()

	prv.expires = expiresHeader
	prv.certs = certs
	return nil
}
