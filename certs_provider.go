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
	GetCerts() *Certs
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

func (prv *StaticCertsProvider) GetCerts() *Certs {
	return prv.certs
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
	prv.updateCerts(context.Background())
	return prv
}

const errFormatString string = "[GoogleTokenVerifier][%v] ERROR loading certs from %s: %v\n"
const defaultRefreshBefore time.Duration = -time.Hour

func (prv *CachedURLCertsProvider) GetCerts() *Certs {
	dNow := time.Now()

	prv.mutex.Lock()
	defer prv.mutex.Unlock()

	if dNow.After(prv.expires.Add(prv.refreshBefore)) {
		if dNow.After(prv.expires) {
			// sync
			prv.certs = nil
			prv.mutex.Unlock()
			prv.updateCerts(context.Background())
			prv.mutex.Lock()
			return prv.certs
		}
		go prv.updateCerts(context.Background())
	}
	return prv.certs
}

func (prv *CachedURLCertsProvider) logErr(err error) {
	fmt.Printf(errFormatString, time.Now().Format(time.RFC3339), prv.url, err)
}

func (prv *CachedURLCertsProvider) updateCerts(ctx context.Context) {
	prv.updateMutex.Lock()
	if prv.updating {
		prv.updateMutex.Unlock()
		return
	}
	prv.updating = true
	prv.updateMutex.Unlock()
	prv.loadCertsFromURL(ctx)
	prv.updateMutex.Lock()
	prv.updating = false
	prv.updateMutex.Unlock()
}

func (prv *CachedURLCertsProvider) loadCertsFromURL(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, "GET", prv.url, nil)
	if err != nil {
		prv.logErr(err)
		return
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		prv.logErr(err)
		return
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		err := fmt.Errorf("Unsuccessful status code: %v", res.StatusCode)
		prv.logErr(err)
		return
	}

	expiresHeader, err := http.ParseTime(res.Header.Get("Expires"))
	if err != nil {
		prv.logErr(err)
		return
	}

	bCerts, err := ioutil.ReadAll(res.Body)
	if err != nil {
		prv.logErr(err)
		return
	}
	res.Body.Close()

	var certs *Certs
	err = json.Unmarshal(bCerts, &certs)
	if err != nil {
		prv.logErr(err)
		return
	}

	prv.mutex.Lock()
	defer prv.mutex.Unlock()

	prv.expires = expiresHeader
	prv.certs = certs
}
