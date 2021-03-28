package GoogleIdTokenVerifier

import (
	"encoding/json"
	"io/ioutil"
)

type CertsProvider interface {
	GetCerts() *Certs
}

type StaticCertsProvider struct {
	certs *Certs
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
