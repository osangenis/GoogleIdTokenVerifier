package GoogleIdTokenVerifier

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// https://developers.google.com/identity/sign-in/web/backend-auth
// https://github.com/google/oauth2client/blob/master/oauth2client/crypt.py

type GoogleTokenVerifier struct {
	certProvider CertsProvider
}

// Default is the way to go to verify Google tokens ;-)
var Default *GoogleTokenVerifier = New(NewCachedURLCertsProvider())

func New(prv CertsProvider) *GoogleTokenVerifier {
	return &GoogleTokenVerifier{prv}
}

func (v *GoogleTokenVerifier) Verify(authToken string, aud string) *TokenInfo {
	var niltokeninfo *TokenInfo
	header, payload, signature, messageToSign, err := divideAuthToken(authToken)
	if err != nil {
		return niltokeninfo
	}

	certs, err := v.certProvider.GetCerts()
	if err != nil {
		return niltokeninfo
	}

	tokeninfo, err := getTokenInfo(payload)
	if err != nil {
		return niltokeninfo
	}

	if aud != tokeninfo.Aud {
		err := errors.New("Token is not valid, Audience from token and certificate don't match")
		fmt.Printf("Error verifying key %s\n", err.Error())
		return niltokeninfo
	}
	if (tokeninfo.Iss != "accounts.google.com") && (tokeninfo.Iss != "https://accounts.google.com") {
		err := errors.New("Token is not valid, ISS from token and certificate don't match")
		fmt.Printf("Error verifying key %s\n", err.Error())
		return niltokeninfo
	}
	if !checkTime(tokeninfo) {
		err := errors.New("Token is not valid, Token is expired.")
		fmt.Printf("Error verifying key %s\n", err.Error())
		return niltokeninfo
	}

	authTokenKeyID, err := getAuthTokenKeyID(header)
	if err != nil {
		return niltokeninfo
	}

	key, err := choiceKeyByKeyID(certs.Keys, authTokenKeyID)
	if err != nil {
		fmt.Printf("Error verifying key %s\n", err.Error())
		return niltokeninfo
	}
	pKey := rsa.PublicKey{N: byteToInt(urlsafeB64decode(key.N)), E: btrToInt(byteToBtr(urlsafeB64decode(key.E)))}
	err = rsa.VerifyPKCS1v15(&pKey, crypto.SHA256, messageToSign, signature)
	if err != nil {
		fmt.Printf("Error verifying key %s\n", err.Error())
		return niltokeninfo
	}
	return tokeninfo
}

func getTokenInfo(bt []byte) (*TokenInfo, error) {
	var a *TokenInfo
	err := json.Unmarshal(bt, &a)
	return a, err
}

func checkTime(tokeninfo *TokenInfo) bool {
	if (time.Now().Unix() < tokeninfo.Iat) || (time.Now().Unix() > tokeninfo.Exp) {
		return false
	}
	return true
}

//GetCertsFromURL is
func GetCertsFromURL() []byte {
	res, _ := http.Get("https://www.googleapis.com/oauth2/v3/certs")
	certs, _ := ioutil.ReadAll(res.Body)
	res.Body.Close()
	return certs
}

//GetCerts is
func GetCerts(bt []byte) (*Certs, error) {
	var certs *Certs
	err := json.Unmarshal(bt, &certs)
	return certs, err
}

func urlsafeB64decode(str string) []byte {
	if m := len(str) % 4; m != 0 {
		str += strings.Repeat("=", 4-m)
	}
	bt, _ := base64.URLEncoding.DecodeString(str)
	return bt
}

func choiceKeyByKeyID(a []keys, tknkid string) (keys, error) {
	// TODO: Improve
	if len(a) == 2 {
		if a[0].Kid == tknkid {
			return a[0], nil
		}
		if a[1].Kid == tknkid {
			return a[1], nil
		}
	}
	err := errors.New("Token is not valid, kid from token and certificate don't match")
	var b keys
	return b, err
}

func getAuthTokenKeyID(bt []byte) (string, error) {
	var a keys
	err := json.Unmarshal(bt, &a)
	return a.Kid, err
}

func divideAuthToken(str string) ([]byte, []byte, []byte, []byte, error) {
	args := strings.Split(str, ".")
	sum, err := calcSum(args[0] + "." + args[1])
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	return urlsafeB64decode(args[0]), urlsafeB64decode(args[1]), urlsafeB64decode(args[2]), sum, nil
}

func byteToBtr(bt0 []byte) *bytes.Reader {
	var bt1 []byte
	if len(bt0) < 8 {
		bt1 = make([]byte, 8-len(bt0), 8)
		bt1 = append(bt1, bt0...)
	} else {
		bt1 = bt0
	}
	return bytes.NewReader(bt1)
}

func calcSum(str string) ([]byte, error) {
	a := sha256.New()
	_, err := a.Write([]byte(str))
	if err != nil {
		return []byte{}, err
	}
	return a.Sum(nil), nil
}

func btrToInt(a io.Reader) int {
	var e uint64
	_ = binary.Read(a, binary.BigEndian, &e)
	return int(e)
}

func byteToInt(bt []byte) *big.Int {
	a := big.NewInt(0)
	a.SetBytes(bt)
	return a
}
