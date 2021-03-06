// Generation of tokens.
package csrf

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/revel/revel"
	"io"
)

var rawTokenLength, lengthCSRFToken int

func getRandomBytes(length int) (bytes []byte, err error) {
	bytes = make([]byte, length)
	_, err = io.ReadFull(rand.Reader, bytes)
	return
}

// A CSRF token is generated by encoding bytes read from crypto/rand as base64.
func GenerateNewToken(c *revel.Controller) (token string) {
	bytes, _ := getRandomBytes(rawTokenLength)
	// Due to base64 encoding, CSRF tokens cannot have null bytes and therefore
	// can safely be used as session values in Revel.
	token = base64.StdEncoding.EncodeToString(bytes)
	revel.AppLog.Infof("REVEL-CSRF: Generated new Token: '%s'\n", token)
	c.Session[cookieName] = token
	return
}

func init() {
	revel.OnAppStart(func() {
		rawTokenLength = revel.Config.IntDefault("csrf.token.length", 32)
		if rawTokenLength < 32 || rawTokenLength > 512 {
			panic(fmt.Sprintf("REVEL_CSRF: csrf.token.length=%d: expected a length in [32..512]", rawTokenLength))
		}
		lengthCSRFToken = base64.StdEncoding.EncodedLen(rawTokenLength)

		// Check that cryptographically secure PRNG is available.
		_, err := getRandomBytes(1)
		if err != nil {
			panic(fmt.Sprintf("REVEL_CSRF: crypto/rand is unavailable: Read() failed with %#v", err))
		}
	})
}
