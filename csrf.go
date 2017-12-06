// Package csrf is a synchronizer Token Pattern implementation.
//
// See [OWASP] https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet
package csrf

import (
	"crypto/subtle"
	"github.com/revel/revel"
	"net/url"
	"regexp"
)

const (
	cookieName = "csrf_token"
	fieldName  = "csrf_token"
	headerName = "X-CSRF-Token"
)

var (
	errNoReferer  = "A secure request contained no Referer or its value was malformed!"
	errBadReferer = "Same-origin policy failure!"
	errBadToken   = "Tokens mismatch!"
	allowedMethods = map[string]bool{
		"GET":     true,
		"HEAD":    true,
		"OPTIONS": true,
		"TRACE":   true,
	}
	sentToken string
)

// Filter implements the CSRF filter.
var Filter = func(c *revel.Controller, fc []revel.Filter) {
	r := c.Request
	if errNoRefererConfig := revel.Config.StringDefault("csrf.errNoReferer", ""); errNoRefererConfig != "" {
		errNoReferer = errNoRefererConfig
	}
	if errBadRefererConfig := revel.Config.StringDefault("csrf.errBadReferer", ""); errBadRefererConfig != "" {
		errBadReferer = errBadRefererConfig
	}
	if errBadTokenConfig := revel.Config.StringDefault("csrf.errBadToken", ""); errBadTokenConfig != "" {
		errBadToken = errBadTokenConfig
	}

	// [OWASP]; General Recommendation: Synchronizer Token Pattern:
	// CSRF tokens must be associated with the user's current session.
	tokenCookie, found := c.Session[cookieName]
	realToken := ""
	if !found {
		realToken = GenerateNewToken(c)
	} else {
		realToken = tokenCookie
		revel.AppLog.Infof("REVEL-CSRF: Session's token: '%s'\n", realToken)
		if len(realToken) != lengthCSRFToken {
			// Wrong length; token has either been tampered with, we're migrating
			// onto a new algorithm for generating tokens, or a new session has
			// been initiated. In any case, a new token is generated and the
			// error will be detected later.
			revel.AppLog.Warnf("REVEL_CSRF: Bad token length: found %d, expected %d",
				len(realToken), lengthCSRFToken)
			realToken = GenerateNewToken(c)
		}
	}

	c.ViewArgs[fieldName] = realToken

	// See http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol#Safe_methods
	if !allowedMethods[c.Request.Method] && !isExempted(c) {
		revel.AppLog.Infof("REVEL-CSRF: Processing unsafe '%s' method...", r.Method)
		if r.URL.Scheme == "https" {
			// See [OWASP]; Checking the Referer Header.
			referer, err := url.Parse(c.Request.Referer())
			if err != nil || referer.String() == "" {
				// Parse error or empty referer.
				if forbidden := revel.Config.StringDefault("csrf.forbidden", ""); forbidden == "" {
					c.Result = c.Forbidden(errNoReferer)
				} else {
					c.Flash.Error(errNoReferer)
					c.Result = c.Redirect(forbidden)
				}
				return
			}
			// See [OWASP]; Checking the Origin Header.
			if !sameOrigin(referer, r.URL) {
				if forbidden := revel.Config.StringDefault("csrf.forbidden", ""); forbidden == "" {
					c.Result = c.Forbidden(errBadReferer)
				} else {
					c.Flash.Error(errBadReferer)
					c.Result = c.Redirect(forbidden)
				}
				return
			}
		}

		if ajaxSupport := revel.Config.BoolDefault("csrf.ajax", false); ajaxSupport {
			// Accept CSRF token in the custom HTTP header X-CSRF-Token, for ease
			// of use with popular JavaScript toolkits which allow insertion of
			// custom headers into all AJAX requests.
			// See http://erlend.oftedal.no/blog/?blogid=118
			sentToken = r.Header.Get(headerName)
		}
		if sentToken == "" {
			// Get CSRF token from form.
			sentToken = c.Params.Get(fieldName)
		}
		revel.AppLog.Infof("REVEL-CSRF: Token received from client: '%s'", sentToken)

		if !compareToken(sentToken, realToken) {
			if forbidden := revel.Config.StringDefault("csrf.forbidden", ""); forbidden == "" {
				revel.AppLog.Info("Triggering forbidden 403")
				c.Result = c.Forbidden(errBadToken)
			} else {
				revel.AppLog.Info("Triggering redirect with flash")
				c.Flash.Error(errBadToken)
				c.Result = c.Redirect(forbidden)
			}
			return
		}
		revel.AppLog.Infof("REVEL-CSRF: Token successfully checked.")
	}

	fc[0](c, fc[1:])
}

// See http://en.wikipedia.org/wiki/Same-origin_policy
func sameOrigin(u1, u2 *url.URL) bool {
	return u1.Scheme == u2.Scheme && u1.Host == u2.Host
}

func compareToken(requestToken, token string) bool {
	// ConstantTimeCompare will panic if the []byte aren't the same length
	if len(requestToken) != len(token) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(requestToken), []byte(token)) == 1
}