// Management of routes exempted from CSRF checks.
package csrf

import (
	"path"
	"github.com/revel/revel"
	"strings"
)

var (
	exemptionsFullPaths = make(map[string]bool)
	exemptionsActions = make(map[string]bool)
	exemptionsGlobs = make(map[string]struct{})
)

// isExempted checks whether given path is exempt from CSRF checks or not.
func isExempted(c *revel.Controller) bool {
	pathRequest := c.Request.GetPath()
	if _, ok := exemptionsFullPaths[strings.ToLower(pathRequest)]; ok {
		revel.AppLog.Infof("REVEL-CSRF: Ignoring exempted route '%s'...\n", pathRequest)
		return true
	}

	if _, ok := exemptionsActions[c.Action]; ok {
		revel.AppLog.Infof("REVEL-CSRF: Ignoring exempted action '%s'...\n", pathRequest)
		return true
	}

	for glob := range exemptionsGlobs {
		found, err := path.Match(glob, pathRequest)
		if err != nil {
			// See http://golang.org/pkg/path/#Match for error description.
			revel.AppLog.Fatalf("REVEL-CSRF: malformed glob pattern: %#v", err)
		}
		if found {
			revel.AppLog.Infof("REVEL-CSRF: Ignoring exempted route '%s'...", pathRequest)
			return true
		}
	}
	return false
}

// ExemptedFullPath exempts path from CSRF checks.
func ExemptedFullPath(path string) {
	if strings.HasPrefix(path, "/") {
		revel.AppLog.Infof("REVEL-CSRF: Adding exemption '%s'...\n", path)
		exemptionsFullPaths[path] = true
	}
}

// ExemptedFullPaths exempts exact paths from CSRF checks.
func ExemptedFullPaths(paths ...string) {
	for _, v := range paths {
		ExemptedFullPath(v)
	}
}

// ExtemptedAction extempts exact action from CSRF checks.
func ExtemptedAction(action string) {
	if actionParts := strings.Split(action, "."); len(actionParts) == 2 {
		// e.g. "ControllerName.ActionName"
		revel.AppLog.Infof("REVEL-CSRF: Adding exemption '%s'...\n", action)
		exemptionsActions[action] = true
	}
}

// ExtemptedActions extempts exact actions from CSRF checks.
func ExtemptedActions(actions ...string) {
	for _, v := range actions {
		ExtemptedAction(v)
	}
}

// ExemptedGlob exempts one path from CSRF checks using pattern matching.
// See http://golang.org/pkg/path/#Match
func ExemptedGlob(path string) {
	revel.AppLog.Infof("REVEL-CSRF: Adding exemption GLOB '%s'...\n", path)
	exemptionsGlobs[path] = struct{}{}
}

// ExemptedGlobs exempts paths from CSRF checks using pattern matching.
func ExemptedGlobs(paths ...string) {
	for _, v := range paths {
		ExemptedGlob(v)
	}
}