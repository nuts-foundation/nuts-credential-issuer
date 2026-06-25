// Package urls holds small URL helpers shared across adapters.
package urls

import "net/url"

// Join appends path elements to a base URL, avoiding double-slash footguns. It
// returns the base unchanged on the (unexpected) parse error.
func Join(base string, elem ...string) string {
	u, err := url.JoinPath(base, elem...)
	if err != nil {
		return base
	}
	return u
}
