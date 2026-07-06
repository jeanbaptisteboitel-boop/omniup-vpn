//go:build !linux

package agent

import "net/http"

// markedHTTPClient : le marquage SO_MARK n'existe que sous Linux (où le
// mode exit node est disponible) ; nil = client HTTP standard.
func markedHTTPClient() *http.Client { return nil }
