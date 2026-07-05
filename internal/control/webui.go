package control

import (
	"embed"
	"net/http"
)

//go:embed webui/index.html webui/portal.html
var webuiFS embed.FS

// registerWebUI expose les pages embarquées : la console d'administration
// (/admin, données via l'API admin en Bearer) et l'espace utilisateur
// (/portal, sessions par cookie).
func registerWebUI(mux *http.ServeMux) {
	servePage := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			page, err := webuiFS.ReadFile("webui/" + name)
			if err != nil {
				http.Error(w, "page indisponible", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(page)
		}
	}
	mux.HandleFunc("GET /admin", servePage("index.html"))
	mux.HandleFunc("GET /portal", servePage("portal.html"))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/portal", http.StatusFound)
	})
}
