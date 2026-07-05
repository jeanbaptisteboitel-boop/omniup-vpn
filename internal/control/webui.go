package control

import (
	"embed"
	"net/http"
)

//go:embed webui/index.html
var webuiFS embed.FS

// registerWebUI expose la console d'administration embarquée. La page est
// statique et publique ; toutes les données passent par l'API admin
// (Bearer), la clé étant saisie dans le navigateur.
func registerWebUI(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, _ *http.Request) {
		page, err := webuiFS.ReadFile("webui/index.html")
		if err != nil {
			http.Error(w, "console indisponible", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(page)
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusFound)
	})
}
