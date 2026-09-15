// Control: request data handled safely. Nothing here should be flagged.
package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	// Parameterised query: the value is a bound parameter, not concatenated.
	id := r.URL.Query().Get("id")
	db.Query("SELECT * FROM users WHERE id = $1", id)

	// Allowlisted filename, confined to a fixed directory.
	name := filepath.Base(r.URL.Query().Get("file"))
	os.ReadFile("/srv/docs/" + name)

	// Fixed program and arguments; no request data.
	exec.Command("ls", "-la", "/tmp")

	// Output is HTML-escaped before being written.
	safe := template.HTMLEscapeString(r.FormValue("q"))
	fmt.Fprintf(w, "<h1>%s</h1>", safe)

	// Redirect to a fixed relative path.
	http.Redirect(w, r, "/dashboard", 302)
}
