// VULN pack: golang
package main

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"math/rand"
)

func query(db *sql.DB, id string) {
	// VULN: go.sql-concat
	db.Query(fmt.Sprintf("SELECT * FROM t WHERE id = %s", id))
}

func client() *tls.Config {
	// VULN: go.insecure-skip-verify
	return &tls.Config{InsecureSkipVerify: true}
}

func sessionToken() int {
	// VULN: go.math-rand-secret
	return rand.Intn(1000000)
}

// --- taint pack: request data reaching sinks through a variable ---
func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	id := r.URL.Query().Get("id")
	// VULN: go.taint-sql
	q := "SELECT * FROM users WHERE id = " + id
	db.Query(q)

	host := r.FormValue("host")
	// VULN: go.taint-command
	exec.Command("ping", host)

	path := r.URL.Query().Get("file")
	// VULN: go.taint-file-read
	os.ReadFile("/srv/" + path)

	target := r.FormValue("url")
	// VULN: go.taint-ssrf
	http.Get(target)

	next := r.URL.Query().Get("next")
	// VULN: go.taint-open-redirect
	http.Redirect(w, r, next, 302)

	// VULN: go.taint-xss
	fmt.Fprintf(w, "<h1>%s</h1>", host)
}
