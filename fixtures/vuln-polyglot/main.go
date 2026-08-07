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
