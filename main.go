package main

import (
	"log"
	"net/http"

	mphttp "github.com/qunulabs/mediport/internal/http"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", mphttp.IndexHandler)
	mux.HandleFunc("/login", mphttp.LoginHandler)
	mux.HandleFunc("/dashboard", mphttp.DashboardHandler)
	mux.HandleFunc("/security", mphttp.SecurityHandler)
	mux.HandleFunc("/records", mphttp.RecordsHandler)
	mux.HandleFunc("/api/diagnostics", mphttp.APIDiagnosticsHandler)

	addr := ":8080"
	log.Printf("MediPort listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
