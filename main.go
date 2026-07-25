package main

import (
	"log"
	"net/http"

	mphttp "github.com/qunulabs/mediport/internal/http"
)

func main() {
	mux := http.NewServeMux()
	// Browsers request /favicon.ico on every page; answer 204 so it stops logging a
	// 404 that reads like a fault during the demo. The portal ships no icon on
	// purpose - the security pages are the story, not the branding.
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
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
