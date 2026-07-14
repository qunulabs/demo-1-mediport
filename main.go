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
	mux.HandleFunc("/records", mphttp.RecordsHandler)

	addr := ":8080"
	log.Printf("MediPort listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
