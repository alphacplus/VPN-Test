package main

import (
	"log"
	"net/http"
	"os"

	handler "vpn-test/api"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/users", handler.Handler)
	mux.HandleFunc("/api/login", handler.LoginHandler)
	mux.HandleFunc("/api/manage-user", handler.ManageUserHandler)
	mux.Handle("/", http.FileServer(http.Dir(".")))

	log.Printf("VPN dashboard listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
