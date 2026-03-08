package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"

	handler "vpn-test/api"
)

func main() {
	// Load .env for local development; production uses real environment vars.
	_ = godotenv.Load()

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/users", handler.Handler)
	mux.HandleFunc("/api/login", handler.LoginHandler)
	mux.HandleFunc("/api/manage-user", handler.ManageUserHandler)
	mux.HandleFunc("/api/groups", handler.GroupsHandler)
	mux.HandleFunc("/api/servers", handler.ServersHandler)
	mux.Handle("/", http.FileServer(http.Dir(".")))

	log.Printf("VPN dashboard listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
