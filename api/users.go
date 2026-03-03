package handler

import (
	"encoding/json"
	"net/http"
)

type User struct {
	ID string `json:"id"`
	IP string `json:"ip"`
}

func Handler(w http.ResponseWriter, r *http.Request) {
	// Security Check [cite: 2026-03-03]
	if r.Header.Get("X-Alpha-Token") != "AlphaCPlus_Secure_Token_2026" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// รายชื่อ User 50 คน (ตัวอย่างเบื้องต้น)
	users := []User{
		{ID: "natt_01", IP: "10.8.0.2"},
		{ID: "staff_01", IP: "10.8.0.3"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}