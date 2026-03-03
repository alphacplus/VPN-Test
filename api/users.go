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
	// 1. Simple Security: เช็ค Token จาก Header [cite: 2026-03-03]
	authToken := r.Header.Get("X-Alpha-Token")
	if authToken != "AlphaCPlus_Secure_Token_2026" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 2. ข้อมูล User (ในเฟสแรกเราอาจจะเก็บเป็น Slice ไปก่อน)
	// ในอนาคตคุณนัทสามารถเชื่อมต่อกับ MongoDB หรือ PostgreSQL บน Cloud ได้ครับ
	users := []User{
		{ID: "natt_01", IP: "10.8.0.2"},
		{ID: "staff_01", IP: "10.8.0.3"},
		{ID: "dev_node_01", IP: "10.8.0.4"},
	}

	// 3. พ่น JSON ออกไป
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}