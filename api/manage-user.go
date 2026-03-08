package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type manageUserRequest struct {
	Action  string `json:"action"`
	ID      string `json:"id"`
	IP      string `json:"ip"`
	GroupID string `json:"group_id"`
}

type manageUserResponse struct {
	Message string `json:"message"`
}

func ManageUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if _, err := validateJWTFromRequest(r); err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req manageUserRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	req.Action = strings.ToLower(strings.TrimSpace(req.Action))
	req.ID = strings.TrimSpace(req.ID)
	req.IP = strings.TrimSpace(req.IP)

	if req.ID == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}

	conn, err := getDB()
	if err != nil {
		http.Error(w, "Database unavailable", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	switch req.Action {
	case "add":
		if req.IP == "" {
			http.Error(w, "ip is required for add action", http.StatusBadRequest)
			return
		}
		
		var groupID interface{} = nil
		if req.GroupID != "" {
			groupID = req.GroupID
		}
		
		_, err = conn.ExecContext(ctx, `
			INSERT INTO public.vpn_users (name, ip_address, group_id, is_active)
			VALUES ($1, $2, $3::uuid, true)
		`, req.ID, req.IP, groupID)
		if err != nil {
			http.Error(w, "Failed to add user", http.StatusInternalServerError)
			return
		}

	case "ban":
		result, execErr := conn.ExecContext(ctx, `
			UPDATE public.vpn_users
			SET is_active = false
			WHERE name = $1
		`, req.ID)
		if execErr != nil {
			http.Error(w, "Failed to ban user", http.StatusInternalServerError)
			return
		}
		affected, affErr := result.RowsAffected()
		if affErr != nil || affected == 0 {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
	
	case "update-group":
		if req.ID == "" {
			http.Error(w, "id is required for update-group action", http.StatusBadRequest)
			return
		}
		
		var groupID interface{} = nil
		if req.GroupID != "" {
			groupID = req.GroupID
		}
		
		result, execErr := conn.ExecContext(ctx, `
			UPDATE public.vpn_users
			SET group_id = $1::uuid, updated_at = NOW()
			WHERE name = $2 AND is_active = true
		`, groupID, req.ID)
		if execErr != nil {
			http.Error(w, "Failed to update user group", http.StatusInternalServerError)
			return
		}
		affected, affErr := result.RowsAffected()
		if affErr != nil || affected == 0 {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

	default:
		http.Error(w, "Unsupported action", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(manageUserResponse{Message: "ok"})
}
