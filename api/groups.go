package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type VPNGroup struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	ServerID    string `json:"server_id,omitempty"`
	ServerName  string `json:"server_name,omitempty"`
	IsActive    bool   `json:"is_active"`
}

type GroupRequest struct {
	Action      string `json:"action"` // list, add, update, delete
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	ServerID    string `json:"server_id,omitempty"`
}

type GroupResponse struct {
	Message string      `json:"message,omitempty"`
	Groups  []VPNGroup  `json:"groups,omitempty"`
	Group   *VPNGroup   `json:"group,omitempty"`
}

func GroupsHandler(w http.ResponseWriter, r *http.Request) {
	// Allow GET for listing, POST for actions
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Require admin JWT authentication
	if _, err := validateJWTFromRequest(r); err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := getDB()
	if err != nil {
		http.Error(w, "Database unavailable", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// GET - List all groups
	if r.Method == http.MethodGet {
		rows, err := conn.QueryContext(ctx, `
			SELECT 
				g.id::text,
				g.name,
				COALESCE(g.description, ''),
				COALESCE(g.server_id::text, ''),
				COALESCE(s.name, ''),
				g.is_active
			FROM public.vpn_groups g
			LEFT JOIN public.vpn_servers s ON g.server_id = s.id
			ORDER BY g.name
		`)
		if err != nil {
			http.Error(w, "Query failed", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		groups := []VPNGroup{}
		for rows.Next() {
			var g VPNGroup
			if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.ServerID, &g.ServerName, &g.IsActive); err != nil {
				http.Error(w, "Scan failed", http.StatusInternalServerError)
				return
			}
			groups = append(groups, g)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(GroupResponse{Groups: groups})
		return
	}

	// POST - Handle actions
	var req GroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	req.Action = strings.ToLower(strings.TrimSpace(req.Action))

	switch req.Action {
	case "add":
		if req.Name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}

		var serverID interface{} = nil
		if req.ServerID != "" {
			serverID = req.ServerID
		}

		var newID string
		err = conn.QueryRowContext(ctx, `
			INSERT INTO public.vpn_groups (name, description, server_id)
			VALUES ($1, $2, $3::uuid)
			RETURNING id::text
		`, req.Name, req.Description, serverID).Scan(&newID)
		
		if err != nil {
			http.Error(w, "Failed to add group", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(GroupResponse{
			Message: "Group added successfully",
			Group:   &VPNGroup{ID: newID, Name: req.Name},
		})

	case "update":
		if req.ID == "" {
			http.Error(w, "id is required for update", http.StatusBadRequest)
			return
		}

		var serverID interface{} = nil
		if req.ServerID != "" {
			serverID = req.ServerID
		}

		result, err := conn.ExecContext(ctx, `
			UPDATE public.vpn_groups
			SET name = COALESCE(NULLIF($1, ''), name),
			    description = COALESCE(NULLIF($2, ''), description),
			    server_id = $3::uuid,
			    updated_at = NOW()
			WHERE id = $4::uuid
		`, req.Name, req.Description, serverID, req.ID)
		
		if err != nil {
			http.Error(w, "Failed to update group", http.StatusInternalServerError)
			return
		}

		affected, _ := result.RowsAffected()
		if affected == 0 {
			http.Error(w, "Group not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(GroupResponse{Message: "Group updated successfully"})

	case "delete":
		if req.ID == "" {
			http.Error(w, "id is required for delete", http.StatusBadRequest)
			return
		}

		// Soft delete - set is_active to false
		result, err := conn.ExecContext(ctx, `
			UPDATE public.vpn_groups
			SET is_active = false, updated_at = NOW()
			WHERE id = $1::uuid
		`, req.ID)
		
		if err != nil {
			http.Error(w, "Failed to delete group", http.StatusInternalServerError)
			return
		}

		affected, _ := result.RowsAffected()
		if affected == 0 {
			http.Error(w, "Group not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(GroupResponse{Message: "Group deleted successfully"})

	default:
		http.Error(w, "Unsupported action", http.StatusBadRequest)
	}
}
