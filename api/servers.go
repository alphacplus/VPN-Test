package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type VPNServer struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Location string `json:"location"`
	MaxUsers int    `json:"max_users"`
	IsActive bool   `json:"is_active"`
}

type ServerRequest struct {
	Action   string `json:"action"` // list, add, update, delete
	ID       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Location string `json:"location,omitempty"`
	MaxUsers int    `json:"max_users,omitempty"`
}

type ServerResponse struct {
	Message string      `json:"message,omitempty"`
	Servers []VPNServer `json:"servers,omitempty"`
	Server  *VPNServer  `json:"server,omitempty"`
}

func ServersHandler(w http.ResponseWriter, r *http.Request) {
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

	// GET - List all servers
	if r.Method == http.MethodGet {
		rows, err := conn.QueryContext(ctx, `
			SELECT 
				id::text,
				name,
				host,
				port,
				protocol,
				COALESCE(location, ''),
				max_users,
				is_active
			FROM public.vpn_servers
			ORDER BY name
		`)
		if err != nil {
			http.Error(w, "Query failed", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		servers := []VPNServer{}
		for rows.Next() {
			var s VPNServer
			if err := rows.Scan(&s.ID, &s.Name, &s.Host, &s.Port, &s.Protocol, &s.Location, &s.MaxUsers, &s.IsActive); err != nil {
				http.Error(w, "Scan failed", http.StatusInternalServerError)
				return
			}
			servers = append(servers, s)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ServerResponse{Servers: servers})
		return
	}

	// POST - Handle actions
	var req ServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	req.Action = strings.ToLower(strings.TrimSpace(req.Action))

	switch req.Action {
	case "add":
		if req.Name == "" || req.Host == "" {
			http.Error(w, "name and host are required", http.StatusBadRequest)
			return
		}

		port := req.Port
		if port == 0 {
			port = 1194
		}
		protocol := req.Protocol
		if protocol == "" {
			protocol = "udp"
		}
		maxUsers := req.MaxUsers
		if maxUsers == 0 {
			maxUsers = 100
		}

		var newID string
		err = conn.QueryRowContext(ctx, `
			INSERT INTO public.vpn_servers (name, host, port, protocol, location, max_users)
			VALUES ($1, $2, $3, $4, $5, $6)
			RETURNING id::text
		`, req.Name, req.Host, port, protocol, req.Location, maxUsers).Scan(&newID)
		
		if err != nil {
			http.Error(w, "Failed to add server", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ServerResponse{
			Message: "Server added successfully",
			Server:  &VPNServer{ID: newID, Name: req.Name},
		})

	case "update":
		if req.ID == "" {
			http.Error(w, "id is required for update", http.StatusBadRequest)
			return
		}

		result, err := conn.ExecContext(ctx, `
			UPDATE public.vpn_servers
			SET name = COALESCE(NULLIF($1, ''), name),
			    host = COALESCE(NULLIF($2, ''), host),
			    port = CASE WHEN $3 > 0 THEN $3 ELSE port END,
			    protocol = COALESCE(NULLIF($4, ''), protocol),
			    location = COALESCE(NULLIF($5, ''), location),
			    max_users = CASE WHEN $6 > 0 THEN $6 ELSE max_users END,
			    updated_at = NOW()
			WHERE id = $7::uuid
		`, req.Name, req.Host, req.Port, req.Protocol, req.Location, req.MaxUsers, req.ID)
		
		if err != nil {
			http.Error(w, "Failed to update server", http.StatusInternalServerError)
			return
		}

		affected, _ := result.RowsAffected()
		if affected == 0 {
			http.Error(w, "Server not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ServerResponse{Message: "Server updated successfully"})

	case "delete":
		if req.ID == "" {
			http.Error(w, "id is required for delete", http.StatusBadRequest)
			return
		}

		// Soft delete - set is_active to false
		result, err := conn.ExecContext(ctx, `
			UPDATE public.vpn_servers
			SET is_active = false, updated_at = NOW()
			WHERE id = $1::uuid
		`, req.ID)
		
		if err != nil {
			http.Error(w, "Failed to delete server", http.StatusInternalServerError)
			return
		}

		affected, _ := result.RowsAffected()
		if affected == 0 {
			http.Error(w, "Server not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ServerResponse{Message: "Server deleted successfully"})

	default:
		http.Error(w, "Unsupported action", http.StatusBadRequest)
	}
}
