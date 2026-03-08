package handler

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
)

type User struct {
	ID         string `json:"id"`
	IP         string `json:"ip"`
	GroupID    string `json:"group_id,omitempty"`
	GroupName  string `json:"group_name,omitempty"`
	ServerName string `json:"server_name,omitempty"`
}

var (
	db   *sql.DB
	dbMu sync.Mutex
)

func getDB() (*sql.DB, error) {
	dbMu.Lock()
	defer dbMu.Unlock()

	if db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := db.PingContext(ctx); err == nil {
			return db, nil
		}
		_ = db.Close()
		db = nil
	}

	dsn := dbURLFromEnv()
	if dsn == "" {
		return nil, errors.New("DATABASE_URL is not set")
	}

	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	// Keep pool small for serverless workloads.
	conn.SetMaxOpenConns(5)
	conn.SetMaxIdleConns(2)
	conn.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.PingContext(ctx); err != nil {
		_ = conn.Close()
		log.Printf("db ping failed: %v", err)
		return nil, err
	}

	db = conn
	return db, nil
}

func Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := authorizeAgentOrAdmin(r); err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := getDB()
	if err != nil {
		log.Printf("users getDB failed: %v", err)
		http.Error(w, "Database unavailable", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	groupID := strings.TrimSpace(r.URL.Query().Get("group_id"))
	limit := 200
	if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
		if parsedLimit, parseErr := strconv.Atoi(rawLimit); parseErr == nil {
			if parsedLimit < 1 {
				parsedLimit = 1
			}
			if parsedLimit > 1000 {
				parsedLimit = 1000
			}
			limit = parsedLimit
		}
	}

	rows, err := conn.QueryContext(ctx, `
		SELECT 
			u.name, 
			u.ip_address,
			COALESCE(u.group_id::text, ''),
			COALESCE(g.name, ''),
			COALESCE(s.name, '')
		FROM public.vpn_users u
		LEFT JOIN public.vpn_groups g ON u.group_id = g.id
		LEFT JOIN public.vpn_servers s ON g.server_id = s.id
		WHERE u.is_active = true
		  AND ($1 = '' OR u.name ILIKE '%' || $1 || '%' OR u.ip_address ILIKE '%' || $1 || '%' OR g.name ILIKE '%' || $1 || '%' OR s.name ILIKE '%' || $1 || '%')
		  AND ($2 = '' OR u.group_id::text = $2)
		ORDER BY u.name
		LIMIT $3
	`, q, groupID, limit)
	if err != nil {
		log.Printf("users query failed: %v", err)
		http.Error(w, "Query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	users := make([]User, 0)
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.IP, &u.GroupID, &u.GroupName, &u.ServerName); err != nil {
			http.Error(w, "Failed to parse result", http.StatusInternalServerError)
			return
		}
		users = append(users, u)
	}

	if err := rows.Err(); err != nil {
		log.Printf("users rows iteration failed: %v", err)
		http.Error(w, "Result iteration failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(users)
}

func authorizeAgentOrAdmin(r *http.Request) error {
	if isValidAgentToken(r.Header.Get("X-Alpha-Token")) {
		return nil
	}
	_, err := validateJWTFromRequest(r)
	return err
}

func isValidAgentToken(token string) bool {
	alphaToken := os.Getenv("ALPHA_TOKEN")
	if alphaToken == "" || token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(alphaToken)) == 1
}

func validateJWTFromRequest(r *http.Request) (jwt.MapClaims, error) {
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return nil, errors.New("JWT_SECRET is not set")
	}

	authz := r.Header.Get("Authorization")
	parts := strings.SplitN(authz, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return nil, errors.New("missing bearer token")
	}

	token, err := jwt.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(jwtSecret), nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}
	return claims, nil
}

func dbURLFromEnv() string {
	if v := strings.TrimSpace(os.Getenv("DATABASE_URL")); v != "" {
		return v
	}
	// Optional fallback for platforms that expose Postgres via this key.
	if v := strings.TrimSpace(os.Getenv("POSTGRES_URL")); v != "" {
		return v
	}
	return ""
}
