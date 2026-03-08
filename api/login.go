package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	OTP      string `json:"otp"`
}

type loginResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

type adminAccount struct {
	ID           string
	Username     string
	PasswordHash string
	TOTPSecret   string
	IsActive     bool
}

var otpRegex = regexp.MustCompile(`^\d{6}$`)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req loginRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" || !otpRegex.MatchString(req.OTP) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	conn, err := getDB()
	if err != nil {
		http.Error(w, "Database unavailable", http.StatusInternalServerError)
		return
	}

	admin, err := loadAdminByUsername(r.Context(), conn, req.Username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	if !admin.IsActive {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	validateOpts := totp.ValidateOpts{
		Period:    readUintEnv("TOTP_PERIOD_SECONDS", 30),
		Skew:      readUintEnv("TOTP_SKEW", 1),
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}

	otpValid, otpErr := totp.ValidateCustom(req.OTP, strings.TrimSpace(admin.TOTPSecret), time.Now().UTC(), validateOpts)
	if otpErr != nil || !otpValid {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		http.Error(w, "Server configuration error", http.StatusInternalServerError)
		return
	}

	ttl := 60 * time.Minute
	if raw := os.Getenv("JWT_TTL_MINUTES"); raw != "" {
		if mins, err := strconv.Atoi(raw); err == nil && mins > 0 {
			ttl = time.Duration(mins) * time.Minute
		}
	}

	now := time.Now()
	expiresAt := now.Add(ttl)

	claims := jwt.MapClaims{
		"sub":      admin.ID,
		"username": admin.Username,
		"iat":      now.Unix(),
		"exp":      expiresAt.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(loginResponse{
		Token:     signedToken,
		ExpiresAt: expiresAt.Unix(),
	})
}

func loadAdminByUsername(ctx context.Context, conn *sql.DB, username string) (*adminAccount, error) {
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var admin adminAccount
	err := conn.QueryRowContext(queryCtx, `
		SELECT id::text, username, password, otp_secret, true
		FROM public.admin_accounts
		WHERE username = $1
		LIMIT 1
	`, username).Scan(
		&admin.ID,
		&admin.Username,
		&admin.PasswordHash,
		&admin.TOTPSecret,
		&admin.IsActive,
	)
	if err != nil {
		return nil, err
	}

	return &admin, nil
}

func readUintEnv(key string, defaultValue uint) uint {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return defaultValue
	}

	parsed, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return defaultValue
	}

	return uint(parsed)
}
