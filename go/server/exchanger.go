package server

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"
)

type Logger interface {
	Printf(format string, v ...interface{})
}

type Exchanger struct {
	cfg *Config
	log Logger
}

const (
	AuthorizationH = "Authorization"
	BearerScheme   = "Bearer"
)

// getBearerTokenJwtPayload extract the payload component of an RFC 7519 JWT
// Bearer token from the Authorization header. Write an appropriate error to the
// response and return false if that can't be done.
func getBearerTokenJwtPayload(w http.ResponseWriter, r *http.Request) (string, bool) {

	values, ok := r.Header[AuthorizationH]

	if !ok {
		http.Error(w, fmt.Sprintf("%s header absent", AuthorizationH), http.StatusForbidden)
		return "", false
	}
	if len(values) != 1 {
		http.Error(w, "multiple authorization headers not supported", http.StatusBadRequest)
		return "", false
	}
	parts := strings.SplitN(values[0], " ", 2)
	if len(parts) != 2 {
		return "", false
	}
	if parts[0] != BearerScheme {
		http.Error(w, fmt.Sprintf("auth scheme '%s' not supported. (only '%s')", parts[0], BearerScheme), http.StatusBadRequest)
		return "", false
	}

	token := parts[1]
	parts = strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		http.Error(w, "invalid token: expected three part, dot delimited, jwt format", http.StatusBadRequest)
		return "", false
	}

	return parts[1], true
}

func (x *Exchanger) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	log.Println("headers for auth", "-----")
	for k, v := range r.Header {
		log.Println(k, v)
	}

	raw, ok := getBearerTokenJwtPayload(w, r)
	if !ok {
		return
	}

	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid token payload encoding: %v", err), http.StatusBadRequest)
		return
	}
	x.log.Printf(string(payload))
	w.Header().Set("Authorization", "Bearer re-written-auth")

	// Explicit OK, we have no response data
	w.WriteHeader(http.StatusOK)
}

func NewExchanger(cfg *Config) *Exchanger {
	x := &Exchanger{
		cfg: cfg,
		log: log.Default(),
	}
	return x
}
