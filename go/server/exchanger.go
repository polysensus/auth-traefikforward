package server

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

type Exchanger struct {
	cfg *Config
}

const (
	AuthorizationH = "Authorization"
	BearerScheme   = "Bearer"
)

func (x *Exchanger) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	values, ok := r.Header[AuthorizationH]

	if !ok {
		http.Error(w, fmt.Sprintf("%s header absent", AuthorizationH), http.StatusForbidden)
		return
	}
	if len(values) != 1 {
		http.Error(w, "multiple authorization headers not supported", http.StatusBadRequest)
		return
	}
	parts := strings.SplitN(values[0], " ", 2)
	if len(parts) != 2 {
		return
	}
	if parts[0] != BearerScheme {
		http.Error(w, fmt.Sprintf("auth scheme '%s' not supported. (only '%s')", parts[0], BearerScheme), http.StatusBadRequest)
		return
	}

	token, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid token encoding: %v", err), http.StatusBadRequest)
		return
	}
	fmt.Println(string(token))

	// Explicit OK, we have no response data
	w.WriteHeader(http.StatusOK)
}

func NewExchanger(cfg *Config) *Exchanger {
	x := &Exchanger{
		cfg: cfg,
	}
	return x
}
