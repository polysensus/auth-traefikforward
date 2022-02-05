package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	exchangeMaxIdleConns = 100
	// As the client is connecting to a single host the default of 2 connections
	// per host in the pool is not appropriate.
	// See https://www.loginradius.com/blog/async/tune-the-go-http-client-for-high-performance/
	exchangeMaxConnsPerHost     = 100
	exchangeMaxIdleConnsPerHost = 100
	exchangeTimeout             = 10 * time.Second
	jsonRPCMethodField          = "method"
	contentTypeH                = "Content-Type"
	contentLengthH              = "Content-Length"
	contentTypeJSON             = "application/json"
	contentTypeURLEncoded       = "application/x-www-form-urlencoded"
	grantTypeTokenExchange      = "urn:ietf:params:oauth:grant-type:token-exchange"
	idTokenType                 = "urn:ietf:params:oauth:token-type:id_token"
	xForwardedUri               = "X-Forwarded-Uri"
)

type logger interface {
	Printf(format string, v ...interface{})
}
type Exchanger struct {
	cfg *Config
	log logger
	c   *http.Client
}

const (
	AuthorizationH = "Authorization"
	BearerScheme   = "Bearer"
)

func (x *Exchanger) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	log.Println("headers for auth", "-----")
	for k, v := range r.Header {
		log.Println(k, v)
	}

	// Basic validity checking but NOT VERIFICATION (leave that to the token exchange)
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

	token, err := x.exchangeForQuorum(r)
	if err != nil {
		http.Error(
			w, fmt.Sprintf(
				"failed exchanging token for quorum: %v", err), http.StatusBadRequest)
		return
	}
	log.Println(token)

	w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", token))

	// Explicit OK, we have no response data
	w.WriteHeader(http.StatusOK)
}

// exchangeForQuorum expects the request to be a json-rpc request to a go-quorum
// instance. It attempts a token exchange for a new access token which has an
// aud matching the implied node identity and scopes which include at least the
// json-rpc method being invoked.
func (x *Exchanger) exchangeForQuorum(r *http.Request) (string, error) {

	if r.Header.Get("content-type") != contentTypeJSON {
		return "", errors.New(
			"this endpoint will only exchange tokens for json-rpc requests")
	}

	if r.URL.Fragment != "" {
		return "", errors.New("fragments in the url are not allowed")
	}

	// method, err := jsonRPCMethodFromRequest(r)
	// if err != nil {
	// 	return "", err
	// }

	// Infer the desired audience from the original path if the header is present
	path := r.Header.Get(xForwardedUri)
	if path == "" {
		path = r.URL.Path
	}

	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return "", errors.New(
			"at least one url path segment is required to identify the node audience (--identity)",
		)
	}
	audience := parts[len(parts)-1]

	subjectToken, err := getBearerToken(r)
	if err != nil {
		return "", err
	}

	// take the aud from the tail of the uri, the json api security implemented
	// by quorum demands that the aud in the token matches the identity of the
	// node. The node identity is set via the --identity geth option.

	// Efficiency demands that we either require the token exchange to cache the
	// methods requested for an id and then return the accumulated scopes in one
	// token OR we do that here at some point. Doing it here is likely the best
	// choice as it is also where sessions for the authentication code flow
	// would naturaly reside. For now, no caching, and we get a new token for
	// every request. Note that if we cache, we must also verify the token here
	// instead of leaving it to the exchange.

	data := url.Values{}
	data.Set("client_id", x.cfg.ClientID)
	data.Set("client_secret", x.cfg.ClientSecret)
	data.Set("grant_type", grantTypeTokenExchange)
	data.Set("audience", audience)
	// data.Set("scope", method)
	data.Set("resource", r.URL.String()) // fragment present in url causes error above
	data.Set("subject_token", subjectToken)
	data.Set("subject_token_type", idTokenType)

	encoded := data.Encode()

	xr, err := http.NewRequest("POST", x.cfg.ExchangeURL, strings.NewReader(encoded))
	if err != nil {
		return "", err
	}
	xr.Header.Add(contentTypeH, contentTypeURLEncoded)
	xr.Header.Add(contentLengthH, strconv.Itoa(len(encoded)))
	resp, err := x.c.Do(xr)
	if err != nil {
		return "", err
	}

	return accessTokenFromResponse(resp)
}

// jsonRPCMethodFromRequest expects a json-rpc method payload in the body and returns
// the name of the method being invoked
func jsonRPCMethodFromRequest(r *http.Request) (string, error) {

	dec := json.NewDecoder(r.Body) // Use GetBody if there is need to read more than once
	for {
		var v map[string]interface{}
		if err := dec.Decode(&v); err != nil {
			return "", err
		}
		for k := range v {
			if k != "method" {
				continue
			}
			method, ok := v[k].(string)
			if !ok {
				return "", fmt.Errorf("method name '%v' is not a string", v[k])
			}
			return method, nil
		}
	}
	// return "", errors.New("'method' not found in data. Was it a json-rpc payload ?")
}

// accessTokenFromResponse expects the response body to be a json document
// containing an accss_token field an returns the value for that field. This
// function closes the response body
func accessTokenFromResponse(r *http.Response) (string, error) {

	defer r.Body.Close()

	dec := json.NewDecoder(r.Body) // Use GetBody if there is need to read more than once
	for {
		var v map[string]interface{}
		if err := dec.Decode(&v); err != nil {
			return "", err
		}
		for k := range v {
			if k != "access_token" {
				continue
			}
			token, ok := v[k].(string)
			if !ok {
				return "", fmt.Errorf("token '%v' is not a string", v[k])
			}
			return token, nil
		}
	}
	// return "", errors.New("'method' not found in data. Was it a json-rpc payload ?")
}

func getBearerToken(r *http.Request) (string, error) {
	values, ok := r.Header[AuthorizationH]

	if !ok {
		return "", fmt.Errorf("%s header absent", AuthorizationH)
	}
	if len(values) != 1 {
		return "", errors.New("multiple authorization headers not supported")
	}
	parts := strings.SplitN(values[0], " ", 2)
	if len(parts) != 2 {
		return "", errors.New("invalid authorization header (auth scheme not found)")
	}
	if parts[0] != BearerScheme {
		return "", fmt.Errorf("auth scheme '%s' not supported. (only '%s')", parts[0], BearerScheme)
	}

	token := parts[1]
	return token, nil
}

// getBearerTokenJwtPayload extract the payload component of an RFC 7519 JWT
// Bearer token from the Authorization header. Write an appropriate error to the
// response and return false if that can't be done.
func getBearerTokenJwtPayload(w http.ResponseWriter, r *http.Request) (string, bool) {

	token, err := getBearerToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return "", false
	}

	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		http.Error(w, "invalid token: expected three part, dot delimited, jwt format", http.StatusBadRequest)
		return "", false
	}

	return parts[1], true
}

func NewExchanger(cfg *Config) *Exchanger {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = exchangeMaxIdleConns
	t.MaxConnsPerHost = exchangeMaxConnsPerHost
	t.MaxIdleConnsPerHost = exchangeMaxConnsPerHost
	x := &Exchanger{
		cfg: cfg,
		log: log.Default(),
		c: &http.Client{
			Timeout:   exchangeTimeout,
			Transport: t,
		},
	}
	return x
}
