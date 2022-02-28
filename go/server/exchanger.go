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
	contentTypeH                = "Content-Type"
	contentLengthH              = "Content-Length"
	contentTypeJSON             = "application/json"
	contentTypeURLEncoded       = "application/x-www-form-urlencoded"
	grantTypeTokenExchange      = "urn:ietf:params:oauth:grant-type:token-exchange"
	idTokenType                 = "urn:ietf:params:oauth:token-type:id_token"
	xForwardedUri               = "X-Forwarded-Uri"
	apiKeyParam                 = "api_key"
	apiKeyHeader                = "x-api-key"
	AuthorizationH              = "Authorization"
	BearerScheme                = "Bearer"
	JOSETypeKey                 = "typ"
	JOSEAlgKey                  = "alg"
	JOSEAlgNone                 = "none"
	JOSETypeJWT                 = "JWT"
)

type TokenSource int

const (
	NoToken TokenSource = iota
	AuthorizationHeader
	APIKeyParameter
	APIKeyHeader
	LastPathSegment
)

type logger interface {
	Printf(format string, v ...interface{})
}
type Exchanger struct {
	cfg *Config
	log logger
	c   *http.Client
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

func (x *Exchanger) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	log.Println("headers for auth", "-----")
	for k, v := range r.Header {
		log.Println(k, v)
	}

	// Basic validity checking but NOT VERIFICATION (leave that to the token exchange)
	token, source, err := x.getRequestToken(r)
	if source == NoToken {
		if err == nil {
			err = errors.New("an exchangable token was not found in the request")
		}
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if r.URL.Fragment != "" {
		http.Error(w, "fragments in the url are not allowed", http.StatusBadRequest)
		return
	}

	// Infer the desired audience from the original path if the header is present
	path := r.Header.Get(xForwardedUri)
	if path == "" {
		path = r.URL.Path
	}

	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		http.Error(w, "at least one path segment is requred to indicate the audience", http.StatusBadRequest)
		return
	}

	var audience string
	if source == LastPathSegment {
		if len(parts) < 2 {
			http.Error(w, "at least two path segments are require when the token is passed in the url", http.StatusBadRequest)
			return
		}
		audience = parts[len(parts)-2]
	} else {
		audience = parts[len(parts)-1]
	}

	u := url.URL{Scheme: r.URL.Scheme, Host: r.URL.Host, Path: path}
	resource := u.String()

	resp, err := x.exchangeToken(r, token, resource, audience)
	if err != nil {
		http.Error(
			w, fmt.Sprintf(
				"failed exchanging token: %v", err), http.StatusBadRequest)
		return
	}

	token, err = accessTokenFromResponse(resp)
	if err != nil {
		http.Error(
			w, fmt.Sprintf(
				"failed decoding exchanged token response: %v", err), http.StatusBadGateway)
		return
	}
	// x.log.Println(token)

	w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", token))

	// Explicit OK, we have no response data
	w.WriteHeader(http.StatusOK)
}

// exchangeToken uses the last uri path segment is the audience for the new token.
func (x *Exchanger) exchangeToken(r *http.Request, subjectToken, resource, audience string) (*http.Response, error) {

	data := url.Values{}
	data.Set("client_id", x.cfg.ClientID)
	data.Set("client_secret", x.cfg.ClientSecret)
	data.Set("grant_type", grantTypeTokenExchange)
	data.Set("subject_token", subjectToken)
	data.Set("subject_token_type", idTokenType)

	data.Set("audience", audience)
	// data.Set("scope", xxx) leave the scopes to the client configuration in the token exchange
	data.Set("resource", resource) // fragment present in url causes error above

	encoded := data.Encode()

	xr, err := http.NewRequest("POST", x.cfg.ExchangeURL, strings.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	xr.Header.Add(contentTypeH, contentTypeURLEncoded)
	xr.Header.Add(contentLengthH, strconv.Itoa(len(encoded)))
	resp, err := x.c.Do(xr)
	if err != nil {
		return nil, err
	}
	return resp, nil
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

func parseAPIKeyParameter(r *http.Request) (string, bool, error) {

	var err error
	var u *url.URL

	uri := r.Header.Get(xForwardedUri)
	if uri == "" {
		u = r.URL
	} else {
		u, err = url.Parse(uri)
		if err != nil {
			return "", false, fmt.Errorf("failed parsing forwarded header '%s'", uri)
		}
	}

	q, _ := url.ParseQuery(u.RawQuery)
	apiKey, ok := q[apiKeyParam]
	if !ok {
		return "", false, nil
	}

	if len(apiKey) > 1 {
		return "", false, fmt.Errorf("multiple values for param '%s'", apiKeyParam)
	}
	if apiKey[0] == "" {
		return "", false, fmt.Errorf("empty api key provided for param '%s'", apiKeyParam)
	}

	return apiKey[0], true, nil
}

func lastPathSegment(r *http.Request) (string, bool, error) {

	var err error
	var u *url.URL

	uri := r.Header.Get(xForwardedUri)
	if uri == "" {
		u = r.URL
	} else {
		u, err = url.Parse(uri)
		if err != nil {
			return "", false, fmt.Errorf("failed parsing forwarded header '%s'", uri)
		}
	}

	parts := strings.Split(u.Path, "/")
	if len(parts) < 1 {
		return "", false, nil
	}
	return parts[len(parts)-1], true, nil
}

// checkJOSEHeaderFormat returns true if the token string has a correctly formated jose header.
// see - https://datatracker.ietf.org/doc/html/rfc7519#section-5
// IT DOES NOT VERIFY THE TOKEN
func checkJOSEHeaderFormat(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("header payload and signature fields not found")
	}

	s, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to base64 decode token header: %v", err)
	}
	header := map[string]string{}
	if err := json.Unmarshal(s, &header); err != nil {
		return fmt.Errorf("failed to json parse token header: %v", err)
	}

	if v, ok := header[JOSETypeKey]; !ok || v != JOSETypeJWT {
		return fmt.Errorf(
			"missing or invalid %s JOSE header type. '%s' != '%s' field: %v", JOSETypeKey, v, JOSETypeJWT, err)
	}

	if v, ok := header[JOSEAlgKey]; ok && v == JOSEAlgNone {
		return fmt.Errorf("unsecured jwt's are not supported")
	}
	return nil
}

// getRequestToken extracts an exchangable token from the request
// It returns a constant indicating which part of the request the token was
// taken from. The possible sources are (in precedence order):
// 	Authorization: Bearer  	header
//  APIKey header  			x-api-key
//  APIKey uri parameter 	?api_key
//  Last path segment of X-Forwarded-Uri
//
// THIS FUNCTION DOES NOT VERIFY THE TOKEN
//
// But it does ensure it has appropriate jose header per
//  https://datatracker.ietf.org/doc/html/rfc7519#section-5
func (x *Exchanger) getRequestToken(r *http.Request) (string, TokenSource, error) {

	var ok bool
	var err error
	var token string

	// Do we have an authorization header ?
	values, ok := r.Header[AuthorizationH]
	if ok {

		// Yes, so reject the request if its not what we support
		if len(values) != 1 || !strings.HasPrefix(values[0], BearerScheme) {
			return "", NoToken, fmt.Errorf("unsupported authorization header format")
		}

		parts := strings.SplitN(values[0], " ", 2)
		if len(parts) != 2 {
			return "", NoToken, fmt.Errorf("unsupported authorization header format")
		}

		token := parts[1]
		if err := checkJOSEHeaderFormat(token); err != nil {
			return "", NoToken, err
		}
		return token, AuthorizationHeader, nil
	}

	// Do we have an api key presented as a header ?
	values, ok = r.Header[http.CanonicalHeaderKey(apiKeyHeader)]
	if ok {
		if len(values) != 1 {
			return "", NoToken, fmt.Errorf("unsupported '%s' header format", apiKeyHeader)
		}

		token := values[0]

		if err := checkJOSEHeaderFormat(token); err != nil {
			return "", NoToken, err
		}

		return token, APIKeyHeader, nil
	}

	// Do we have an api key presented as a url parameter ?
	if token, ok, err = parseAPIKeyParameter(r); ok || err != nil {
		if err != nil {
			return "", NoToken, err
		}
		if err := checkJOSEHeaderFormat(token); err != nil {
			return "", NoToken, err
		}

		return token, APIKeyHeader, nil
	}

	// Last chance saloon, attempt to interpret the last path segment as a token

	if token, ok, err = lastPathSegment(r); ok || err != nil {
		if err != nil {
			return "", NoToken, err
		}

		if err := checkJOSEHeaderFormat(token); err != nil {
			return "", NoToken, err
		}

		return token, LastPathSegment, nil
	}

	return "", NoToken, nil

}
