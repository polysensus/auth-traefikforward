package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	ttlcache "github.com/jellydator/ttlcache/v3"

	"github.com/polysensus/auth-tokenexchange/reqtoken"
)

const (
	exchangeMaxIdleConns = 100
	// As the client is connecting to a single host the default of 2 connections
	// per host in the pool is not appropriate.
	// See https://www.loginradius.com/blog/async/tune-the-go-http-client-for-high-performance/
	exchangeMaxConnsPerHost     = 100
	exchangeMaxIdleConnsPerHost = 100
	exchangeTimeout             = 10 * time.Second
	cacheEntryTTL               = 5 * time.Minute // this can comfortably be 30 minutes or so
	contentTypeH                = "Content-Type"
	contentLengthH              = "Content-Length"
	contentTypeJSON             = "application/json"
	contentTypeURLEncoded       = "application/x-www-form-urlencoded"
	grantTypeTokenExchange      = "urn:ietf:params:oauth:grant-type:token-exchange"
	grantTypeClientCredentials  = "client_credentials"
	idTokenType                 = "urn:ietf:params:oauth:token-type:id_token"
)

type logger interface {
	Printf(format string, v ...interface{})
}
type Exchanger struct {
	cfg   *Config
	log   logger
	c     *http.Client
	cache *ttlcache.Cache[string, string]
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
		cache: ttlcache.New(
			ttlcache.WithTTL[string, string](cacheEntryTTL),
		),
	}
	go x.cache.Start()

	return x
}

func (x *Exchanger) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	log.Println("headers for auth", "-----")
	for k, v := range r.Header {
		log.Println(k, v)
	}
	if r.URL.Fragment != "" {
		http.Error(w, "fragments in the url are not allowed", http.StatusBadRequest)
		return
	}

	// Basic validity checking but NOT VERIFICATION (leave that to the token exchange)
	c, err := reqtoken.FromRequest(r)
	if err != nil || c.Format == reqtoken.FormatNotSupported {
		http.Error(
			w, fmt.Sprintf(
				"failed decoding request token: %v", err), http.StatusBadRequest)
		return
	}

	var accessToken string
	switch {
	// case c.Format == reqtoken.FormatNotSupported:
	default:
		err = errors.New("an exchangable token was not found in the request")

	case c.Format == reqtoken.FormatAPIKey:
		x.log.Printf("exchanging apikey")
		accessToken, err = x.exchangeAPIKey(r, &c)

	case c.Format == reqtoken.FormatJWT:
		x.log.Printf("exchanging idtoken")
		accessToken, err = x.exchangeIDToken(r, &c, "")
	}
	if err != nil {
		http.Error(
			w, fmt.Sprintf(
				"failed exchanging token: %v", err), http.StatusForbidden)
		return
	}

	w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	// Explicit OK, we have no response data
	w.WriteHeader(http.StatusOK)
}

func (x *Exchanger) exchangeIDToken(
	r *http.Request, c *reqtoken.Components, audience string,
) (string, error) {

	urlEncodedParams, err := x.encodeClientSecret(r, c, audience)
	if err != nil {
		return "", err
	}

	if accessToken, ok := x.cacheRead(urlEncodedParams); ok {
		log.Println("cache hit: id token")
		return accessToken, nil
	}
	log.Println("cache miss: id token")

	resp, err := x.exchangeClientCredentials(urlEncodedParams)
	if err != nil {
		return "", err
	}

	accessToken, err := accessTokenFromResponse(resp)
	if err != nil {
		return "", err
	}

	x.cacheToken(urlEncodedParams, accessToken)
	return accessToken, nil
}

func (x *Exchanger) exchangeAPIKey(
	r *http.Request, c *reqtoken.Components,
) (string, error) {

	urlEncodedParams, err := x.encodeAPIKey(r, c)
	if err != nil {
		return "", err
	}

	requestImage := urlEncodedParams + c.Data

	if accessToken, ok := x.cacheRead(requestImage); ok {
		log.Println("cache hit: api key")
		return accessToken, nil
	}

	log.Println("cache miss: api key")
	resp, err := x.exchangeBasicAuth(urlEncodedParams, c.Data)
	if err != nil {
		return "", err
	}
	accessToken, err := accessTokenFromResponse(resp)
	if err != nil {
		return "", err
	}

	x.cacheToken(requestImage, accessToken)
	return accessToken, nil
}

func (x *Exchanger) encodeAPIKey(
	r *http.Request, c *reqtoken.Components,
) (string, error) {

	if c.Format != reqtoken.FormatAPIKey {
		return "", fmt.Errorf("apikey to exchange must be robinbryce/apikey format")
	}

	// Derive the resource from the original request uri
	path := r.Header.Get(reqtoken.XForwardedUri)
	if path == "" {
		path = r.URL.Path
	}

	u := url.URL{Scheme: r.URL.Scheme, Host: r.URL.Host, Path: path}

	if host := r.Header.Get(reqtoken.XForwardedHost); host != "" {
		u.Host = host
	}
	if scheme := r.Header.Get(reqtoken.XForwardedProto); scheme != "" {
		u.Scheme = scheme
	}
	if port := r.Header.Get(reqtoken.XForwardedPort); port != "" {
		// Force on the port if its not standard for the scheme
		if (u.Scheme == "https" && port != "443") || (u.Scheme == "http" && port != "80") {
			u.Host = u.Host + ":" + port
		}
	}

	resource := u.String()

	data := url.Values{}

	// Sending the whole apikey as both secret and id works around an
	// awkwardness in oidc-provider
	// data.Set("client_id", c.Data)
	// data.Set("client_secret", c.Data)
	data.Set("grant_type", grantTypeClientCredentials)
	data.Set("resource", resource)

	return data.Encode(), nil
}

// encodeClientSecret uses the last uri path segment is the audience for the new token.
func (x *Exchanger) encodeClientSecret(
	r *http.Request, c *reqtoken.Components, audience string,
) (string, error) {

	if c.Format != reqtoken.FormatJWT {
		return "", fmt.Errorf("id token to exchange must be jwt format")
	}

	// Infer the desired audience from the original path if the header is present
	path := r.Header.Get(reqtoken.XForwardedUri)
	if path == "" {
		path = r.URL.Path
	}

	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return "", fmt.Errorf("at least one path segment is requred to indicate the audience")
	}

	if audience == "" {
		if c.Source == reqtoken.LastPathSegment {
			if len(parts) < 2 {
				return "", fmt.Errorf("at least two path segments are require when the token is passed in the url")
			}
			audience = parts[len(parts)-2]
		} else {
			audience = parts[len(parts)-1]
		}
	}

	u := url.URL{Scheme: r.URL.Scheme, Host: r.URL.Host, Path: path}
	resource := u.String()

	data := url.Values{}
	data.Set("client_id", x.cfg.ClientID)
	data.Set("client_secret", x.cfg.ClientSecret)
	data.Set("grant_type", grantTypeTokenExchange)
	data.Set("subject_token", c.Data)
	data.Set("subject_token_type", idTokenType)

	data.Set("audience", audience)
	// data.Set("scope", xxx) leave the scopes to the client configuration in the token exchange
	data.Set("resource", resource) // fragment present in url causes error above

	return data.Encode(), nil
}

func (x *Exchanger) exchangeClientCredentials(urlEncodedParams string) (*http.Response, error) {
	xr, err := http.NewRequest("POST", x.cfg.ExchangeURL, strings.NewReader(urlEncodedParams))
	if err != nil {
		return nil, err
	}
	xr.Header.Add(contentTypeH, contentTypeURLEncoded)
	xr.Header.Add(contentLengthH, strconv.Itoa(len(urlEncodedParams)))
	resp, err := x.c.Do(xr)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (x *Exchanger) exchangeBasicAuth(urlEncodedParams, basicAuth string) (*http.Response, error) {

	xr, err := http.NewRequest("POST", x.cfg.ExchangeURL, strings.NewReader(urlEncodedParams))
	if err != nil {
		return nil, err
	}

	// This is how we should do it
	// Supply the clientid:secret in the Authorization: Basic <> header
	xr.Header.Add(reqtoken.AuthorizationH, fmt.Sprintf("Basic %s", basicAuth))

	xr.Header.Add(contentTypeH, contentTypeURLEncoded)
	xr.Header.Add(contentLengthH, strconv.Itoa(len(urlEncodedParams)))
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

func (x *Exchanger) cacheRead(requestImage string) (string, bool) {
	cv := x.cache.Get(requestImage)
	if cv == nil {
		return "", false
	}
	v := cv.Value()
	// Do we have a colision ?
	if !strings.HasPrefix(v, requestImage) {
		log.Println("cache key collision forcing evicttion")
		return "", false
	}
	return v[len(requestImage):], true
}

func (x *Exchanger) cacheToken(
	requestImage, token string) *ttlcache.Item[string, string] {
	return x.cache.Set(requestImage, requestImage+token, ttlcache.DefaultTTL)
}
