// This handler exchanges the token then proxies the request directly
package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/robinbryce/authex/reqtoken"
)

type GethProxy struct {
	Exchanger
}

func NewGethProxy(cfg *Config) *GethProxy {
	p := &GethProxy{
		Exchanger: *NewExchanger(cfg),
	}
	return p
}

func (p *GethProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	log.Println("headers for auth", "-----")
	for k, v := range r.Header {
		log.Println(k, v)
	}
	log.Println("request url:", r.URL.String())

	// Basic validity checking but NOT VERIFICATION (leave that to the token exchange)
	c, err := reqtoken.FromRequest(r)

	// TODO: audience will come from the api key if it is specified there
	// otherwise it will be picked. Essentially this will need to grow into a
	// mini loadbalancer specialised for ethereum rpc's
	audience := "ethnode1"

	var accessToken string
	switch {
	// case c.Format == reqtoken.FormatNotSupported:
	default:
		if err == nil {
			err = errors.New("an exchangable token was not found in the request")
		}

	case c.Format == reqtoken.FormatAPIKey:
		accessToken, err = p.exchangeAPIKey(r, &c)
	case c.Format == reqtoken.FormatJWT:
		accessToken, err = p.exchangeIDToken(r, &c, audience)
	}
	if err != nil {
		http.Error(
			w, fmt.Sprintf(
				"failed exchanging token: %v", err), http.StatusForbidden)
		return
	}

	// Note that we strip the original request path as that is only used to
	// direct the request to this proxy. If it isn't striped the node will 404
	r.RequestURI = "/"
	r.URL.Path = "/"
	// url, err := url.Parse(fmt.Sprintf("%s://%s:%s/", r.URL.Scheme, audience, "8300"))
	url, err := url.Parse(fmt.Sprintf("http://%s:%s/", audience, "8300"))
	if err != nil {
		http.Error(w, "Failed: "+err.Error(), http.StatusInternalServerError)
	}
	hostHeader := r.Header.Get("Host")
	if hostHeader != "" {
		r.Header.Set("X-Forwarded-Host", hostHeader)
	}
	r.Host = r.URL.Host
	r.Header.Set(reqtoken.AuthorizationH, fmt.Sprintf("Bearer %s", accessToken))
	proxy := httputil.NewSingleHostReverseProxy(url)
	proxy.Transport = p.c.Transport

	log.Println("proxy url:", url.String(), "request url:", r.URL.String())
	proxy.ServeHTTP(w, r)
}
