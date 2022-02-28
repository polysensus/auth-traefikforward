// This handler exchanges the token then proxies the request directly
package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
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
	token, source, err := p.getRequestToken(r)
	if source == NoToken {
		if err == nil {
			err = errors.New("an exchangable token was not found in the request")
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if r.URL.Fragment != "" {
		http.Error(w, "fragments in the url are not allowed", http.StatusBadRequest)
		return
	}

	path := r.Header.Get(xForwardedUri)
	if path == "" {
		path = r.URL.Path
	}

	parts := strings.Split(path, "/")
	if source == LastPathSegment {
		parts = parts[:len(parts)-1]
	}

	// TODO: audience will come from the api key if it is specified there
	// otherwise it will be picked. Essentially this will need to grow into a
	// mini loadbalancer specialised for ethereum rpc's
	audience := "ethnode1"
	parts = append(parts, audience)

	u := url.URL{Scheme: r.URL.Scheme, Host: r.URL.Host, Path: strings.Join(parts, "/")}
	resource := u.String()

	resp, err := p.exchangeToken(r, token, resource, audience)
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
	r.Header.Set(AuthorizationH, fmt.Sprintf("Bearer %s", token))
	proxy := httputil.NewSingleHostReverseProxy(url)
	proxy.Transport = p.c.Transport

	log.Println("proxy url:", url.String(), "request url:", r.URL.String())
	proxy.ServeHTTP(w, r)
}
