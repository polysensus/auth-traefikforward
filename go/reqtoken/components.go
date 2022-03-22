package reqtoken

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/robinbryce/apikeys"
)

type TokenSource int

const (
	NoToken TokenSource = iota
	AuthorizationHeader
	APIKeyParameter
	APIKeyHeader
	LastPathSegment
)

type TokenFormat int

const (
	FormatNotSupported TokenFormat = iota
	FormatJWT
	FormatAPIKey
)

const (
	apiKeyParam     = "api_key"
	apiKeyHeader    = "x-api-key"
	AuthorizationH  = "Authorization"
	BearerScheme    = "Bearer"
	XForwardedUri   = "X-Forwarded-Uri"
	XForwardedHost  = "X-Forwarded-Host"
	XForwardedPort  = "X-Forwarded-Port"
	XForwardedProto = "X-Forwarded-Proto"

	JOSETypeKey = "typ"
	JOSEAlgKey  = "alg"
	JOSEAlgNone = "none"
	JOSETypeJWT = "JWT"
)

// Components holds a semi processed and *unverified* token from a request
type Components struct {
	Source            TokenSource
	Format            TokenFormat
	Data              string
	JWTHeader         JWTHeader
	ClientCredentials ClientCredentials
}

type JWTHeader struct {
	Parts  []string
	Header map[string]string
}

// ClientCredentials holds the ClientID extracted from the apikey format we
// support. The secret is the whole apikey token
type ClientCredentials struct {
	ClientID string
	// The whole token is the secret as far as the client_credentials grant is concerned
}

func New(source TokenSource, data string) (Components, error) {

	var werr error
	var err error

	c := Components{Source: source, Data: data}
	if err = DecodeJOSEHeader(&c.JWTHeader, c.Data); err == nil {
		c.Format = FormatJWT
		return c, nil
	}
	werr = fmt.Errorf("failed to decode JOSE header: %w", err)

	ak, _, err := apikeys.Decode(data)
	if err == nil {
		c.Format = FormatAPIKey
		c.ClientCredentials.ClientID = ak.ClientID
		return c, nil
	}
	werr = fmt.Errorf("failed to decode robinbryce/apikeys.Key: %w", werr)

	return Components{Source: NoToken, Format: FormatNotSupported}, werr
}

// DecodeJOSEHeader returns true if the token string has a correctly formated jose header.
// see - https://datatracker.ietf.org/doc/html/rfc7519#section-5
// IT DOES NOT VERIFY THE TOKEN
func DecodeJOSEHeader(m *JWTHeader, token string) error {
	m.Parts = strings.Split(token, ".")
	if len(m.Parts) != 3 {
		return fmt.Errorf("header payload and signature fields not found")
	}

	s, err := base64.RawURLEncoding.DecodeString(m.Parts[0])
	if err != nil {
		return fmt.Errorf("failed to base64 decode token header: %v", err)
	}
	if err := json.Unmarshal(s, &m.Header); err != nil {
		return fmt.Errorf("failed to json parse token header: %v", err)
	}

	if v, ok := m.Header[JOSETypeKey]; !ok || v != JOSETypeJWT {
		return fmt.Errorf(
			"missing or invalid %s JOSE header type. '%s' != '%s' field: %v", JOSETypeKey, v, JOSETypeJWT, err)
	}

	if v, ok := m.Header[JOSEAlgKey]; ok && v == JOSEAlgNone {
		return fmt.Errorf("unsecured jwt's are not supported")
	}
	return nil
}

// FromRequest extracts an exchangable token from the request
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
func FromRequest(r *http.Request) (Components, error) {

	var ok bool
	var err error
	var data string

	// Do we have an authorization header ?
	values, ok := r.Header[AuthorizationH]
	if ok {

		// Yes, so reject the request if its not what we support
		if len(values) != 1 || !strings.HasPrefix(values[0], BearerScheme) {
			return Components{}, fmt.Errorf("unsupported authorization header format")
		}

		parts := strings.SplitN(values[0], " ", 2)
		if len(parts) != 2 {
			return Components{}, fmt.Errorf("unsupported authorization header format")
		}

		return New(AuthorizationHeader, parts[1])
	}

	// Do we have an api key presented as a header ?
	values, ok = r.Header[http.CanonicalHeaderKey(apiKeyHeader)]
	if ok {
		if len(values) != 1 {
			return Components{}, fmt.Errorf("unsupported '%s' header format", apiKeyHeader)
		}

		return New(APIKeyHeader, values[0])
	}

	// Do we have an api key presented as a url parameter ?
	if data, ok, err = parseAPIKeyParameter(r); ok || err != nil {
		if err != nil {
			return Components{}, err
		}

		return New(APIKeyParameter, data)
	}

	// Last chance saloon, attempt to interpret the last path segment as a token

	if data, ok, err = lastPathSegment(r); ok || err != nil {
		if err != nil {
			return Components{}, err
		}

		return New(LastPathSegment, data)
	}

	return Components{}, nil
}

func parseAPIKeyParameter(r *http.Request) (string, bool, error) {

	var err error
	var u *url.URL

	uri := r.Header.Get(XForwardedUri)
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

	uri := r.Header.Get(XForwardedUri)
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
