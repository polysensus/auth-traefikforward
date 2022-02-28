package server

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const (
	johnDoe        = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	missingHeader  = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	missingSig     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
	missingPayload = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	badTYP         = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVHgifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.KyvCqCPpH_ub8Y6ZGzgTMxIriQ_gDjB2N2i0-0BvxrM"
	algIsNone      = "eyJhbGciOiJub25lIiwgInR5cGUiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.KyvCqCPpH_ub8Y6ZGzgTMxIriQ_gDjB2N2i0-0BvxrM"
)

func Test_lastPathSegment(t *testing.T) {
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   bool
		wantErr bool
	}{
		{"path is token", args{r: &http.Request{URL: &url.URL{Path: johnDoe}}}, johnDoe, true, false},
		{"token is second element", args{
			r: &http.Request{
				URL: &url.URL{Path: strings.Join([]string{"first", johnDoe}, "/")},
			}}, johnDoe, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := lastPathSegment(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("lastPathSegment() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("lastPathSegment() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("lastPathSegment() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func urlParse(t *testing.T, s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parsing url: %s: %v", s, err)
	}
	return u
}

func Test_parseAPIKeyParameter(t *testing.T) {
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   bool
		wantErr bool
	}{
		{"token as query paramater - no path", args{
			r: &http.Request{
				URL: urlParse(t, fmt.Sprintf("https://nowhere.org?api_key=%s", johnDoe)),
			}}, johnDoe, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := parseAPIKeyParameter(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAPIKeyParameter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseAPIKeyParameter() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("parseAPIKeyParameter() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_checkJOSEHeaderFormat(t *testing.T) {
	type args struct {
		token string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
		{"john doe", args{token: johnDoe}, false},
		{"empty token", args{token: ""}, true},
		{"egregiously bad token", args{token: "egregiously bad token"}, true},
		{"missing header", args{token: missingHeader}, true},
		{"missing payload", args{token: missingPayload}, true},
		{"missing sig", args{token: missingSig}, true},
		{"unsecured jwt", args{token: algIsNone}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := checkJOSEHeaderFormat(tt.args.token); (err != nil) != tt.wantErr {
				t.Errorf("checkJOSEHeaderFormat() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExchanger_getRequestToken(t *testing.T) {
	type fields struct {
		cfg *Config
		log logger
		c   *http.Client
	}
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		want1   TokenSource
		wantErr bool
	}{
		// TODO: Add test cases.
		{"token is bearer token", fields{cfg: nil, log: nil, c: nil}, args{
			r: &http.Request{
				Header: map[string][]string{
					"Authorization": {fmt.Sprintf("Bearer %s", johnDoe)},
				},
				// bearer should take precendence
				URL: &url.URL{Path: strings.Join([]string{"audience", johnDoe}, "/")},
			}}, johnDoe, AuthorizationHeader, false},

		{"token is second path element", fields{cfg: nil, log: nil, c: nil}, args{
			r: &http.Request{
				URL: &url.URL{Path: strings.Join([]string{"audience", johnDoe}, "/")},
			}}, johnDoe, LastPathSegment, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := &Exchanger{
				cfg: tt.fields.cfg,
				log: tt.fields.log,
				c:   tt.fields.c,
			}
			got, got1, err := x.getRequestToken(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("Exchanger.getRequestToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Exchanger.getRequestToken() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("Exchanger.getRequestToken() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
