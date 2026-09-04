package oauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOptions_Validate(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		wantErr  bool
	}{
		{"google", "google", false},
		{"github", "github", false},
		{"https issuer", "https://accounts.google.com", false},
		{"https issuer with path", "https://sso.example.org/realms/homelab", false},
		// http:// is accepted by Validate(); the --insecure gating is
		// enforced separately in oauthCmd.
		{"http issuer", "http://localhost:8080/realms/test", false},
		{"bare name", "keycloak", true},
		{"ftp issuer", "ftp://accounts.google.com", true},
		{"empty", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &options{Provider: tt.provider}
			err := o.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Validate() error = nil, want error for provider %q", tt.provider)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate() error = %v, want nil for provider %q", err, tt.provider)
			}
		})
	}
}

const (
	oidcDoc  = `{"authorization_endpoint":"https://idp.example/auth","token_endpoint":"https://idp.example/token"}`
	oauthDoc = `{"authorization_endpoint":"https://idp.example/oauth/auth","token_endpoint":"https://idp.example/oauth/token"}`
)

func TestDisco(t *testing.T) {
	t.Run("oidc discovery", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/openid-configuration" {
				_, _ = w.Write([]byte(oidcDoc))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		d, err := disco(srv.URL)
		if err != nil {
			t.Fatalf("disco() error = %v", err)
		}
		if got := d["token_endpoint"]; got != "https://idp.example/token" {
			t.Fatalf("token_endpoint = %v, want https://idp.example/token", got)
		}
	})

	t.Run("rfc8414 oauth fallback", func(t *testing.T) {
		// Only the OAuth authorization server metadata path is served; the
		// OIDC path 404s, exercising the RFC 8414 fallback.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/oauth-authorization-server" {
				_, _ = w.Write([]byte(oauthDoc))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		d, err := disco(srv.URL)
		if err != nil {
			t.Fatalf("disco() error = %v", err)
		}
		if got := d["token_endpoint"]; got != "https://idp.example/oauth/token" {
			t.Fatalf("token_endpoint = %v, want https://idp.example/oauth/token", got)
		}
	})

	t.Run("explicit well-known url fetched as-is", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/openid-configuration" {
				_, _ = w.Write([]byte(oidcDoc))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		d, err := disco(srv.URL + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatalf("disco() error = %v", err)
		}
		if d["authorization_endpoint"] != "https://idp.example/auth" {
			t.Fatalf("unexpected metadata: %v", d)
		}
	})

	t.Run("non-200 reports status code", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "nope", http.StatusNotFound)
		}))
		defer srv.Close()

		_, err := disco(srv.URL)
		if err == nil {
			t.Fatal("disco() error = nil, want error")
		}
		if !strings.Contains(err.Error(), "404") {
			t.Fatalf("disco() error = %v, want mention of status code 404", err)
		}
	})

	t.Run("invalid json reports unsupported format", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("<html>not json</html>"))
		}))
		defer srv.Close()

		_, err := disco(srv.URL)
		if err == nil {
			t.Fatal("disco() error = nil, want error")
		}
		if !strings.Contains(err.Error(), "unsupported format") {
			t.Fatalf("disco() error = %v, want unsupported format", err)
		}
	})
}
