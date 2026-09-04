package oauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The --account file is read and unmarshalled into map[string]interface{}, and
// every value used to be pulled out with a bare type assertion. Each case below
// panicked, except the unsupported-type one, which returned a nil error because
// errors.Wrapf(nil, ...) is nil.
func TestReadAccountCredentialsErrors(t *testing.T) {
	dir := t.TempDir()

	for _, tt := range []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name:    "installed is not an object",
			content: `{"installed":"notamap"}`,
			wantErr: `"installed" must be an object`,
		},
		{
			name:    "installed is missing its keys",
			content: `{"installed":{}}`,
			wantErr: `missing or invalid "auth_uri"`,
		},
		{
			name:    "installed has a non-string value",
			content: `{"installed":{"auth_uri":1}}`,
			wantErr: `missing or invalid "auth_uri"`,
		},
		{
			name:    "service account is missing its keys",
			content: `{"type":"service_account"}`,
			wantErr: `missing or invalid "auth_uri"`,
		},
		{
			name:    "unsupported account type",
			content: `{"other":1}`,
			wantErr: "unsupported account type",
		},
		{
			name:    "not json",
			content: `not json at all`,
			wantErr: "unsupported format",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(tt.name, " ", "_")+".json")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}

			creds, err := readAccountCredentials(path)
			if err == nil {
				t.Fatalf("expected an error, got credentials %+v", creds)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestReadAccountCredentialsMissingFile(t *testing.T) {
	if _, err := readAccountCredentials(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestReadAccountCredentialsInstalled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installed.json")
	content := `{"installed":{"auth_uri":"https://accounts.example.com/auth",` +
		`"token_uri":"https://oauth2.example.com/token",` +
		`"client_id":"cid","client_secret":"secret"}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	creds, err := readAccountCredentials(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.authzEp != "https://accounts.example.com/auth" {
		t.Errorf("unexpected authzEp %q", creds.authzEp)
	}
	if creds.tokenEp != "https://oauth2.example.com/token" {
		t.Errorf("unexpected tokenEp %q", creds.tokenEp)
	}
	if creds.clientID != "cid" || creds.clientSecret != "secret" {
		t.Errorf("unexpected client credentials %q / %q", creds.clientID, creds.clientSecret)
	}
	if creds.do2lo {
		t.Error("do2lo should be false for an installed account")
	}
}

func TestReadAccountCredentialsServiceAccount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sa.json")
	content := `{"type":"service_account","auth_uri":"https://accounts.example.com/auth",` +
		`"token_uri":"https://oauth2.example.com/token","private_key_id":"kid",` +
		`"private_key":"pk","client_email":"svc@example.com"}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	creds, err := readAccountCredentials(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.clientID != "kid" || creds.clientSecret != "pk" {
		t.Errorf("unexpected client credentials %q / %q", creds.clientID, creds.clientSecret)
	}
	if creds.issuer != "svc@example.com" {
		t.Errorf("unexpected issuer %q", creds.issuer)
	}
	if !creds.do2lo {
		t.Error("do2lo should be true for a service account")
	}
}
