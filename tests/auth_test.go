package tests

import (
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey_NoAuthHeader(t *testing.T) {
	headers := make(http.Header)
	apiKey, err := auth.GetAPIKey(headers)
	if apiKey != "" || err != auth.ErrNoAuthHeaderIncluded {
		t.Errorf("Expected no auth header error, but got apiKey='%s', error='%v'", apiKey, err)
	}
}

func TestGetAPIKey_MalformedAuthHeader(t *testing.T) {
	headers := http.Header{"Authorization": []string{"Bearer"}}
	apiKey, err := auth.GetAPIKey(headers)
	if apiKey != "" || err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("Expected malformed auth header error, but got apiKey='%s', error='%v'", apiKey, err)
	}
}

func TestGetAPIKey_ValidAuthHeader(t *testing.T) {
	headers := http.Header{"Authorization": []string{"ApiKey myApiKey"}}
	apiKey, err := auth.GetAPIKey(headers)
	if apiKey != "myApiKey" || err != nil {
		t.Errorf("Expected apiKey='myApiKey', but got apiKey='%s', error='%v'", apiKey, err)
	}
}

func TestGetAPIKey_ValidBearerHeader(t *testing.T) {
	headers := http.Header{"Authorization": []string{"Bearer myAccessToken"}}
	apiKey, err := auth.GetAPIKey(headers)
	if apiKey != "" || err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("Expected malformed auth header error, but got apiKey='%s', error='%v'", apiKey, err)
	}
}
