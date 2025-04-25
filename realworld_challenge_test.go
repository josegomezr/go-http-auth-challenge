package http_auth_test

import (
	http_auth "github.com/josegomezr/go-http-auth-challenge"
	"reflect"
	"testing"
)

func TestRealWorldBearerDocker(t *testing.T) {
	wwwAuthenticateHeader := `Bearer realm="https://auth.docker.io/token",service="registry.docker.io"`

	expectedHeaders := []http_auth.Challenge{
		{
			Scheme: "Bearer",
			Params: http_auth.Params{
				"realm":   "https://auth.docker.io/token",
				"service": "registry.docker.io",
			},
		},
	}

	results, err := http_auth.ParseChallenges(wwwAuthenticateHeader)
	if err != nil {
		t.Fatalf("Error parsing challenge: %s", err)
	}

	if !reflect.DeepEqual(expectedHeaders, results) {
		t.Fatalf("Returned challenges does not match numbers of expected challenges. expected=%q got=%q", expectedHeaders, results)
	}
}

func TestRealWorldBearerDockerWithError(t *testing.T) {
	wwwAuthenticateHeader := `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",error="invalid_token"`

	expectedHeaders := []http_auth.Challenge{
		{
			Scheme: "Bearer",
			Params: http_auth.Params{
				"realm":   "https://auth.docker.io/token",
				"service": "registry.docker.io",
				"error":   "invalid_token",
			},
		},
	}

	results, err := http_auth.ParseChallenges(wwwAuthenticateHeader)
	if err != nil {
		t.Fatalf("Error parsing challenge: %s", err)
	}

	if !reflect.DeepEqual(expectedHeaders, results) {
		t.Fatalf("Returned challenges does not match numbers of expected challenges. expected=%q got=%q", expectedHeaders, results)
	}
}

func TestRealWorldBasicGiteaChallenge(t *testing.T) {
	wwwAuthenticateHeader := `Basic realm="gitea-lfs"`

	expectedHeaders := []http_auth.Challenge{
		{
			Scheme: "Basic",
			Params: http_auth.Params{
				"realm": "gitea-lfs",
			},
		},
	}

	results, err := http_auth.ParseChallenges(wwwAuthenticateHeader)
	if err != nil {
		t.Fatalf("Error parsing challenge: %s", err)
	}

	if !reflect.DeepEqual(expectedHeaders, results) {
		t.Fatalf("Returned challenges does not match numbers of expected challenges. expected=%q got=%q", expectedHeaders, results)
	}
}

func TestRealWorldDigest(t *testing.T) {
	wwwAuthenticateHeader := `Basic realm="My Kindom"`

	expectedHeaders := []http_auth.Challenge{
		{
			Scheme: "Basic",
			Params: http_auth.Params{
				"realm": "My Kindom",
			},
		},
	}

	results, err := http_auth.ParseChallenges(wwwAuthenticateHeader)
	if err != nil {
		t.Fatalf("Error parsing challenge: %s", err)
	}

	if !reflect.DeepEqual(expectedHeaders, results) {
		t.Fatalf("Returned challenges does not match numbers of expected challenges. expected=%q got=%q", expectedHeaders, results)
	}
}
