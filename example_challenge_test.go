package http_auth_test

import (
	http_auth "github.com/josegomezr/go-http-auth-challenge"
	"reflect"
	"testing"
)

func TestRealWorldBearerChallenge(t *testing.T) {
	wwwAuthenticateHeader := `Bearer realm="https://auth.docker.io/token",service="registry.docker.io"`

	expectedHeaders := []http_auth.Challenge{
		{
			Scheme: "Bearer",
			Params: []http_auth.AuthParam{
				{"realm", "https://auth.docker.io/token"},
				{"service", "registry.docker.io"},
			},
		},
	}

	results, err := http_auth.ParseChallenges(wwwAuthenticateHeader, true)
	if err != nil {
		t.Fatalf("Error parsing challenge: %s", err)
	}

	if !reflect.DeepEqual(expectedHeaders, results) {
		t.Fatalf("Returned challenges does not match numbers of expected challenges. expected=%q got=%q", expectedHeaders, results)
	}
}
