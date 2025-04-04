package http_auth_test

import (
	http_auth "github.com/josegomezr/go-http-auth-challenge"
	"reflect"
	"testing"
)

func TestRealWorldBearerAuthorization(t *testing.T) {
	authorizationHeader := `Bearer dG9rZW4=`

	expectedHeaders := http_auth.Authorization{
		Scheme: "Bearer",
		Params: []http_auth.AuthParam{
			{"0", "dG9rZW4="},
		},
	}

	results, err := http_auth.ParseAuthorization(authorizationHeader, true)
	if err != nil {
		t.Fatalf("Error parsing challenge: %s", err)
	}

	if !reflect.DeepEqual(expectedHeaders, results) {
		t.Fatalf("Returned authorizations does not match numbers of expected challenges. expected=%q got=%q", expectedHeaders, results)
	}
}

func TestRealWorldBasicAuthorization(t *testing.T) {
	authorizationHeader := `Basic dG9rZW4=`

	expectedHeaders := http_auth.Authorization{
		Scheme: "Basic",
		Params: []http_auth.AuthParam{
			{"0", "dG9rZW4="},
		},
	}

	results, err := http_auth.ParseAuthorization(authorizationHeader, true)
	if err != nil {
		t.Fatalf("Error parsing challenge: %s", err)
	}

	if !reflect.DeepEqual(expectedHeaders, results) {
		t.Fatalf("Returned authorizations does not match numbers of expected challenges. expected=%q got=%q", expectedHeaders, results)
	}
}
