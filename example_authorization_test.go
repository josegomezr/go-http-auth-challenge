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

func TestRealWorldAmazonSigV4(t *testing.T) {
	// signature copied from: https://github.com/aws/aws-sdk-go/blob/v1.55.6/aws/signer/v4/v4_test.go#L202
	wwwAuthenticateHeader := "AWS4-HMAC-SHA256 Credential=AKID/19700101/us-east-1/dynamodb/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-meta-other-header;x-amz-meta-other-header_with_underscore;x-amz-security-token;x-amz-target, Signature=a518299330494908a70222cec6899f6f32f297f8595f6df1776d998936652ad9"

	expectedHeaders := http_auth.Challenge{
		Scheme: "AWS4-HMAC-SHA256",
		Params: []http_auth.AuthParam{
			{"Credential", "AKID/19700101/us-east-1/dynamodb/aws4_request"},
			{"SignedHeaders", "content-length;content-type;host;x-amz-date;x-amz-meta-other-header;x-amz-meta-other-header_with_underscore;x-amz-security-token;x-amz-target"},
			{"Signature", "a518299330494908a70222cec6899f6f32f297f8595f6df1776d998936652ad9"},
		},
	}

	results, err := http_auth.ParseAuthorization(wwwAuthenticateHeader, true)
	if err != nil {
		t.Fatalf("Error parsing challenge: %s", err)
	}

	if !reflect.DeepEqual(expectedHeaders, results) {
		t.Fatalf("Returned challenges does not match numbers of expected challenges. expected=%q got=%q", expectedHeaders, results)
	}
}
