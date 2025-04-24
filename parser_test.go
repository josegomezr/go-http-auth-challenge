package http_auth

import (
	"reflect"
	"testing"
)

func TestParseAuthChallengeSimple(t *testing.T) {
	inputHeader := `Basic realm="simple"`

	expectedHeaders := []Challenge{
		{
			Scheme: "Basic",
			Params: Params{
				"realm": "simple",
			},
		},
	}

	results, err := ParseChallenges(inputHeader)
	if err != nil {
		t.Fatalf("Error parsing challenge: %s", err)
	}

	if !reflect.DeepEqual(expectedHeaders, results) {
		t.Fatalf("Returned challenges does not match numbers of expected challenges. expected=%q got=%q", expectedHeaders, results)
	}
}

func TestParseAuthChallengeTwoParams(t *testing.T) {
	inputHeader := `Bearer realm="simple", service=lol`

	expectedHeaders := []Challenge{
		{
			Scheme: "Bearer",
			Params: Params{
				"realm":   "simple",
				"service": "lol",
			},
		},
	}

	results, err := ParseChallenges(inputHeader)
	if err != nil {
		t.Fatalf("Error parsing challenge: %s", err)
	}

	if !reflect.DeepEqual(expectedHeaders, results) {
		t.Fatalf("Returned challenges does not match numbers of expected challenges. expected=%q got=%q", expectedHeaders, results)
	}
}

func TestParseAuthChallenge(t *testing.T) {
	inputHeader := `Newauth realm="apps", type=1, title="Login to \"apps\"", Basic realm="simple"`

	expectedHeaders := []Challenge{
		{
			Scheme: "Newauth",
			Params: Params{
				"realm": "apps",
				"type":  "1",
				"title": "Login to \"apps\"",
			},
		},
		{
			Scheme: "Basic",
			Params: Params{
				"realm": "simple",
			},
		},
	}

	results, err := ParseChallenges(inputHeader)
	if err != nil {
		t.Fatalf("Error parsing challenge: %s", err)
	}

	if len(results) == 0 {
		t.Fatalf("Error no challenge returned. %+v", results)
	}

	if len(results) != len(expectedHeaders) {
		t.Fatalf("Returned challenges does not match numbers of expected challenges. expected=%q got=%q", expectedHeaders, results)
	}

	if !reflect.DeepEqual(expectedHeaders, results) {
		t.Fatalf("Returned challenges does not match numbers of expected challenges. expected=%q got=%q", expectedHeaders, results)
	}
}

func TestParseIncompleteChallenge(t *testing.T) {
	inputHeader := ``

	results, err := ParseChallenges(inputHeader)
	if err == nil {
		t.Fatalf("It did not fail, wtf: %+v", results)
	}
}

func TestParseIncompleteCompoundChallengeNoStrict(t *testing.T) {
	// when setting strict to false we tolerate a bit of borkedness in the header
	inputHeader := `Newauth realm="abc"           ,              , Basic`

	results, err := ParseChallenges(inputHeader)
	expectedHeaders := []Challenge{
		{
			Scheme: "Newauth",
			Params: Params{
				"realm": "abc",
			},
		},
		{
			Scheme: "Basic",
			Params: Params{},
		},
	}
	if err != nil {
		t.Fatalf("Error parsing challenge: %s", err)
	}

	if len(results) == 0 {
		t.Fatalf("Error no challenge returned. %+v", results)
	}

	if len(results) != len(expectedHeaders) {
		t.Fatalf("Returned challenges does not match numbers of expected challenges. expected=%q got=%q", expectedHeaders, results)
	}

	if !reflect.DeepEqual(expectedHeaders, results) {
		t.Fatalf("Returned challenges does not match numbers of expected challenges. expected=%#v got=%#v", expectedHeaders, results)
	}
}
