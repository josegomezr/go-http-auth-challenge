package http_auth

import (
	"reflect"
	"testing"
)

func TestEmpty(t *testing.T) {
	c := NewChallenge()
	if c.Params == nil {
		t.Fatalf("Params map is empty")
	}

	if !c.IsEmpty() {
		t.Fatalf("Cannot assert emptyness")
	}
}

func TestOnlyScheme(t *testing.T) {
	c := NewChallenge()
	c.Scheme = "lol"

	if c.IsEmpty() {
		t.Fatalf("Did not detect that the scheme is set.")
	}
}

func TestAddTokenParam(t *testing.T) {
	c := NewChallenge()
	c.Scheme = "lol"
	value := "A-Token"

	if err := c.setTokenParam(value); err != nil {
		t.Fatalf("Could not save token param on an empty challenge")
	}
	v, ok := c.GetTokenParam()
	if !ok {
		t.Fatalf("Did not saved a token value")
	}
	if v != value {
		t.Fatalf("Token value saved does not match. Got=%q expected=%q", v, value)
	}
}

func TestAddNamedParam(t *testing.T) {
	c := NewChallenge()
	c.Scheme = "lol"
	key, value := "realm", "kindom"

	if err := c.setParam(key, value); err != nil {
		t.Fatalf("Could not save param %q on an empty challenge", key)
	}
	v, ok := c.GetParam(key)
	if !ok {
		t.Fatalf("Did not saved a value on key %q", key)
	}
	if v != value {
		t.Fatalf("Value saved on %q does not match. Got=%q expected=%q", key, v, value)
	}
}

func TestRealmGetter(t *testing.T) {
	c := NewChallenge()
	c.Scheme = "lol"
	key, value := "realm", "kindom"

	if err := c.setParam(key, value); err != nil {
		t.Fatalf("Could not save param %q on an empty challenge", key)
	}
	v, ok := c.Realm()
	if !ok {
		t.Fatalf("Did not saved a value on key %q", key)
	}
	if v != value {
		t.Fatalf("Value saved on %q does not match. Got=%q expected=%q", key, v, value)
	}
}

func TestAddDuplicatedNamedParam(t *testing.T) {
	c := NewChallenge()
	c.Scheme = "lol"
	key, value := "realm", "kindom"

	if err := c.setParam(key, value); err != nil {
		t.Fatalf("Could not save param %q on an empty challenge", key)
	}

	if err := c.setParam(key, value); err == nil {
		t.Fatalf("Allowed to overwrite auth param %q value", key)
	}
}

func TestAddDuplicatedParam(t *testing.T) {
	c := NewChallenge()
	c.Scheme = "lol"
	value := "kindom"

	if err := c.setTokenParam(value); err != nil {
		t.Fatalf("Could not save token param on an empty challenge")
	}

	if err := c.setTokenParam(value); err == nil {
		t.Fatalf("Allowed to overwrite token param value")
	}
}

func TestRealWorldBearerChallenge(t *testing.T) {
	wwwAuthenticateHeader := `Bearer realm="https://auth.docker.io/token",service="registry.docker.io"`

	expectedHeaders := []Challenge{
		{
			Scheme: "Bearer",
			Params: Params{
				"realm":   "https://auth.docker.io/token",
				"service": "registry.docker.io",
			},
		},
	}

	results, err := ParseChallenges(wwwAuthenticateHeader)
	if err != nil {
		t.Fatalf("Error parsing challenge: %s", err)
	}

	if !reflect.DeepEqual(expectedHeaders, results) {
		t.Fatalf("Returned challenges does not match numbers of expected challenges. expected=%q got=%q", expectedHeaders, results)
	}
}
