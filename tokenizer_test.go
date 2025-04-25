package http_auth

import (
	"reflect"
	"slices"
	"testing"
)

func TestTokenizer(t *testing.T) {
	expected := []string{
		"Basic",
		`realm="abc"`,
		",",
		"lol=1",
	}
	got := slices.Collect(tokenize(`Basic realm="abc"      , lol=1`))
	if !reflect.DeepEqual(expected, got) {
		t.Fatalf("Returned authorizations does not match numbers of expected challenges. expected=%q got=%q", expected, got)
	}
}

func TestTokenizeListSemantics(t *testing.T) {
	// Annoying semantics tbh
	expected := []string{
		"Basic",
		`realm="abc"`,
		",",
		",",
		"lol=1",
	}
	got := slices.Collect(tokenize(`Basic realm="abc", , lol=1`))
	if !reflect.DeepEqual(expected, got) {
		t.Fatalf("Returned authorizations does not match numbers of expected challenges. expected=%q got=%q", expected, got)
	}
}

func TestChunkByComma(t *testing.T) {
	tokens := []string{
		"Basic",
		`realm="abc"`,
		",",
		"lol=1",
	}

	expected := [][]string{
		[]string{
			"Basic",
			`realm="abc"`,
			",",
		},
		[]string{
			"lol=1",
		},
	}

	got := slices.Collect(groupTokensUntilComma(slices.Values(tokens)))
	if !reflect.DeepEqual(expected, got) {
		t.Fatalf("Returned authorizations does not match numbers of expected challenges. expected=%q got=%q", expected, got)
	}
}

func TestProcessChunk(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		_, _, err := processChunk()
		if err == nil {
			t.Fatalf("Unexpected success? empty slices should be invalid")
		}
	})

	t.Run("one-item slice", func(t *testing.T) {
		t.Run("auth-param", func(t *testing.T) {
			_, value, err := processChunk("key=value")
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}

			if value != "key=value" {
				t.Fatalf("Value not saved properly")
			}
		})

		t.Run("token68", func(t *testing.T) {
			_, value, err := processChunk("ToKen68=")
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}

			if value != "ToKen68=" {
				t.Fatalf("Value not saved properly")
			}
		})

		t.Run("scheme", func(t *testing.T) {
			scheme, _, err := processChunk("Sch")
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}

			if scheme != "Sch" {
				t.Fatalf("Value not saved properly")
			}
		})
	})

	t.Run("two-item slice", func(t *testing.T) {
		t.Run("auth-param", func(t *testing.T) {
			scheme, value, err := processChunk("Basic", "key=value")
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}

			if scheme != "Basic" {
				t.Fatalf("Scheme not saved properly. got=%q", scheme)
			}

			if value != "key=value" {
				t.Fatalf("Value not saved properly")
			}
		})

		t.Run("token68", func(t *testing.T) {
			scheme, value, err := processChunk("Basic", "ToKen68=")
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}

			if scheme != "Basic" {
				t.Fatalf("Scheme not saved properly")
			}

			if value != "ToKen68=" {
				t.Fatalf("Value not saved properly")
			}
		})

		t.Run("scheme", func(t *testing.T) {
			scheme, value, err := processChunk("Sch", "LoL")
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}

			if scheme != "Sch" {
				t.Fatalf("Scheme not saved properly, got=%q", scheme)
			}
			if value != "LoL" {
				t.Fatalf("Value not saved properly")
			}
		})

		t.Run("empty scheme", func(t *testing.T) {
			_, _, err := processChunk("", "LoL")
			if err == nil {
				t.Fatalf("Unexpected success")
			}
		})
		t.Run("trailing comma", func(t *testing.T) {
			scheme, value, err := processChunk("Sch", ",")
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}

			if scheme != "" {
				t.Fatalf("Scheme not saved properly, got=%q", scheme)
			}
			if value != "Sch" {
				t.Fatalf("Value not saved properly")
			}
		})
	})

	t.Run("three-item slice", func(t *testing.T) {
		t.Run("complete", func(t *testing.T) {
			scheme, value, err := processChunk("Basic", "key=value", ",")
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}

			if scheme != "Basic" {
				t.Fatalf("Scheme not saved properly")
			}

			if value != "key=value" {
				t.Fatalf("Value not saved properly")
			}
		})

		t.Run("missing scheme", func(t *testing.T) {
			_, _, err := processChunk("", "key=value", ",")
			if err == nil {
				t.Fatalf("Unexpected success")
			}
		})

		t.Run("missing value", func(t *testing.T) {
			_, _, err := processChunk("Basic", "", ",")
			if err == nil {
				t.Fatalf("Unexpected success")
			}
		})

	})
}
