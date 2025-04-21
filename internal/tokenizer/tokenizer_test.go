package tokenizer

import (
	"reflect"
	"testing"
)

func TestSingleChallenge(t *testing.T) {
	header := `Newauth realm="apps", type=1, title="Login to \"apps\""`
	expected := []Token{
		{TokenToken, "Newauth"},
		{TokenAuthParam, `realm="apps"`},
		{TokenAuthParam, `type=1`},
		{TokenAuthParam, `title="Login to \"apps\""`},
	}
	idx := 0
	for got := range Tokenize(header) {
		if idx >= len(expected) {
			t.Fatalf("Failed. got extra token=%+v", got)
		}
		if !reflect.DeepEqual(got, expected[idx]) {
			t.Fatalf("Failed. got=%+v expected=%+v", got, expected[idx])
		}
		idx += 1
	}
	if len(expected) != idx {
		t.Fatalf("Failed. Token count mismatch. Last token=%#v", expected[idx])
	}
}

func TestDoubleChallenge(t *testing.T) {
	header := `Newauth realm="apps", type=1, title="Login to \"apps\"", Basic realm="simple"`
	expected := []Token{
		{TokenToken, "Newauth"},
		{TokenAuthParam, `realm="apps"`},
		{TokenAuthParam, `type=1`},
		{TokenAuthParam, `title="Login to \"apps\""`},
		{TokenToken, "Basic"},
		{TokenAuthParam, `realm="simple"`},
	}
	idx := 0
	for got := range Tokenize(header) {
		if idx >= len(expected) {
			t.Fatalf("Failed. got extra token=%#v", got)
		}
		if !reflect.DeepEqual(got, expected[idx]) {
			t.Fatalf("Failed. got=%#v expected=%#v", got, expected[idx])
		}
		idx += 1
	}
	if len(expected) != idx {
		t.Fatalf("Failed. Token count mismatch")
	}
}

func TestAuthorizationWithoutAuthParams(t *testing.T) {
	header := `Bearer S0VLU0UhIExFQ0tFUiEK, Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ== `
	expected := []Token{
		{TokenToken, "Bearer"},
		{TokenToken68, "S0VLU0UhIExFQ0tFUiEK"},
		{TokenToken, "Basic"},
		{TokenToken68, "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="},
	}
	idx := 0
	for got := range Tokenize(header) {
		if idx >= len(expected) {
			t.Fatalf("Failed. got extra token=%#v", got)
		}
		if !reflect.DeepEqual(got, expected[idx]) {
			t.Fatalf("Failed. got=%#v expected=%#v", got, expected[idx])
		}
		idx += 1
	}
	if len(expected) != idx {
		t.Fatalf("Failed. Token count mismatch")
	}
}

func TestAuthorizationMixedWithParams(t *testing.T) {
	header := `Bearer S0VLU0UhIExFQ0tFUiEK, Signature QWxhZGRpbjpvcGVuIHNlc2FtZQ==, , keyId=3`
	expected := []Token{
		{TokenToken, "Bearer"},
		{TokenToken68, "S0VLU0UhIExFQ0tFUiEK"},
		{TokenToken, "Signature"},
		{TokenToken68, "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="},
		{TokenAuthParam, "keyId=3"},
	}
	idx := 0
	for got := range Tokenize(header) {
		if idx >= len(expected) {
			t.Fatalf("Failed. got extra token=%#v", got)
		}
		if !reflect.DeepEqual(got, expected[idx]) {
			t.Fatalf("Failed. got=%#v expected=%#v", got, expected[idx])
		}
		idx += 1
	}

	if len(expected) != idx {
		t.Fatalf("Failed. Token count mismatch. Last token=%#v", expected[idx])
	}
}

func TestQuickNo1SpaceCommaSpace(t *testing.T) {
	header := `Newauth realm="apps" ,`
	expected := []Token{
		{TokenToken, "Newauth"},
		{TokenAuthParam, `realm="apps"`},
	}
	idx := 0
	for got := range Tokenize(header) {
		if idx >= len(expected) {
			t.Fatalf("Failed. got extra token=%#v", got)
		}
		if !reflect.DeepEqual(got, expected[idx]) {
			t.Fatalf("Failed. got=%#v expected=%#v", got, expected[idx])
		}
		idx += 1
	}
	if len(expected) != idx {
		t.Fatalf("Failed. Token count mismatch. Last token=%#v", expected[idx])
	}
}

func TestOnlyScheme(t *testing.T) {
	header := `Basic`
	expected := []Token{
		{TokenToken, "Basic"},
	}
	idx := 0
	for got := range Tokenize(header) {
		if idx >= len(expected) {
			t.Fatalf("Failed. got extra token=%#v", got)
		}
		if !reflect.DeepEqual(got, expected[idx]) {
			t.Fatalf("Failed. got=%#v expected=%#v", got, expected[idx])
		}
		idx += 1
	}
	if len(expected) != idx {
		t.Fatalf("Failed. Token count mismatch. Last token=%#v", expected[idx])
	}
}

func TestOnlyAuthBasic(t *testing.T) {
	header := `Basic dG9rZW4=`
	expected := []Token{
		{TokenToken, "Basic"},
		{TokenToken68, "dG9rZW4="},
	}
	idx := 0
	for got := range Tokenize(header) {
		if idx >= len(expected) {
			t.Fatalf("Failed. got extra token=%#v", got)
		}
		if !reflect.DeepEqual(got, expected[idx]) {
			t.Fatalf("Failed. got=%#v expected=%#v", got, expected[idx])
		}
		idx += 1
	}
	if len(expected) != idx {
		t.Fatalf("Failed. Token count mismatch. Last token=%#v", expected[idx])
	}
}

func TestBorkedQuoting(t *testing.T) {
	header := `Basic realm="abc""`
	expected := []Token{
		{TokenToken, "Basic"},
		{NOTOKEN, "realm=\"abc\"\""},
	}
	idx := 0
	for got := range Tokenize(header) {
		if idx >= len(expected) {
			t.Fatalf("Failed. got extra token=%#v", got)
		}
		if !reflect.DeepEqual(got, expected[idx]) {
			t.Fatalf("Failed. got=%#v expected=%#v", got, expected[idx])
		}
		idx += 1
	}
	if len(expected) != idx {
		t.Fatalf("Failed. Token count mismatch. Last token=%#v", expected[idx])
	}
}
