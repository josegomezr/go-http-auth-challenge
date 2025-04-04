package http_auth

import (
	"reflect"
	"testing"
)

func TestSingleChallenge(t *testing.T) {
	header := `Newauth realm="apps", type=1, title="Login to \"apps\""`
	expected := []TokenizerDTO{
		{TokenToken, "Newauth"},
		{TokenAuthParam, `realm="apps"`},
		{TokenAuthParam, `type=1`},
		{TokenAuthParam, `title="Login to \"apps\""`},
	}
	idx := 0
	for got := range tokenizeHeader(header) {
		if idx >= len(expected) {
			t.Fatalf("Failed. got extra token=%q", got)
		}
		if !reflect.DeepEqual(got, expected[idx]) {
			t.Fatalf("Failed. got=%q expected=%q", got, expected[idx])
		}
		idx += 1
	}
	if len(expected) != idx {
		t.Fatalf("Failed. Token count mismatch. Last token=%q", expected[idx])
	}
}

func TestDoubleChallenge(t *testing.T) {
	header := `Newauth realm="apps", type=1, title="Login to \"apps\"", Basic realm="simple"`
	expected := []TokenizerDTO{
		{TokenToken, "Newauth"},
		{TokenAuthParam, `realm="apps"`},
		{TokenAuthParam, `type=1`},
		{TokenAuthParam, `title="Login to \"apps\""`},
		{TokenToken, "Basic"},
		{TokenAuthParam, `realm="simple"`},
	}
	idx := 0
	for got := range tokenizeHeader(header) {
		if idx >= len(expected) {
			t.Fatalf("Failed. got extra token=%q", got)
		}
		if !reflect.DeepEqual(got, expected[idx]) {
			t.Fatalf("Failed. got=%q expected=%q", got, expected[idx])
		}
		idx += 1
	}
	if len(expected) != idx {
		t.Fatalf("Failed. Token count mismatch")
	}
}

func TestAuthorizationWithoutAuthParams(t *testing.T) {
	header := `Bearer S0VLU0UhIExFQ0tFUiEK, Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ== `
	expected := []TokenizerDTO{
		{TokenToken, "Bearer"},
		{TokenToken68, "S0VLU0UhIExFQ0tFUiEK"},
		{TokenToken, "Basic"},
		{TokenToken68, "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="},
	}
	idx := 0
	for got := range tokenizeHeader(header) {
		if idx >= len(expected) {
			t.Fatalf("Failed. got extra token=%q", got)
		}
		if !reflect.DeepEqual(got, expected[idx]) {
			t.Fatalf("Failed. got=%q expected=%q", got, expected[idx])
		}
		idx += 1
	}
	if len(expected) != idx {
		t.Fatalf("Failed. Token count mismatch")
	}
}
func TestAuthorizationMixedWithParams(t *testing.T) {
	header := `Bearer S0VLU0UhIExFQ0tFUiEK, Signature QWxhZGRpbjpvcGVuIHNlc2FtZQ==, keyId=3`
	expected := []TokenizerDTO{
		{TokenToken, "Bearer"},
		{TokenToken68, "S0VLU0UhIExFQ0tFUiEK"},
		{TokenToken, "Signature"},
		{TokenToken68, "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="},
		{TokenAuthParam, "keyId=3"},
	}
	idx := 0
	for got := range tokenizeHeader(header) {
		if idx >= len(expected) {
			t.Fatalf("Failed. got extra token=%q", got)
		}
		if !reflect.DeepEqual(got, expected[idx]) {
			t.Fatalf("Failed. got=%q expected=%q", got, expected[idx])
		}
		idx += 1
	}

	if len(expected) != idx {
		t.Fatalf("Failed. Token count mismatch. Last token=%q", expected[idx])
	}
}

func TestQuickNo1SpaceCommaSpace(t *testing.T) {
	header := `Newauth realm="apps" ,`
	expected := []TokenizerDTO{
		{TokenToken, "Newauth"},
		{TokenAuthParam, `realm="apps"`},
	}
	idx := 0
	for got := range tokenizeHeader(header) {
		if idx >= len(expected) {
			t.Fatalf("Failed. got extra token=%q", got)
		}
		if !reflect.DeepEqual(got, expected[idx]) {
			t.Fatalf("Failed. got=%q expected=%q", got, expected[idx])
		}
		idx += 1
	}
	if len(expected) != idx {
		t.Fatalf("Failed. Token count mismatch. Last token=%q", expected[idx])
	}
}

func TestOnlyScheme(t *testing.T) {
	header := `Basic`
	expected := []TokenizerDTO{
		{TokenToken, "Basic"},
	}
	idx := 0
	for got := range tokenizeHeader(header) {
		if idx >= len(expected) {
			t.Fatalf("Failed. got extra token=%q", got)
		}
		if !reflect.DeepEqual(got, expected[idx]) {
			t.Fatalf("Failed. got=%q expected=%q", got, expected[idx])
		}
		idx += 1
	}
	if len(expected) != idx {
		t.Fatalf("Failed. Token count mismatch. Last token=%q", expected[idx])
	}
}

func TestOnlyAuthBasic(t *testing.T) {
	header := `Basic dG9rZW4=`
	expected := []TokenizerDTO{
		{TokenToken, "Basic"},
		{TokenToken68, "dG9rZW4="},
	}
	idx := 0
	for got := range tokenizeHeader(header) {
		if idx >= len(expected) {
			t.Fatalf("Failed. got extra token=%q", got)
		}
		if !reflect.DeepEqual(got, expected[idx]) {
			t.Fatalf("Failed. got=%q expected=%q", got, expected[idx])
		}
		idx += 1
	}
	if len(expected) != idx {
		t.Fatalf("Failed. Token count mismatch. Last token=%q", expected[idx])
	}
}

func TestRealWorldAmazon(t *testing.T) {
	header := "AWS4-HMAC-SHA256 Credential=AKID/19700101/us-east-1/dynamodb/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-meta-other-header;x-amz-meta-other-header_with_underscore;x-amz-security-token;x-amz-target, Signature=a518299330494908a70222cec6899f6f32f297f8595f6df1776d998936652ad9"
	expected := []TokenizerDTO{
		{TokenToken, "AWS4-HMAC-SHA256"},
		{TokenAuthParam, "Credential=AKID/19700101/us-east-1/dynamodb/aws4_request"},
		{TokenAuthParam, "SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-meta-other-header;x-amz-meta-other-header_with_underscore;x-amz-security-token;x-amz-target"},
		{TokenAuthParam, "Signature=a518299330494908a70222cec6899f6f32f297f8595f6df1776d998936652ad9"},
	}

	idx := 0
	for got := range tokenizeHeader(header) {
		if idx >= len(expected) {
			t.Fatalf("Failed. got extra token=%q", got)
		}
		if !reflect.DeepEqual(got, expected[idx]) {
			t.Fatalf("Failed. got=%q expected=%q", got, expected[idx])
		}
		idx += 1
	}
	if len(expected) != idx {
		t.Fatalf("Failed. Token count mismatch. Last token=%q", expected[idx])
	}
}
