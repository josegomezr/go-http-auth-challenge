package main

import (
	"bufio"
	"fmt"
	"unicode"
	"unicode/utf8"
	"strings"
	"iter"
)

func ScanWords(data []byte, atEOF bool) (advance int, token []byte, err error) {
	// Skip leading spaces.
	start := 0
	for width := 0; start < len(data); start += width {
		var r rune
		r, width = utf8.DecodeRune(data[start:])
		if !unicode.IsSpace(r) /*&& r != ','*/ {
			break
		}
	}
	// Scan until space, marking end of word.
	quoting := false
	escaping := false
	for width, i := 0, start; i < len(data); i += width {
		var r rune
		r, width = utf8.DecodeRune(data[i:])

		if quoting && escaping {
			escaping = false
			continue
		}

		if r == '"' {
			quoting = !quoting
		}

		if quoting {
			if r == '\\' {
				escaping = true
			}

			continue
		}

		if unicode.IsSpace(r) {
			return i + width, data[start:i], nil
		}

		if r == ',' {
			if i == 0 {
				return i + width, data[start:i+width], nil
			}
			return i, data[start:i], nil
		}
	}
	// If we're at EOF, we have a final, non-empty, non-terminated word. Return it.
	if atEOF && len(data) > start {
		return len(data), data[start:], nil
	}
	// Request more data.
	return start, nil, nil
}

func tokenize(input string) iter.Seq[string] {
	scan := bufio.NewScanner(strings.NewReader(input))
	scan.Split(ScanWords)

	return func(yield func(string) bool) {
		for scan.Scan() {
			if !yield(scan.Text()){
				break
			}
		}
	}
}


func chunkByComma(seq iter.Seq[string]) iter.Seq[[]string] {
	acc := []string{}

	return func(yield func([]string) bool) {
		next, stop := iter.Pull(seq)
		defer stop()
		for {
			val, ok := next();
			if !ok {
				break;
			}
			acc = append(acc, val)
			if val == "," {
				if !yield(acc) {
					return
				}
				acc = []string{}
				continue
			}

		}
		if len(acc) > 0 {
			yield(acc)
		}
	}
}

func processChunk(chunk...string) (scheme string, value string, err error) {
	switch len(chunk) {
	case 1:
		tok := chunk[0]
		if strings.ContainsRune(tok, '=') {
			value = tok
		}else{
			scheme = tok
		}
	case 2:
		scheme, value = chunk[0], chunk[1]
		if len(scheme) == 0 || len(value) == 0 {
			err = fmt.Errorf("empty scheme/value")
		}else if value == "," {
			value = scheme
			scheme = ""
		}
	case 3:
		scheme, value = chunk[0], chunk[1]
		if len(scheme) == 0 || len(value) == 0 {
			err = fmt.Errorf("empty scheme/value")
		}
	default:
		err = fmt.Errorf("Redundant syntax: %s", chunk)
	}
	return
}

type Challenge struct {
	Scheme string
	Params []string
}


func parseChallenges(input string) iter.Seq2[Challenge, error] {
	return func(yield func(Challenge, error) bool) {
		curr := Challenge{}
		for chunk := range chunkByComma(tokenize(input)) {
			scheme, value, err := processChunk(chunk...)
			if err != nil {
				yield(curr, fmt.Errorf("Error processing header: %+w", err))
				return
			}

			if len(scheme) > 0 {
				if curr.Scheme != "" {
					if(!yield(curr, nil)){
						return
					}
					curr = Challenge{}
				}
				curr.Scheme = scheme
			}

			if len(value) > 0 {
				if curr.Scheme == "" {
					yield(curr, fmt.Errorf("Unexpected param before scheme"))
					return
				}
				
				curr.Params = append(curr.Params, value)
			}
		}
		if curr.Scheme != "" {
			yield(curr, nil)
		}
	}

}

func ParseChallenges(input string) ([]Challenge, error) {
	var res []Challenge
	for challenge, err := range parseChallenges(input) {
		if err != nil {
			return nil, err
		}
		res = append(res, challenge)
	}

	if len(res) <= 0 {
		return nil, fmt.Errorf("Empty challenges")
	}
	return res, nil
}

func ParseAuthorization(input string) (Challenge, error) {
	next, stop := iter.Pull2(parseChallenges(input))
	defer stop()
	challenge, err, ok := next()
	if !ok {
		return challenge, fmt.Errorf("No auth header found")
	}
	if err != nil {
		return challenge, err
	}

	_, err, ok = next()
	if ok {
		return challenge, fmt.Errorf("multiple auth scheme found in a single header")
	}

	return challenge, nil
}

func main() {
	// An artificial input source.
	inputs := []string{
		// ``,
		// `realm="apps", type="1", another=abc, zzz=1111, title="Login to \"apps\"", Basic realm="simple"`,
		// `Newauth   realm="apps", type="1", another=abc, zzz=1111, title="Login to \"apps\"", Basic realm="simple"`,
		// `Newauth        realm="apps", type=1, title="Login to \"apps\""`,
		// `Bearer S0VLU0UhIExFQ0tFUiEK AAAAAa, Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ== `,
		`Bearer S0VLU0UhIExFQ0tFUiEK=1, AAA`,
		`Bearer AAA, B=1`,
		// `Bearer   S0VLU0UhIExFQ0tFUiEK, Signature QWxhZGRpbjpvcGVuIHNlc2FtZQ==, , keyId=3`,
		// `Newauth realm="apps" ,`,
		// `Basic`,
		// `Basic dG9rZW4=`,
		// `Basic realm="abc""`,
		// `Bearer         S0VLU0UhIExFQ0tFUiEK, Signature QWxhZGRpbjpvcGVuIHNlc2FtZQ==, , keyId=3, Sandwich toasted=yes, mayo="please say \" nope \""`,
		// `Signature   realm="lorem ipsum dolor"`,
		// `Basic   realm="lorem ipsum dolor"`,
		// `Basic   YWI6Y2QK`,
		// `SSWS   YWI6Y2QK`,
		// `YWI6Y2QK   SSWS`,
		// // from: https://github.com/aws/aws-sdk-go/blob/v1.55.6/aws/signer/v4/v4_test.go#L202
		// `AWS4-HMAC-SHA256 Credential=AKID/19700101/us-east-1/dynamodb/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-meta-other-header;x-amz-meta-other-header_with_underscore;x-amz-security-token;x-amz-target, Signature=a518299330494908a70222cec6899f6f32f297f8595f6df1776d998936652ad9`,
	}
	for _, input := range inputs {
		fmt.Printf("INPUT: %q\n", input)
		res, err := ParseChallenges(input)

		if err != nil {
			fmt.Println("chall-error: ", err)
		}else{
			fmt.Printf("%+v\n", res)
		}
		res2, err := ParseAuthorization(input)
		if err != nil {
			fmt.Println("auth-error: ", err)
		}else{
			fmt.Printf("%+v\n", res2)
		}
		fmt.Println()
	}
}
