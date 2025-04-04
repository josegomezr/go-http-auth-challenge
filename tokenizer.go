package http_auth

import (
	"iter"
	"strings"
	"unicode"
)

type TokenizerState int

const (
	StateSTART TokenizerState = iota
	StateToken
	StateSP
	StateQuotedString
	StateQuotedStringEscaping
	StateToken68
	StateTokenKey
	StateTokenValue
)

type TokenType int

const (
	NOTOKEN TokenType = iota
	TokenToken
	TokenToken68
	TokenAuthParam
	TokenKey
	TokenValue
	TokenQuotedString
)

type TokenizerDTO struct {
	Type  TokenType
	Token string
}

// Reference Grammar
// Collected from [RFC7230] § 3.2.6 & [RFC7235] § 2.1
//
// OWS            = *( SP / HTAB )
//                  ; optional whitespace
// BWS            = OWS
//                  ; "bad" whitespace
// token          = 1*tchar
// tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
//                      / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
//                      / DIGIT / ALPHA
//                  ; any VCHAR, except delimiters
//
// quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE
// qdtext         = HTAB / SP /%x21 / %x23-5B / %x5D-7E / obs-text
// obs-text       = %x80-FF
//
// token68        = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
//                  ; pretty much: base64, base64url, base32, base 16 (hex)
//                    with or without padding
// auth-scheme    = token
// auth-param     = token BWS "=" BWS ( token / quoted-string )
// challenge      = auth-scheme [ 1*SP ( token68 / #auth-param ) ]

// close enough character clasification functions
func isTchar(c rune) bool {
	punctuation := "!#$%&'*+-.^_`|~/="
	return unicode.IsLetter(c) || unicode.IsNumber(c) || strings.ContainsRune(punctuation, c)
}

func isToken68Char(c rune) bool {
	punctuation := "-._~+/"
	return unicode.IsLetter(c) || unicode.IsNumber(c) || strings.ContainsRune(punctuation, c)
}

func isWS(c rune) bool {
	return c == '\t' || c == ' '
}

// This here is using very modern go, if it's really needed I could try
// backporting it to more "available" go.

// TODO: Give it a try refactoring this as a formal state machine with cool
// patternz like the ones in refactoring.guru
func tokenizeHeader(header string) iter.Seq[TokenizerDTO] {
	return func(yield func(TokenizerDTO) bool) {
		acc := ""
		state := StateToken
		previouslyEmitted := NOTOKEN

		for _, c := range header {
			if state == StateSP {
				if isTchar(c) {
					state = StateToken
					acc = ""
				} else if isWS(c) {
					acc = ""
					continue
				} else if c == ',' {
					acc = ""
					continue
				}
			}

			if state == StateQuotedString {
				if c == '\\' {
					state = StateQuotedStringEscaping
				}
				if c == '"' {
					// quoted strings are _guaranteed_ to be authparams
					acc += string(c)
					yield(TokenizerDTO{TokenAuthParam, acc})
					previouslyEmitted = TokenAuthParam
					state = StateSP
					acc = ""
					continue
				}
			}

			if state == StateQuotedStringEscaping && c == '"' {
				state = StateQuotedString
			}

			if state == StateToken68 {
				if !isToken68Char(c) {
					state = StateToken
				} else if c == '"' {
					state = StateQuotedString
				}
			}

			if state == StateToken {
				if c == '"' {
					state = StateQuotedString
				} else if !isTchar(c) {
					t := extractPotentialTokenPair(previouslyEmitted, acc)
					yield(t)
					previouslyEmitted = t.Type

					state = StateSP
					acc = ""
					continue
				}
			}
			acc += string(c)
		}

		if acc != "" {
			yield(extractPotentialTokenPair(previouslyEmitted, acc))
		}
	}
}

// This kinda worked, the intention behind it is (pardon my mental dance)
//
// We presume that we're dealing with a token, as it has the most general
// grammar.
//
// If the current token is not an auth-param (meaning it doesn't have an
// equal sign on it, or if it does, it's at the very end [base64 for
// example])
//
// We need emit token TokenToken68 to differentiate in the parser between the
// actual Auth Scheme and and Auth Param
//
// To accomodate for it we check the previously emitted token, if it's a
// TokenToken, then we've emitted the Auth Scheme, and we can proceed with
// TokenToken68.

// This will prolly make more sense if I emit spaces & commas, the parser
// does not make me any favor by making:
//
// Authorization: Basic realm="abc" ,
//
// As a valid header expression, even though it can be interpreted as:
//
// Challenges:
// - Scheme: Basic
//   Auth Params:
//   - realm="abc"
//   -
//
// or:
//
// Challenges:
// - Scheme: Basic
//   Auth Params:
//   - realm="abc"
// - ~
//
// I'll take artistic liberties until anyone complains.

func extractPotentialTokenPair(previouslyEmitted TokenType, acc string) TokenizerDTO {
	hasEqual := strings.Contains(acc, "=")
	endsEqual := strings.HasSuffix(acc, "=")

	tokenType := TokenToken

	if hasEqual && endsEqual {
		tokenType = TokenToken68
	} else if hasEqual {
		tokenType = TokenAuthParam
	}

	if previouslyEmitted == TokenToken {
		tokenType = TokenToken68
	}
	return TokenizerDTO{tokenType, acc}
}
