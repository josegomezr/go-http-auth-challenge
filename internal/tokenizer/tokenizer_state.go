package tokenizer

import "fmt"

type TokenizerState int

const (
	NOSTATE                   TokenizerState = iota
	StateToken                               // Parsing a Token
	StateSP                                  // Parsing a Space
	StateComma                               // Parsing a Comma
	StateQuotedString                        // Parsing a Quoted String
	StateQuotedStringEscaping                // Parsing an escaped character in a quoted string
	StateToken68                             // Parsing a Token68 [a letter of the base{64,32,16} alphabet]
)

type TokenType int

const (
	NOTOKEN        TokenType = iota
	TokenToken               // A token like the Challenge Scheme name
	TokenWS                  // A token like the Challenge Scheme name
	TokenComma               // A token like the Challenge Scheme name
	TokenToken68             // A Token68 [base{64,32,16} string]
	TokenAuthParam           // A key=value token
)

func (t TokenType) String() string {
	switch t {
	case NOTOKEN:
		return "NOTOKEN"
	case TokenToken:
		return "TokenToken"
	case TokenWS:
		return "TokenWS"
	case TokenComma:
		return "TokenComma"
	case TokenToken68:
		return "TokenToken68"
	case TokenAuthParam:
		return "TokenAuthParam"
	default:
		return fmt.Sprintf("%d", int(t))
	}
}
