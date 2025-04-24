HTTP Auth* Headers Parser [![Go Reference](https://pkg.go.dev/badge/github.com/josegomezr/go-http-auth-challenge.svg)](https://pkg.go.dev/github.com/josegomezr/go-http-auth-challenge)
===

A compliant-enough implementation to parse HTTP `WWW-Authenticate` &
`Authorization` headers with 0 dependencies

This implementation tries to be compliant-enough (to the extent of my skills)
with the grammars defined in [RFC 7230 § 3.2.6](https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6) & [RFC 7235 § 2.1](https://datatracker.ietf.org/doc/html/rfc7235#section-2.1) with regards
to processing the values of the HTTP Authorization headers.

Usage
---

### When consuming challenge headers (`www-authenticate`, `proxy-authenticate`)

```go
package main

import (
	"fmt"
	http_auth "github.com/josegomezr/go-http-auth-challenge"
)

func main() {
	// what a server would respond
	wwwAuthenticateHeader := `Bearer realm="https://auth.docker.io/token",service="registry.docker.io"`

	// Get the list of defined challenges
	challenges, err := http_auth.ParseChallenges(wwwAuthenticateHeader, true)
	if err != nil {
		panic(fmt.Sprintf("Error parsing challenges: %s", err))
	}

	// To accomodate for multiple challenges on a single header, the return type
	// is a slice of challenges, most of the world only uses one at a time, it up
	// for consumers to take this decision and use the first challenge if they
	// see it fit.
	for _, challenge := range challenges {
		switch challenge.Scheme {
		case "Basic":
			fmt.Println("Scheme: Basic")
			/* do some stuff with auth basic */
			// ...
			realm, found := challenge.Realm()
			if found {
				fmt.Println("- realm:", realm)
			}
		case "Bearer":
			fmt.Println("Scheme: Bearer")
			/* do some stuff with auth basic */
			// ...

			realm, found := challenge.Realm()
			if found {
				fmt.Println("- realm:", realm)
			}
			service, found := challenge.GetParam("service")
			if found {
				fmt.Println("- service:", service)
			}
			fmt.Printf("- all-params: %v\n", challenge.Params)
		default:
			panic(fmt.Sprintf("Unknown challenge scheme: %s", challenge.Scheme))
		}
	}
}
```

### When consuming authorization headers (`authentication`, `proxy-authorization`)

```go
package main

import (
	"fmt"
	http_auth "github.com/josegomezr/go-http-auth-challenge"
)

func main() {
	// what a server would respond
	authorizationHeader := `Bearer dG9rZW4=,keyId=abc,username=foo`

	// Get the list of defined challenges
	challenge, err := http_auth.ParseAuthorization(authorizationHeader, true)
	if err != nil {
		panic(fmt.Sprintf("Error parsing authorization header: %s", err))
	}

	fmt.Println("Scheme: ", challenge.Scheme)
	// The convention here is that tokens (not auth-params) are saved in order
	// as string indexes. If it's too cumbersome, i'll refactor it.
	value0, found := challenge.GetParam("0")
	if found {
		fmt.Println("- value0:", value0)
	}
	fmt.Printf("- all-params: %v\n", challenge.Params)
}
```

Take a look at the `example_*.go` files for more usage tips.
