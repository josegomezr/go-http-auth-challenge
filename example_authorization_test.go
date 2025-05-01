package http_auth_test

import (
	"fmt"
	http_auth "github.com/josegomezr/go-http-auth-challenge"
	"log"
)

// Inspect the bearer token sent by client.
func ExampleParseAuthorization_simple() {
	authorizationHeader := `Bearer ObscureTokenHere=`
	authorization, err := http_auth.ParseAuthorization(authorizationHeader)
	if err != nil {
		log.Fatalf("Error parsing challenge: %s", err)
	}

	fmt.Println("Scheme:", authorization.Scheme)
	token, found := authorization.GetTokenParam()
	fmt.Printf("- token (found=%v): %s\n", found, token)
}

// Inspect the authorization header sent by client.
func ExampleParseAuthorization_newstyle() {
	authorizationHeader := `Bearer userId=alpha,token="ObscureTokenHere="`
	authorization, err := http_auth.ParseAuthorization(authorizationHeader)
	if err != nil {
		log.Fatalf("Error parsing challenge: %s", err)
	}

	fmt.Println("Scheme:", authorization.Scheme)
	userId, foundUserId := authorization.GetParam("userId")
	token, foundToken := authorization.GetParam("token")
	fmt.Printf("- userId (found=%v): %s\n", foundUserId, userId)
	fmt.Printf("- token  (found=%v): %s\n", foundToken, token)
}
