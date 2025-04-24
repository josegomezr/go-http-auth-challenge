package http_auth_test

import (
	"fmt"
	http_auth "github.com/josegomezr/go-http-auth-challenge"
	"log"
)

// Inspect the challenges sent by a server.
func ExampleParseChallenges_inspectChallenges() {
	wwwAuthenticateHeader := `Basic realm="Your pet's name", Bearer service="postal", Fax number=1234`
	challenges, err := http_auth.ParseChallenges(wwwAuthenticateHeader)
	if err != nil {
		log.Fatalf("Error parsing challenge: %s", err)
	}

	for _, challenge := range challenges {
		switch challenge.Scheme {
		case "Basic":
			fmt.Println("Scheme: Basic")
			realm, found := challenge.Realm()
			if found {
				fmt.Println("- realm:", realm)
			}
		case "Bearer":
			fmt.Println("Scheme: Bearer")
			service, found := challenge.Params["service"]
			if found {
				fmt.Println("- service:", service)
			}
			fmt.Printf("- all-params: %v\n", challenge.Params)
		default:
			fmt.Printf("Unknown challenge scheme: %s - %v\n", challenge.Scheme, challenge.Params)
		}
	}
}
