package http_auth_test

import (
	http_auth "github.com/josegomezr/go-http-auth-challenge"
	"reflect"
	"testing"
)

func TestRealWorldBearerAuthorization(t *testing.T) {
	authorizationHeader := `Bearer dG9rZW4=`

	expectedHeaders := http_auth.Authorization{
		Scheme: "Bearer",
		Params: http_auth.Params{
			http_auth.TokenParameterName: "dG9rZW4=",
		},
	}

	results, err := http_auth.ParseAuthorization(authorizationHeader)
	if err != nil {
		t.Fatalf("Error parsing challenge: %s", err)
	}

	if !reflect.DeepEqual(expectedHeaders, results) {
		t.Fatalf("Returned authorizations does not match numbers of expected challenges. expected=%q got=%q", expectedHeaders, results)
	}
}

func TestRealWorldBasicAuthorization(t *testing.T) {
	authorizationHeader := `Basic dG9rZW4=`

	expectedHeaders := http_auth.Authorization{
		Scheme: "Basic",
		Params: http_auth.Params{
			http_auth.TokenParameterName: "dG9rZW4=",
		},
	}

	results, err := http_auth.ParseAuthorization(authorizationHeader)
	if err != nil {
		t.Fatalf("Error parsing challenge: %s", err)
	}

	if !reflect.DeepEqual(expectedHeaders, results) {
		t.Fatalf("Returned authorizations does not match numbers of expected challenges. expected=%q got=%q", expectedHeaders, results)
	}
}

func TestRealWorldOBSSignatureAUth(t *testing.T) {
	authorizationHeader := `Signature keyId="dummy-username",algorithm="ssh",signature="U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgSKpcECPm8Vjo9UznZS+M/QLjmXXmLzoBxkIbZ8Z/oPkAAAAaVXNlIHlvdXIgZGV2ZWxvcGVyIGFjY291bnQAAAAAAAAABnNoYTUxMgAAAFMAAAALc3NoLWVkMjU1MTkAAABA8cmvTy1PgpW2XhHWxQ1yw/wPGAfT2M3CGRJ3II7uT5Orqn1a0bWlo/lEV0WiqP+pPcQdajQ4a2YGJvpfzT1uBA==",headers="(created)",created="1664187470"`
	expectedHeaders := http_auth.Authorization{
		Scheme: "Signature",
		Params: http_auth.Params{
			"keyId":     "dummy-username",
			"algorithm": "ssh",
			"signature": "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgSKpcECPm8Vjo9UznZS+M/QLjmXXmLzoBxkIbZ8Z/oPkAAAAaVXNlIHlvdXIgZGV2ZWxvcGVyIGFjY291bnQAAAAAAAAABnNoYTUxMgAAAFMAAAALc3NoLWVkMjU1MTkAAABA8cmvTy1PgpW2XhHWxQ1yw/wPGAfT2M3CGRJ3II7uT5Orqn1a0bWlo/lEV0WiqP+pPcQdajQ4a2YGJvpfzT1uBA==",
			"headers":   "(created)",
			"created":   "1664187470",
		},
	}

	results, err := http_auth.ParseAuthorization(authorizationHeader)
	if err != nil {
		t.Fatalf("Error parsing challenge: %s", err)
	}

	if !reflect.DeepEqual(expectedHeaders, results) {
		t.Fatalf("Returned authorizations does not match numbers of expected challenges. expected=%q got=%q", expectedHeaders, results)
	}
}

// from: https://github.com/aws/aws-sdk-go/blob/v1.55.6/aws/signer/v4/v4_test.go#L202
// Funnily enough, this accidentally passes even though it shouldn't. AWS Is
// breaking the grammar by not quoting the `SignedHeaders` parameters and using
// a delimiter forbidden delimiter char as part of the token value

// tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
//
//	/ "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
//	/ DIGIT / ALPHA
//	; any VCHAR, except delimiters
func TestRealWorldAWSAuth(t *testing.T) {
	authorizationHeader := `AWS4-HMAC-SHA256 Credential=AKID/19700101/us-east-1/dynamodb/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-meta-other-header;x-amz-meta-other-header_with_underscore;x-amz-security-token;x-amz-target, Signature=a518299330494908a70222cec6899f6f32f297f8595f6df1776d998936652ad9`

	expectedHeaders := http_auth.Authorization{
		Scheme: "AWS4-HMAC-SHA256",
		Params: http_auth.Params{
			"Credential":    "AKID/19700101/us-east-1/dynamodb/aws4_request",
			"SignedHeaders": "content-length;content-type;host;x-amz-date;x-amz-meta-other-header;x-amz-meta-other-header_with_underscore;x-amz-security-token;x-amz-target",
			"Signature":     "a518299330494908a70222cec6899f6f32f297f8595f6df1776d998936652ad9",
		},
	}

	results, err := http_auth.ParseAuthorization(authorizationHeader)
	if err != nil {
		t.Fatalf("Error parsing challenge: %s", err)
	}

	if !reflect.DeepEqual(expectedHeaders, results) {
		t.Fatalf("Returned authorizations does not match numbers of expected challenges. expected=%q got=%q", expectedHeaders, results)
	}
}

// func aTestFuzz(t *testing.T) {
// 	authorizationHeader := `6C0I1WQ3B824XyAS             HfR5tVt1t 	 		 =	 		    "¨\	 \ª"	 		 	  ,	  	 			 05n44F320YsS				 	  		 =V6o17hX					  			 	 ,			8H344nv		 = 			  	  	  	 1	 	        		  	,	   0N0dRfEcSV		 			      	=		   	 	    		 58Wnj3G4l  		  ,Jh 	   	 		=	  	   		 	 	  					y257g236BYx5q 		, 	 Eqb077				=   	    				  	 	 	"w%\	\ \¼{	\	!ñc\k*\w\Ë	\	!"	 	   	    	 , 			 	 	  	 	4u07W64T919948J3Tp		=  						"\	µ\b\	o\0\ \A\n"	 	   				,    	 		  			u5R62D0801Oj0D40  	 	 =			 		 	   	"\	\Û \F\	Ó\  R"     	 	   		 		  ,  			  		 		 	   	58M128aO92Yl7tZL 	  = 		     				 9			 	  , 	18cW14fd6s74U1ZIu41  				 	  	  	=  	 			  	  	  00qRvIMu7	 	        	  	,		 		 				8CF3ap3ouJ4g7Zxx94 				  		 	   =		926704cPg7iw4lNnat3 	 	 	  			 , 	    	 o88K5022p1f5c 	 =	   	 	 	    				 		eQKgZ8H8m 		  	, 	 		 	 	   	y1ti13s280H2	    			 	 	 		 		=	 	zo18O4d	   	 			    	 	,		U3l283rf8Tn7n3F0A3	=689QL7OH3D90iYoQ9`

// 	fmt.Printf("%+v", tokenize(authorizationHeader))

// 	_, err := http_auth.ParseAuthorization(authorizationHeader)
// 	if err != nil {
// 		t.Fatalf("Error parsing challenge: %s", err)
// 	}
// }
