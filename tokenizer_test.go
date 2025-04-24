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

func TestFuzz1(t *testing.T) {
	authorizationHeaders := []string{
		`6C0I1WQ3B824XyAS             HfR5tVt1t 	 		 =	 		    "¨\	 \ª"	 		 	  ,	  	 			 05n44F320YsS				 	  		 =V6o17hX					  			 	 ,			8H344nv		 = 			  	  	  	 1	 	        		  	,	   0N0dRfEcSV		 			      	=		   	 	    		 58Wnj3G4l  		  ,Jh 	   	 		=	  	   		 	 	  					y257g236BYx5q 		, 	 Eqb077				=   	    				  	 	 	"w%\	\ \¼{	\	!ñc\k*\w\Ë	\	!"	 	   	    	 , 			 	 	  	 	4u07W64T919948J3Tp		=  						"\	µ\b\	o\0\ \A\n"	 	   				,    	 		  			u5R62D0801Oj0D40  	 	 =			 		 	   	"\	\Û \F\	Ó\  R"     	 	   		 		  ,  			  		 		 	   	58M128aO92Yl7tZL 	  = 		     				 9			 	  , 	18cW14fd6s74U1ZIu41  				 	  	  	=  	 			  	  	  00qRvIMu7	 	        	  	,		 		 				8CF3ap3ouJ4g7Zxx94 				  		 	   =		926704cPg7iw4lNnat3 	 	 	  			 , 	    	 o88K5022p1f5c 	 =	   	 	 	    				 		eQKgZ8H8m 		  	, 	 		 	 	   	y1ti13s280H2	    			 	 	 		 		=	 	zo18O4d	   	 			    	 	,		U3l283rf8Tn7n3F0A3	=689QL7OH3D90iYoQ9`,
		`Sm5V24tZc6esj                   2		  =		 	 			  	   	 	775264gcdLw43  	 	 			 ,  		   		 				     	972Ha1OLqE72jTH 		  		 	  ="\	\ \X\Ö\-\ \ô!NR!\ó"				, 				218m69			   		 					  	=  060PhJE2l94u  	 		 	 ,	  Au = "\$ \          \	\	3 \ý_\	" 	   		 	 	  		 	, 		   J7y2z9Ob0     	 	 	   	= 	   			 		n6Ivi ,  	3R1uJ= "!\	\ <\	 	 0!\; "	 			,	   	d8onBhKj02ZU37  	 		 		     		  =     			 					 "	C\ F\·Z\Ä\\ " ,	 		 	4aO19p58557ahbEh 			    		 	= 					 	 	 "!!\x\ "	  , 	 			 		  p93sG0m81Kv     	    	 	=		     			Cd1X81p099U5`,
	}

	expectations := [][]string{
		[]string{
			"6C0I1WQ3B824XyAS",
			"HfR5tVt1t=\"¨\\\t \\ª\"",
			",",
			"05n44F320YsS=V6o17hX",
			",",
			"8H344nv=1",
			",",
			"0N0dRfEcSV=58Wnj3G4l",
			",",
			"Jh=y257g236BYx5q",
			",",
			"Eqb077=\"w%\\\t\\ \\¼{\t\\\t!ñc\\k*\\w\\Ë\t\\\t!\"",
			",",
			"4u07W64T919948J3Tp=\"\\\tµ\\b\\\to\\0\\ \\A\\n\"",
			",",
			"u5R62D0801Oj0D40=\"\\\t\\Û \\F\\\tÓ\\  R\"",
			",",
			"58M128aO92Yl7tZL=9",
			",",
			"18cW14fd6s74U1ZIu41=00qRvIMu7",
			",",
			"8CF3ap3ouJ4g7Zxx94=926704cPg7iw4lNnat3",
			",",
			"o88K5022p1f5c=eQKgZ8H8m",
			",",
			"y1ti13s280H2=zo18O4d",
			",",
			"U3l283rf8Tn7n3F0A3=689QL7OH3D90iYoQ9",
		},

		[]string{
			"Sm5V24tZc6esj",
			"2=775264gcdLw43",
			",",
			"972Ha1OLqE72jTH=\"\\\t\\ \\X\\Ö\\-\\ \\ô!NR!\\ó\"",
			",",
			"218m69=060PhJE2l94u",
			",",
			"Au=\"\\$ \\          \\\t\\\t3 \\ý_\\\t\"",
			",",
			"J7y2z9Ob0=n6Ivi",
			",",
			"3R1uJ=\"!\\\t\\ <\\\t \t 0!\\; \"",
			",",
			"d8onBhKj02ZU37=\"\tC\\ F\\·Z\\Ä\\\\ \"",
			",",
			"4aO19p58557ahbEh=\"!!\\x\\ \"",
			",",
			"p93sG0m81Kv=Cd1X81p099U5",
		},
	}

	for k, authorizationHeader := range authorizationHeaders {
		got := slices.Collect(tokenize(authorizationHeader))
		expected := expectations[k]
		if !reflect.DeepEqual(expected, got) {
			t.Fatalf("Returned authorizations does not match numbers of expected challenges. expected=%#v got=%#v", expected, got)
		}
	}
}
