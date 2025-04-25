package http_auth

import (
	"reflect"
	"slices"
	"testing"
)

// samples generated with: https://github.com/rexim/bnfuzzer & RFC 9110 grammar
func TestFuzzerMindfuck(t *testing.T) {
	authorizationHeaders := []string{
		"6C0I1WQ3B824XyAS             HfR5tVt1t \t \t\t =\t \t\t    \"¨\\\t \\ª\"\t \t\t \t  ,\t  \t \t\t\t 05n44F320YsS\t\t\t\t \t  \t\t =V6o17hX\t\t\t\t\t  \t\t\t \t ,\t\t\t8H344nv\t\t = \t\t\t  \t  \t  \t 1\t \t        \t\t  \t,\t   0N0dRfEcSV\t\t \t\t\t      \t=\t\t   \t \t    \t\t 58Wnj3G4l  \t\t  ,Jh \t   \t \t\t=\t  \t   \t\t \t \t  \t\t\t\t\ty257g236BYx5q \t\t, \t Eqb077\t\t\t\t=   \t    \t\t\t\t  \t \t \t\"w%\\\t\\ \\¼{\t\\\t!ñc\\k*\\w\\Ë\t\\\t!\"\t \t   \t    \t , \t\t\t \t \t  \t \t4u07W64T919948J3Tp\t\t=  \t\t\t\t\t\t\"\\\tµ\\b\\\to\\0\\ \\A\\n\"\t \t   \t\t\t\t,    \t \t\t  \t\t\tu5R62D0801Oj0D40  \t \t =\t\t\t \t\t \t   \t\"\\\t\\Û \\F\\\tÓ\\  R\"     \t \t   \t\t \t\t  ,  \t\t\t  \t\t \t\t \t   \t58M128aO92Yl7tZL \t  = \t\t     \t\t\t\t 9\t\t\t \t  , \t18cW14fd6s74U1ZIu41  \t\t\t\t \t  \t  \t=  \t \t\t\t  \t  \t  00qRvIMu7\t \t        \t  \t,\t\t \t\t \t\t\t\t8CF3ap3ouJ4g7Zxx94 \t\t\t\t  \t\t \t   =\t\t926704cPg7iw4lNnat3 \t \t \t  \t\t\t , \t    \t o88K5022p1f5c \t =\t   \t \t \t    \t\t\t\t \t\teQKgZ8H8m \t\t  \t, \t \t\t \t \t   \ty1ti13s280H2\t    \t\t\t \t \t \t\t \t\t=\t \tzo18O4d\t   \t \t\t\t    \t \t,\t\tU3l283rf8Tn7n3F0A3\t=689QL7OH3D90iYoQ9",
		"Sm5V24tZc6esj                   2\t\t  =\t\t \t \t\t\t  \t   \t \t775264gcdLw43  \t \t \t\t\t ,  \t\t   \t\t \t\t\t\t     \t972Ha1OLqE72jTH \t\t  \t\t \t  =\"\\\t\\ \\X\\Ö\\-\\ \\ô!NR!\\ó\"\t\t\t\t, \t\t\t\t218m69\t\t\t   \t\t \t\t\t\t\t  \t=  060PhJE2l94u  \t \t\t \t ,\t  Au = \"\\$ \\          \\\t\\\t3 \\ý_\\\t\" \t   \t\t \t \t  \t\t \t, \t\t   J7y2z9Ob0     \t \t \t   \t= \t   \t\t\t \t\tn6Ivi ,  \t3R1uJ= \"!\\\t\\ <\\\t \t 0!\\; \"\t \t\t\t,\t   \td8onBhKj02ZU37  \t \t\t \t\t     \t\t  =     \t\t\t \t\t\t\t\t \"\tC\\ F\\·Z\\Ä\\\\ \" ,\t \t\t \t4aO19p58557ahbEh \t\t\t    \t\t \t= \t\t\t\t\t \t \t \"!!\\x\\ \"\t  , \t \t\t\t \t\t  p93sG0m81Kv     \t    \t \t=\t\t     \t\t\tCd1X81p099U5",
		"~_$~+|-%'|^                   '^!1%^~  \t \t\t\t\t \t\t=   \t \t \t \t\t &*--#$|#!",
		"~%'|~&zu`^^~`|8",
		"+-$!_~*-.!!#6-~'*'#.              .&+|'`*    =\t \t\t \t\t\t\"\\\t)\\ \t9oi(\\[\u0085\\\t\\Ð\\ \\bø\\§\\ \\\t\"   \t  \t  , \t \t\t \t _&h-|   \t\t\t=\t\t  \t\t _&`|!|_^`#%_\t\t \t  \t\t\t\t,\t     \t\t\t \t\t  \t\t   %$~-\t\t    \t\t \t= \t  \t  \t\t\t \"\t\t \\N\\\t\\\u0085\\ \\+^\\\t\\Õw\",\t     &.^.-!-%^\t\t \t \t=\t|91'!^6-.!#-%`|_`*   \t \t \t ,\t  \t     \t \t\t   \t&-^~|!^+w~5^#&23_%\t \t\t \t\t \t\t \t\t =\t  \t\t \t\"\\µD z\\ \\\t\\µd\\)f\\J\\_   \t\\\t\"       \t,  &j^&$^i$$$#^'-9\t \t\t\t \t   \t\t   \t\t\t\t=\t\t\t \t\t  \t\t\t\t\t ^+~'-%#.*_+\t,   \t  \t \t\t  \t\t \t\t'_!_+*`-&-`#-%|++*_=\t \t \t\t\t\t  \t\t \t\"\\ç\\ Á\\\t\t\\ýlÖ  K!\" \t\t \t \t, \t   \t\t *.7!$+#~&'%8$.&     \t \t \t  =\t   \"\\ í \\ !\\D\\Ò3\\\t\\; \",    \t*&%#--_-%!%$||!~_'\t\t  \t\t  \t \t\t\t \t\t\t\t\t=\t  \t    \t  \t  ^#&1|'_#..#_#e   \t \t  \t   \t\t, \t\t\t \t\t   \t   \t  '#*$*v%~|   \t\t \t\t\t\t\t  = \t    \t     __*.+%`a|09P`-h~\t\t\t\t\t\t \t \t\t\t\t  \t \t, \t\t   \t\t\t \t\t. \t\t    \t \t\t\t\t = \"\u0096 \\yNÛ\\\t¬ é\\@e\"\t  \t,  \t\t  \t  \t\t\t \t*+^!`-.^`+|#*\t=      \t\t  \t \t\t  \t~\t\t \t\t  \t\t  \t  \t\t\t, \t\t\t\t \t\t\t   \t   \t  *^`!|*^%| \t     \t \t\t  \t\t\t  =\t \"\\ \\ \\\u009a\\£Ì\\õ\\\t!\\!e \\\t©\\ \\Üi\\/\\ \\!\"\t\t\t\t  \t\t     \t \t\t\t, \t\t \t \t  \t\t\t\t   &_+^##.%`0'\t\t \t\t \t  \t\t\t \t=\t\t  \t\t  \"\\] \\7 e\\\t\t\tÄM\\{\t\\\t}\tm\\¨N \t\" \t,\t      \t  \t   \t*_`$-#       \t\t\t=\t  \t\"\t\\\t7\tC \\.!\\\t\\ q\\\t\\q\t\"\t  ,!__&&## \t \t  \t  \t\t=\t\t\t\t\t \t\t\t\t\t \t*`$EF \t\t\t,  \t\t\t\t  \t\t\t\t\t\t\t \t*#_|#.%.'`'~.~%8  =\t   %+!\t \t \t   \t\t   \t,\t \t  \t\t\t\t   \t   \t\t $`&h&%#&#^$%_~    \t \t \t \t\t\t\t \t=\t   \"\\ \t\t\t\\ \\ !\\ä&!\t\\ À\\\tj\"\t\t,  \t \t\t\t\t\t\t\t  \t+-''$+#_._..-_-_+~$~   \t \t\t\t\t\t     \t\t =  \t     \t\t\"!\\\t\\\t\\\t\\ß\\ ~\\ D\\ !!\t\\ \\\t\\û\"",
		"$&..|+-|4#$&k._..|   9j================",
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
		[]string{
			"~_$~+|-%'|^",
			"'^!1%^~=&*--#$|#!",
		},
		[]string{
			"~%'|~&zu`^^~`|8",
		},
		[]string{
			"+-$!_~*-.!!#6-~'*'#.",
			".&+|'`*=\"\\\t)\\ \t9oi(\\[\u0085\\\t\\Ð\\ \\bø\\§\\ \\\t\"",
			",",
			"_&h-|=_&`|!|_^`#%_",
			",",
			"%$~-=\"\t\t \\N\\\t\\\u0085\\ \\+^\\\t\\Õw\"",
			",",
			"&.^.-!-%^=|91'!^6-.!#-%`|_`*",
			",",
			"&-^~|!^+w~5^#&23_%=\"\\µD z\\ \\\t\\µd\\)f\\J\\_   \t\\\t\"",
			",",
			"&j^&$^i$$$#^'-9=^+~'-%#.*_+",
			",",
			"'_!_+*`-&-`#-%|++*_=\"\\ç\\ Á\\\t\t\\ýlÖ  K!\"",
			",",
			"*.7!$+#~&'%8$.&=\"\\ í \\ !\\D\\Ò3\\\t\\; \"",
			",",
			"*&%#--_-%!%$||!~_'=^#&1|'_#..#_#e",
			",",
			"'#*$*v%~|=__*.+%`a|09P`-h~",
			",",
			".=\"\u0096 \\yNÛ\\\t¬ é\\@e\"",
			",",
			"*+^!`-.^`+|#*=~",
			",",
			"*^`!|*^%|=\"\\ \\ \\\u009a\\£Ì\\õ\\\t!\\!e \\\t©\\ \\Üi\\/\\ \\!\"",
			",",
			"&_+^##.%`0'=\"\\] \\7 e\\\t\t\tÄM\\{\t\\\t}\tm\\¨N \t\"",
			",",
			"*_`$-#=\"\t\\\t7\tC \\.!\\\t\\ q\\\t\\q\t\"",
			",",
			"!__&&##=*`$EF",
			",",
			"*#_|#.%.'`'~.~%8=%+!",
			",",
			"$`&h&%#&#^$%_~=\"\\ \t\t\t\\ \\ !\\ä&!\t\\ À\\\tj\"",
			",",
			"+-''$+#_._..-_-_+~$~=\"!\\\t\\\t\\\t\\ß\\ ~\\ D\\ !!\t\\ \\\t\\û\"",
		},
		[]string{
			"$&..|+-|4#$&k._..|",
			"9j================",
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
