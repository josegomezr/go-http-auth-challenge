package http_auth

import (
	"testing"
)

// samples generated with: https://github.com/rexim/bnfuzzer & RFC 9110 grammar
func TestFuzzerAuthorizationHeader(t *testing.T) {
	inputs := []string{
		".+.!_",
		"1*!F.+&#+-_%`^'*",
		"%*4|-|9",
		"^`|`%+'8K+%&!",
		"~_$~+|-%'|^                   '^!1%^~  \t \t\t\t\t \t\t=   \t \t \t \t\t &*--#$|#!",
		"~%'|~&zu`^^~`|8",
		"+-$!_~*-.!!#6-~'*'#.              .&+|'`*    =\t \t\t \t\t\t\"\\\t)\\ \t9oi(\\[\u0085\\\t\\Ð\\ \\bø\\§\\ \\\t\"   \t  \t  , \t \t\t \t _&h-|   \t\t\t=\t\t  \t\t _&`|!|_^`#%_\t\t \t  \t\t\t\t,\t     \t\t\t \t\t  \t\t   %$~-\t\t    \t\t \t= \t  \t  \t\t\t \"\t\t \\N\\\t\\\u0085\\ \\+^\\\t\\Õw\",\t     &.^.-!-%^\t\t \t \t=\t|91'!^6-.!#-%`|_`*   \t \t \t ,\t  \t     \t \t\t   \t&-^~|!^+w~5^#&23_%\t \t\t \t\t \t\t \t\t =\t  \t\t \t\"\\µD z\\ \\\t\\µd\\)f\\J\\_   \t\\\t\"       \t,  &j^&$^i$$$#^'-9\t \t\t\t \t   \t\t   \t\t\t\t=\t\t\t \t\t  \t\t\t\t\t ^+~'-%#.*_+\t,   \t  \t \t\t  \t\t \t\t'_!_+*`-&-`#-%|++*_=\t \t \t\t\t\t  \t\t \t\"\\ç\\ Á\\\t\t\\ýlÖ  K!\" \t\t \t \t, \t   \t\t *.7!$+#~&'%8$.&     \t \t \t  =\t   \"\\ í \\ !\\D\\Ò3\\\t\\; \",    \t*&%#--_-%!%$||!~_'\t\t  \t\t  \t \t\t\t \t\t\t\t\t=\t  \t    \t  \t  ^#&1|'_#..#_#e   \t \t  \t   \t\t, \t\t\t \t\t   \t   \t  '#*$*v%~|   \t\t \t\t\t\t\t  = \t    \t     __*.+%`a|09P`-h~\t\t\t\t\t\t \t \t\t\t\t  \t \t, \t\t   \t\t\t \t\t. \t\t    \t \t\t\t\t = \"\u0096 \\yNÛ\\\t¬ é\\@e\"\t  \t,  \t\t  \t  \t\t\t \t*+^!`-.^`+|#*\t=      \t\t  \t \t\t  \t~\t\t \t\t  \t\t  \t  \t\t\t, \t\t\t\t \t\t\t   \t   \t  *^`!|*^%| \t     \t \t\t  \t\t\t  =\t \"\\ \\ \\\u009a\\£Ì\\õ\\\t!\\!e \\\t©\\ \\Üi\\/\\ \\!\"\t\t\t\t  \t\t     \t \t\t\t, \t\t \t \t  \t\t\t\t   &_+^##.%`0'\t\t \t\t \t  \t\t\t \t=\t\t  \t\t  \"\\] \\7 e\\\t\t\tÄM\\{\t\\\t}\tm\\¨N \t\" \t,\t      \t  \t   \t*_`$-#       \t\t\t=\t  \t\"\t\\\t7\tC \\.!\\\t\\ q\\\t\\q\t\"\t  ,!__&&## \t \t  \t  \t\t=\t\t\t\t\t \t\t\t\t\t \t*`$EF \t\t\t,  \t\t\t\t  \t\t\t\t\t\t\t \t*#_|#.%.'`'~.~%8  =\t   %+!\t \t \t   \t\t   \t,\t \t  \t\t\t\t   \t   \t\t $`&h&%#&#^$%_~    \t \t \t \t\t\t\t \t=\t   \"\\ \t\t\t\\ \\ !\\ä&!\t\\ À\\\tj\"\t\t,  \t \t\t\t\t\t\t\t  \t+-''$+#_._..-_-_+~$~   \t \t\t\t\t\t     \t\t =  \t     \t\t\"!\\\t\\\t\\\t\\ß\\ ~\\ D\\ !!\t\\ \\\t\\û\"",
		"$&..|+-|4#$&k._..|   9j================",
		"#_!*+'m^+!&&%%`'x$                A6n307c5Nb7U62=================",
		"~+A'&$$$_&-i2&#G^%^",
		"!`~-",
		"`            PA40============",
		"_$*`-6#|&-^$+!^$$           ",
		"*-.    x2522il6S21wZoy85cd=================",
		"~^&`P^4|*    '#`%8~`$~.^0^%&\t   \t\t\t \t\t  \t\t  \t \t\t=\t     \t\t  \t\t\"U \\.\\ \\òù \\\u0089\\ !\\7\\\u008b\\ËÌB=\"   \t\t,   \t\t  \t\t\t\t \t\t   \t  &&~$$`#&^%|M.  \t\t   \t\t=  \t\"!s!\\\t\\ü\\{\" \t\t  \t\t\t,||^^8_&'&\t\t     \t\t\t=\t\t\t \t\t\t\t \t\t \t\t\t\"\\Ú\t\\ \\Õ\\G\"\t    \t\t\t\t\t \t ,\t\t\t\t \t^^*S-1=\t \t \t\t  \"\\\tÉ\t\\Ø\\\tk}\t\\\t_\\Ø\\ ¡!{\\«¹\\\t\u0085\" \t\t  \t\t \t  \t \t,\t\t\t \t\t\t\t\t\t\t \t\t$!..~$!#`5-|| \t\t\t \t\t\t    =    \"²3\\»Ð\\\t!\\\t\\l\\Y!\\½\\ p\"  \t\t\t \t \t\t\t\t\t  \t \t\t ,\t\t\t\t\t \t\t\t\t\t\t \t  \t\t \t^v`~%%*'_%v+k'+|#\t\t\t\t\t \t\t =\t\t    \t  \"\\b\\ \\ \\\t\\\t.\\Q\\\t\\ \\\tx\"\t   ,  7_^_  \t \t  \t\t\t=\t \t\t   \t \t\t\t\t\t \t   \t``&t~.$+|~5. \t\t\t\t\t,  #'*_.*^*=\t \t\t   \t     \t \t\t\"\tkãN\\x\tug\\)\\è\\®\" \t \t    \t \t \t,\t   \t\t\t  \t   \t  \t\t-'_^%.$&'Q`\t \t\t   \t=\t \t\t \t \t\t\t &!'-s!_&|^`|%#& \t   \t\t \t\t\t, \t\t\t\t   \t \t       *!B+#.^'|&!| \t \t=   \t\t \t\t\t$`*+-_- \t\t \t \t\t \t\t\t   \t \t, \t'8_$#.9.#%.\t \t=\t\t      \t \t\"\\§\u009a !Æù\t! æ\\ \\ h\tq\\\t\\\t m\"\t  \t\t  \t   ,\t\t   \t!|*`'*9_`=\t\t '`_*^-.-.+!+_$-X_-    \t \t\t \t \t \t\t  \t\t ,\t \t\t '#-`4$~9  =\t\"2\\ZT\\Ó\\\t\\;\\\t÷r \\y\u0096\\ \\ º\\\t|\"",
		"|-+||-9_`_-%.-'_^#4.               D6E9v6OK4e1214Y",
		"&~%.$~%3F!%!~",
		"4-`!#",
		"!&.3*~$$'$_-%e|",
		".|V.*",
		"Rd-'|_~#`$%",
		"*_2|!#'~H'_*$7`%'*|",
		"`+H_!63",
		"!.h'-_^",
		"`!'^$_#_^I'-+``'#$        Lh488163ck42cIksf=================",
		"..%_^|               ",
		"-|~3$_++.    !^*~.*%_'~9#$+.|| \t    \t   \t \t\t =\t\t\t  \t |%  \t \t,\t \t Z_|P`\t \t \t\t  \t  \t=\t\t   \t\t     \t\t   \"\" \t \t\t \t\t\t\t\t\t\t \t  \t\t,'+|!#+~%'+-$#%`.'  =\t\t\t\t   \t$~'$$|_$+\t\t\t\t \t   \t\t\t   \t\t , \t\t\t\t\t\t   \t   \t-`=\t \t\"\\\t\\\t\t\\ \\ \t·\t\\ \t\\\u009f\" \t\t  \t  \t\t\t    \t\t, \t\t  &5%\t \t \t \t\t\t\t \t\t\t\t =\t  \t\t\t  \t\t  \t\t\"!6\\Ñ\t\\\t+\\r\\Yô!\\\t~$!\\?\\  \\\t\"  \t\t\t  \t  \t ,\t \t.+3$ = \t\t \t\t    \t\t  \"\u009d\t\\   ,M \\ \\\t>\\ Y\t  \\\t\\B\"  \t  \t   \t\t\t  \t\t,\t \t \t\t  \t\t\t   \t 2'$`-$+|4.-.|+%+.`|^ \t \t  \t\t\t\t\t \t \t\t \t =\t \t\t  \t\t  \t~3- \t  \t\t \t   \t \t  , \t\t\t   \t\t     \t  #+$.##_6'_$+%$.|+`  = \t\t  \t    6#`|^`'$_'%~`, \t \t \t   \t \t\t\t\t\t \t~a#^J.^$8`*-.%%\t \t  \t\t\t \t\t  \t\t\t =\t\t \t\t|`*%7^-`&#-|*\t \t \t, \t\t\t\t\t\t\t%-.7$t#+`!|_`#| \t\t\t  \t\t\t\t \t\t \t\t\t= \"\\e5\\d\\ \\à\" \t ,   \t $  \t \t\t    \t \t= \t \t\t    \t  \t\t\t\t\t%%\t   \t \t\t\t \t   \t,  \t\t\t\t \t\t\t\t \t *p%~&_$#|\t  \t\t   \t    \t   =  \t\t\t \t   \t\t \t\t  \"\\\t\\ ½\\\t \u0092]sY\\\t\\â\\\t\\ \th\" \t \t\t\t , \t _$ \t\t\t = \t \t\t \t \t\t\t\t\t\t\t  $`_`$!'*&.$'51&9#%|.\t  \t \t\t\t \t\t,\t\t\t \t\t    \t \t  \t %'!-%'$*^'|+$ \t\t\t \t \t  \t   \t\t\t\t\t=\t\t\t\t\t\t\t  \t\" ¶\\ \u008d\t\t\\\t\\D\t !\\Ï\t\\ ó \\ò!!\"\t \t  \t  ,  \t\t \t      \t2~~_!'#3`+!%'#-$^         =\t\t\t\t      \t\t\t`-^'#*8*&%~~#'\t\t\t \t, \t\t\t^$ \t \t\t\t \t    \t\t \t \t =\t \t    \t\t    \t\t   \t -+^$..96-*_^%|\t\t \t  ,  \t \t\t  \t\t\t  \t \t\t\t  &!~~.P%%.#!!K#~7 \t \t \t \t=\t \t 3&&._+'.$I*-~&-\t \t \t\t \t \t\t \t,  \t-!^ \t \t\t=\t\t \t\t\t  \t\t   \t\t \"\\%\\Aq\\ \\C`\\\t. {\" \t\t\t,  \t\t\t \t\t\t\t\t\t \t  ##5^'' \t  \t \t \t\t   \t   \t\t\t=  \t\t   \t\t  \t\t\t  \t\"3\\\t\\\t \" \t\t \t ,\t\tl~2^&.!=  \t   \t     \t \t \t\"\\\u009d\\ð \\ \"   \t\t\t\t\t\t\t\t , \t\t\t \t\t\t\t  ^|b6~#^.~^k^._~_ \t \t  \t\t\t  \t\t  \t \t  =    \t\t    \t \t\t  \t%`%|!!`~8!_",
		"3%_~~",
		"`.*m~0%s~%#%+$",
		"_$.J%|_`.~9#*||*!",
		"``%_+&*d*^*                  ",
		"'+-~_!      8N3================",
		".8.#$$_+^",
		"`.$.'                  #$~93$D` \t\t\t\t  \t \t \t\t\t= \t  \t \t\t  \t \t _$_'__^$^#_'-~^$* \t\t  \t\t\t ,\t\t  \t\t \t\t  \t \t  \t!#`~  =\t \t +^5%!`~7\t\t  \t          \t ,\t\t$^$*.| \t \t\t\t \t \t=\t      \t\t\t\t\t\t  \t\t \t_$!~*%*'|`_^~\t \t\t\t  \t    \t \t\t \t\t ,\t  \t\t  \t  \t\t-~Cw.G#$*'---+#\t\t \t=     \t\t\t \t   \"~ i \\\t\"\t    \t \t   \t\t \t  ,   \t$~_%'`|R%% \t=\t\t&-%-`D\t\t \t  \t\t\t \t  \t \t\t,  \t*#+*%|$|%Q*`^~!`*~ \t\t \t=\t  \t \t\t \"\\\t\t\\ý\\\t\\\t\\:k\\Q\\É\" \t\t\t \t  \t \t  \t ,\t\t\t .+&-+`%+^$$8'`|  \t \t\t\t  \t  =\t\t\t\t\t-|9..-'\t ,*$&-^_    \t \t\t\t\t\t\t \t   \t \t=\t\t`N+#9l&  \t\t\t\t\t  \t \t \t  \t\t\t,\t \t\t\t\t\t\t \t\t\t.~_&6&#HN~~_^`+.+' \t \t\t  \t\t\t       =\t\" !\\ì  '\\\t\\\u008fö\\\u009cÍ \t\t\\\u0094\\á\",\t\t \t \t ~1h#|%%|^-d\t\t\t\t\t\t  \t  \t\t\t   =\t    \"\\)[\\\u008f! \\S\t\\\t \u0095\\?Ý\" \t,   \t  \t\t\t\t\t\t\t\to&5+'^$!&$\t\t\t  =\t \t\t     \t\t    \t\t\t^|.&_     \t\t \t \t \t\t    \t,  \t\t%'|.^%~+.&4$|#! \t\t=  \t\t\t\t\t  \"\\X\\¢\t$\\ \t\\°ª!\t\\\t\\\u0084\"",
		".      P7khV9d0G==",
		"-|_*&~*|.^*",
		"`*$^#^*`._.&$`^",
		"~|''_+$++&&-7-*",
		"-$3+_              H2W9==",
		"``Z^~",
		"%~'j.^^%.`$+~q|~^!`_",
		"'#~      63IU04477K07908f4============",
		"`&`^A~.K*|!*'^_*-&. i6K79ZWH3476845=======",
		"%^+*+",
		"$%_^.P*_!*#`6-%~'-",
		"**#'P+#_n-8W_`^|^7-               %_..#.43|`~%.1^_=\t  \t      \t \t\t\t\t\"\u0089-3\\ \\ \\\t.\\\t\\Ò\" \t \t  \t  ,\t   \t  \t\t%%%6#6_$7$%%'-#-`  \t\t \t\t \t=\t\t  #\t\t\t\t\t\t   \t \t ,\t\t\t\t   \t  \t \t\t \t ^+%%%4&+     \t \t  \t\t  \t    =  \t \t  \t\"!\\ \\S\\\t\\  \\\u009bg-\\Ñ\\ k\\v\\a\\ö\\O\\\t!\" \t\t \t    \t\t  \t\t\t\t\t\t,\t     \t\t\t 3$&'.%!|#!9`6-p\t\t \t  =\t\t  \t \t \t\t\t\t\t\t    #|7\t\t  \t\t,\t    \t\t\t \t\t  \t   \t~%\t \t\t\t\t =\t    \t\t      %&%.^|~*|_%\t \t   \t\t \t ,\t\t\t\t \t \t &-.&''^~&~#%^$`A.   =\t \t\t \t \t\t$+*&_-#^#!*F!7^! \t\t\t\t,  \t\t\t\t\t~+  \t\t=\t \t!%___*%*+%_-+%_|C ,\t \t\t\t  \t\t '+$!$&'$^s|%  \t\t \t \t\t   \t\t\t \t  \t=  \t\"\t\\\t\\`\\\t\\\t\\\t \\\tm\\;\\ \\\t\\`\" \t\t\t \t  \t  \t \t \t   ,        \t\t\t\t    \t !&|.~'%*$!~%%+%~*%~~\t\t\t\t\t =  \t\t\t \t  \t^7r.'&-~8*%^2~_~- \t   \t\t\t\t \t ,\t \t \t \t\t*|$_!|&!||15^.~7~O\t \t     \t\t\t= \t\t\t \t   \t \t \"\\\t\\\t\tà\" \t\t \t\t  \t\t\t\t\t  \t \t ,\t\t\t     \t  \t\t  \t \t\t%!^$-d~^z%|_%.+H    \t \t \t=\t  \t\t\t\t \t `'6!\t\t\t  ,\t \t\t \t .%%*-#%9._#|~-'#^+&+\t  \t\t\t\t   \t\t =\t \t  \t\t      \t \t\t \" c\\\t\\u¨\\\t\\µ\\\t\\\t\\ø\\ _\\ \\ \u009aw\"\t\t  \t\t\t      \t \t\t\t,\t\t\t\t\t\t \t\t\t\t \t\t\t `7^ \t\t \t\t=\t \t\"\\\t\\È!s_\" \t \t\t \t ,\t\t \t   \t\t \t\t\t     \t\ta+\t   \t= \t%*%#&.#^#`#\t \t\t ,  \t\t\t \t     \t \t 6-!_!#_\t \t\t=   \t  \t \t\t  \t   \"\\Ö\\\t\\¿Ñ!\\}\tbx!\\ \\\tg\"\t \t \t\t,\t \t       \t   \t$&$#.#%~#_++_''|\t  =\t  \t \t \t\t\t \t\t\t \t \" E\"\t   \t\t\t \t \t\t ,\t\t_*%%|||f$- \t\t\t \t \t\t =\t\t\t\t  \t \t \t\t\t   +5-%-.|~&*+#-`-  \t,'$$%$^%*|'+1!~#.%||^\t\t \t\t=  -!3&&M6|`#^$~# \t , \t \t\t  -'I+#-~'=\t\t !_-|.7!`-",
		"y$!.^.~+++",
		"h                69xm0975T935GHm335i5=======",
		"E#-~%                ",
		"^-*&5^|^`+-|",
		"$A$^",
		"_w           9#~`'!_4!$-'l.'-*|_! \t  =    \t#&`&Y*~!._9.`I&w%__! \t\t    \t \t     \t\t,\t\t    \t \t  \t'|.+~+*~&!\t\t  \t \t\t  \t \t  \t\t=   \t  \t \t `*$#-'2,  \t \t\t\t\t  \t\t\t  \t\t \t\t&!-#- \t\t  =     \t\t\"\"  \t\t\t \t\t \t \t    ,\t  \t#%!.'_`$%.*2'#.*  \t  =\t  \t \t\t     \t\t \t`.'&0z \t\t \t\t   \t\t \t\t,\t \t\t\t*_A.|z'.|'\t\t\t     \t\t\t=\t\t \t  \t \t \t \t\t \t\t\"\\\u0099\\\t\\ ø\\ \tð#G!\t§\\z\\\t\" \t \t \t     \t\t\t\t , \t  -'C.#| \t=  \t \t\t\t\t\t \t\"\\÷\\e¢\\r\\×f¯\\A|\\\t\t\\Ì\\ü\t\" \t\t ,   \t \t       \t\t\t\t\t \t|& \t\t\t\t    \t\t\t\t\t\t\t \t\t\t=  \"\\\t\\\t\\O?\t\\ 8!\\ y\u0090\\\t$!^\u0086\\Ö\th\"    \t\t \t,\t\t  \t\t\t\t   \t\t  \t  .$_~'%~+3$z_|^P#D1 \t\t\t \t\t  =  \t\t\t\t\"\\\td\\s\\Û\t!\u0097\\\t1\t\" \t\t\t\t \t\t \t\t  \t \t\t\t\t\t,   \t\t \t  \t\t\t \tc#!#'+*+\t\t \t    \t \t\t  \t=\t  \t   \"\\\tr\\ G\\ \u009f\t!d!\\\u0092\\.!\t\\G\t\\ q\\ \"\t   \t\t\t \t\t\t   \t\t \t,      \t   ^-l-$!&^^'__`.-$\t\t \t  \t\t\t = \t\t     \t \t\t\t  \t # \t \t \t\t  \t,\t\t\t  \t\t\t\t.'_*z\t  \t=\t\t \t \t \t\t$~+1^^g%4&``% \t \t  \t\t\t \t\t   ,   \t\t \t4#|hT^_|5&     \t\t\t \t \t \t\t\t= \t  \t \t\t\t  \t\t` \t\t\t\t \t\t\t  \t,\t'3&R`! \t \t\t\t\t  \t \t\t = \t    \t\t\t\t\t   \t\t \t \"\\`\t\\eÚ\\\t\\4 !\\K\\\tÖ \\i\\\t\\Wfkti¢\" \t\t\t\t \t ,  \t \t\t\t  \t\t \t|*. \t\t\t\t\t\t\t\t  \t\t  \t\t \t\t=\t \t  \t \t    \t\t~0#-!*-`d6   \t\t ,   \t  \t\t\t \t\t &%Z*8~^~|6+.'`\t \t =\t\t  \t    \t  \t\t\t\t\"\\ \\F \\\\õ\tb\t \\\tM\\ \\ \\ \\ \\i\\º\t\\\t*\" \t\t\t\t \t    \t\t \t \t\t,      \t  \t~_#*+\t=\t       \t\tL~\t  \t\t \t \t   , \t \t  \t  \t\t\t \t  \tD%!+*~\t \t\t\t \t = \t  \t\t\t\t      \t\t \t_^'2'.*#|7-|~\t  \t    \t, \t  \t _!  \t \t\t\t  \t   \t\t     = \t     \"\\,.\\¿\\ \\A\\\t \" \t,\t\t\t \t  \t \t5*$~|l||_     \t\t \t   = \t \t     \t\t\t\t \t\t\t\t\"üW\u009d\"\t \t\t\t  \t \t,\t\t &*#*-.$$`-+\t\t\t \t\t ='|8c|_^d%'#%~79    \t \t\t \t      , \t \t\t\t       \t  \t&M%|+_ \t \t\t \t\t\t       =  \t\t \t\t\t\t \t\t '+!%",
		"%'      #*~&.'-!_%.|^.\t\t\t\t  =\t \t \tG.+s+4        \t  \t\t\t ,     \t      \t \t \t \t ~6&_`*^-^~&B1!+\t \t\t  \t \t\t =\t \t \t`~_`*6|.`-$.--^ \t \t\t \t ,\t\t  \t\t   |    \t\t  \t\t        \t= \t\t  \t \t\t\t \t _#~~~-!$|~!!-0V*`",
		"~^*.&#w`          j5wF8G=====",
		"+2#&+!_",
		"|2+!_*'~$",
		"%`6||-!#_!%#_!|q%1$%                  67er=====",
		"'!i",
		"#4-||6~0+8$#.hw`$|.!                    973l3wv91n====",
		"'*$",
		"'3~$'_&!*4._|#`             5k28G429kb8HQ4O====================",
		"+#*^'$^",
		"%#+!~",
		"% ",
		"`~ _&*&+%++_~.    \t\t=\t\t \t\t \t  \t \t\t \t \t\t .-\t\t \t\t  \t\t\t\t \t \t\t  \t,\t\t\t \t\t\t     \t  \t  .#-!+`$+8\t\t\t \t\t\t=\t\t \t\t \t \t\t __e'|~_& \t  \t ,    \t\t\t!!%$.-+$+Y$&^`\t \t\t   \t \t \t \t \t\t =  \t \"!!\\®\\\t \t\\k\"",
		"&#|-$#",
		"*'~|",
		"H-|!~.~3_#~+                ^zv^5-7#&|'`\t\t\t =\t  \t \t\t\t\t\t\t\t   ^\t\t\t   \t\t  \t ,\t\t  \t\t\t \t+=  \t \t \"Ú\t\\D\\?\\\t\\ \\-\\\u0096\\ð!\t\" \t \t \t,\t \t\t  \t#`oz^18_#|_'.`\t \t \t \t \t \t\t  \t =\t\t \t\"\\\t\\30\\ \\ \\É!\\ fw\tI\t#\\ò\\'\\\u00a0\\ \\°\" \t,\t\t\t*^&%`##!$T--  \t\t \t \t= \t   \t\t\t\t\t\t  \" \\§\t!\u0089c !\\\t\\ \\X\\\t\\\t \\ \"   \t \t\t\t \t\t\t   , %30-*9#~-.+       \t\t      =\t\t \t\t\t   \t\t\t\t \t  \"\\¨G®\\K|¿\\  \\½h\\RE \\ \\\u008b!b\\\u008f\\\t\"\t  \t   \t \t\t\t \t\t \t \t , \t \t\t\t\t  \t\t\t \t`-*^'C\t\t=\t\"\u00ad\\\t\\ h\\\t\\L  \\ \\p\\F\"       \t\t\t\t    ,\t\t\t\t\t\t    \t \t\t\t \t\t'*`'._#.$-&$!\t\t \t   \t\t\t   = \t\t  \t &*#~~*^   \t\t,\t \t\t  |`~^+!G^`1~#%3'  \t\t \t\t \t  \t\t =\t   \t\t\t\t\t\"\\ \\ \\\t\\õ\\8!p\\ \\Nr\\2ý\\Á6\"\t\t \t\t      \t,  \t \tY|*&!&#%`$!*3^_ \t  \t= \t\t \t\t\t \t   \"\t<\t\\\u0081\" ,\t\t\t\tmM'$`#|\t\t\t   \t \t  \t\t\t\t =    \t\t  \"\\Ë\\nf \\}!Òê \\\tA\\\t \\ \"\t\t  \t \t\t  , \t\t\t\t 9-4#R#!%    \t\t  \t    \t\t\t\t\t =  '#`!'",
		".%",
		"*!%`'!#",
		"*&$.!$*&l!`^^_*!|+    ",
		"_&$+|'      D^%#-|&_^|.|^`~%.\t   \t\t\t    \t= \t \t   \t \t\"\"  \t\t\t   \t   \t \t\t\t\t , \t \t \t  \t\t\t\t$4''&S|&.!'`+\t\t\t \t\t\t\t\t   \t= \t \t\t\t\t\t  \t\t \t \" jq\\\t!\\  \\Ù 4@\\Û\\ 2 !\\ç\u0084\"\t\t\t,\t \t~^*`|-++zq_#^J8#1%*9\t\t  =   \"d \"\t,\t   \t \t 7+^^%'#*!     \t \t \t        =\t \t\t`|.^'%.&$I`* \t \t\t\t \t\t\t \t \t  \t\t  ,\t\t\t\t\t\t \t     \t\t\t  T_x`!&_.%*|'*$|-\t       \t=\t \"n\\\t!!j\t\\ \\Ë\"",
		"vf+%R!+^&'**2*!%   pm================",
		"%6'.",
		"+&.%&$&#8`*283~+#      h998========",
		"|F+.&G~%`!_'|b|_+",
		".~D&-|&'%&|.           ",
		"'&-_4._$L      M298G=============",
		"!y-_~&|*`  yRi4=========",
		"_##*$`#z'!~               ~1#'~^|\t\t \t  \t\t\t\t\t\t\t\t=\t\t \t \t \t\t \t \t \t\t\"!\t\\Fl\\@>\\Ìg\\J \\ u!\\©Ñ\t\\\t\\«\\Òr\" \t   \t,\t \t \t\t    \t  \t   \t \t-^~f'+^-*#&!%$.*#!-\t\t  \t \t= \t \t         7%_-#|o|__.||_# \t \t \t\t\t\t\t \t\t,   \t  \t \t \t\t\t.#|_9_^\t\t\t     \t\t \t  =  \t\t \t\t\t \t \t  \"Õ \"",
		"~^~|!8._!!'-#$_&|'$          ",
		"*|",
		"7|$_..g`_%&!%_*#~`8.            4o071jo81=====",
		".~$#1~&d_$~           o3=",
		"#^$%$%!_&^-                  F''`. \t  \t=    \t  \t\t\t   \t \t \t.\t\t\t   \t    \t  , \t  \t \t \t\t \t\t\t\t  \t\t&$!|+|^*!$*%'+&!*~3    \t\t  \t\t\t  \t\t\t=\t\t\t \t\t\t \t\t   \t\t \t\t\"c!\\\t\\\t\\E ì\\±\\\t\"\t \t \t    \t\t \t    ,\t\t\t \t\t  \t  \t\t \t\t'^.g|#*%'*6&|~$%|.~-\t\t  \t\t\t\t\t\t\t =\t \t\t  \t\t\t  \t\t \t  \t\"\\ \\v\"\t \t\t\t \t  \t\t \t\t \t   , \t\t\t  $#'#*||+.2*++ \t\t \t \t\t\t\t\t=\t  \t\t\t\t\"\\ !\\\t1\\ \t \"  \t \t\t \t\t\t\t\t \t \t, \t \t\t       \t\t     %.-#&^o~#-#`'.+~%!$\t   \t\t\t\t\t     \t=\t\t\t \t\t\t \t\"t\\\t\u008eQ¡\\}\" \t ,\t\t\t\t  \t  \t\t\t    \t   ^#\t  \t  \t   \t= \t \t \"v)\\Ù\tÂ\\\u0080\\ø\\\t\\ \t\\.\\\t\\yd4\"\t\t  ,  .%'    \t\t\t \t\t\t\t\t =\t  \t\t   \t\t \t\t\"\\\t\\T\\ p\\)\"",
		"#*-%+",
		".|.|%_^_^.|~+.%",
		"-''!|#e#~t^$``'~^                    ",
		"+.^-&6!'.*!*&%`*&-%    A_|%0#u~`#&&|#%& \t  \t  \t\t\t=  \t\t \t\t \t\t\t%|`#^`$'$Z~$-%\t \t  \t\t,  \t   \t \t     \t F||`-D^`\t\t\t \t\t\t  \t \t \t   \t  =\t \t\t \t    4_-*.&^|-.q`!3.|_   ,\t\t\t\t\t \t'_|#.!^1+#%`&.X!A \t \t \t \t\t\t    =      \t  \t\t \t\"\"  \t\t \t ,  \t\t\t\t   56&*~1`'5%|||_5%%.\t = \t\t   \t     \t\t \t  \"\\ \\Ï\\\u009e_ \\ \t \"\t \t    \t \t\t ,\t\t\t \t  `%#`%-$  \t\t \t=  \t   \" Éè\\}W\\\u0091\\ \\\t\\\t\tÔ\\>\\\t\\|\"    \t\t  \t\t    ,\t  \t\t\t\t \t\t6``5*  \t\t \t\t=\t   \t\t\t\"\\ù\t\u008b/Í\\9\\\t\\®!\\  \\% \\ \" ,\t\t\t\t  \t  \t\t\t  \t\t \t-#_3%|_  \t  \t  \t\t   \t=\t   \t \t    \t   -!|+-.#1$+%+$- \t\t \t \t    \t \t\t \t  ,\t   \t\t    \t y$!$$-^#|-'&`  \t \t\t  \t  =\t   \t5~%#*.#-''&+&3*` \t , \t\t\t\t\t   \t\t!^**'%!*`-|~!~|'#|#`  \t\t\t\t  \t\t  \t  =\t\t \t\t\t -$&`jL'-* \t \t \t\t \t   ,\t \t\t \t\t  \t!3'|&%  \t \t \t\t= \t\t \t \t \t%|.'!-%%+^+'`*~+.  \t\t \t,\t\t\t+|!|4%'$+%&%7+'-#H`$       \t \t\t  \t\t=\t  \t\t \t\t\t\t     \"D\\0\\\t\\C1s! V0\\% \u009b\\+\\ !\\Ýn\\Ò\" ,\t\t \t   -*_!&!%_&'\t\t \t=   \t\t\"\\è \t\\©\\  !\t¦ë\"\t\t \t \t \t\t\t \t ,  1^'~&* \t \t    \t \t \t= \t\"\\*\\þ\\e\\\t\\\t!\t\\=\\   ! \\ \\\u0087\\Ã\\\t^\\ \\\t\"  \t \t\t \t  \t \t,\t \t\t \t \t\t \t _+` \t \t  \t\t  \t \t =\t \t\t \t\t\t  \t\t\t\t   \t-% \t\t\t  \t ,\t   \t \t\t \t\t\t\t\t \t-*#-*#|%*.'!'&%%\t\t\t\t\t\t=\t\t\" \\Y\"",
		"T$-!*~!#.+'.!!'!.",
		"--'*_-&._#*^$m`#                 m1V7KE66TeNclp============",
		"8|-._#!~+&+^           ",
		"8.-*~^'-!|*^|-.^^~_    I1q68551C0fJb3=============",
		"`_         6fCD62l===================",
		"`|g#.%#|%m5",
		"+''_+~.%#.&            ^'&~_~`+\t\t\t\t  \t\t  \t\t\t \t\t\t =\t     \t\t  \t\t\t    \t\t+'~|~.%!e%_-\t\t \t \t \t \t \t \t , \t\t \t\t\t\t\t\t    \t  \t-'^^=\t \t   $`.+`.^~\t \t,\t\t  \t\t &%#!r+9    \t\t\t\t    \t= \t\t\t  \t \t \t \t\t\t  \"\\I!p~\\\t \\ [\t\\Ê\\\t¾\\\t\\7\" \t \t\t \t\t\t\t\t\t  \t \t ,\t  \t\t\t$~-`6g+!!+%_&9.~_&G=\t\t\t \t\t \t \t\t  \t \t    \"\\\t\\àA\\\t\\ør\\ \\\t \\F\\zz\\b2\t!Ëe\\\u009e\\ \"  \t \t\t \t\t \t,\t  \t  `+#&&*$-U'&~|`%_#.*\t\t\t\t  \t\t=\t\t\t \t\t \t\t \t\t   \"\\o\\\t\tp\\\t \\Ó\\dò\\\t\t\t \\\t\\ \"\t\t\t, \t  \t\t \t\t\t\t\t\t   \t\t -&!.`_#u`.p|+`% \t \t=  \t  \" OH\\è\\\t\\ \\\t\\\t\"\t   \t,\t\t\t\t  \t\t\t\t\t..+~^.`\t\t\t  \t\t   \t\t  \t \t\t = $7|!%$*#+* \t\t\t , %!.*\t    \t =\t \t    \t \t\tU&''&&-\t \t\t  \t \t \t \t   ,\t\t -%.%+.2t\t \t   \t\t\t   \t   = \t\"\" \t\t    \t \t ,     \t \t  %&`$'-'$*$v-_|f*#|+  \t=  \t \t\t \t\t\t  \t  \t\t\t \"\\N\t\\\u0095B!!\" \t\t\t\t\t\t\t\t,\t\t\t\t\t \t\t\t\t\t |~`7+#0_\t \t \t\t  \t\t\t\t= \t\t \t \t\t \t\t  \"\tµÅ\\ y\"\t \t\t\t  \t \t\t  \t   , \t  \t'~.7\t\t \t\t \t    \t\t=\t \t \t\t \tU+^^-\t,\t &*.`-..6 =  \t \t  '\t\t \t\t\t   \t\t\t\t\t\t\t\t,1#|^++|^.  \t  \t\t\t\t \t =\t \t\t  \t\t  \t\t\t\"\\ \"\t\t \t\t \t, \t \t\t \t\t\t   \t \t \t_-7'-`+   \t  =    \t\t\t\t \t7^!++3.^K+-^\t\t \t \t\t\t \t\t\t\t \t,  \t\t  \t \t``   =\t   \t  \t.C%'&#|%*+# \t\t  ,\t\t\t   \t\t\t\t&&-&|!#8%#H*`^|!\t\t    \t\t   \t= \t\t  \t \t\t   \"\\\u0081{\\± 1!\\\t\\ \\ E\"",
		"`m+_#^L%v2&|",
		"X`.#&~!`#~^$                    ",
		"*`'~_+`-!#.*%``%6",
		"2*`-|^&-`*&17+$",
	}

	for _, inputHeader := range inputs {
		_, err := ParseChallenges(inputHeader)

		if err != nil {
			t.Fatalf("Failed parsing %v. With err=%s", inputHeader, err)
		}
	}
}
