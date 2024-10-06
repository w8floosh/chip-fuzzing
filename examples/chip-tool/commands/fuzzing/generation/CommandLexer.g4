lexer grammar CommandLexer;

fragment HEX: [0-9A-F];
fragment ESC: '\\' (["\\/bfnrt] | UNICODE);
fragment UNICODE: 'u' HEX HEX HEX HEX;
fragment SAFECODEPOINT: ~ ["\\\u0000-\u001F];

fragment OCTET: HEX HEX;
HEX_8: '0x' OCTET;
HEX_16: '0x' OCTET OCTET;
HEX_32: '0x' OCTET OCTET OCTET OCTET;
HEX_64: '0x' OCTET OCTET OCTET OCTET OCTET OCTET OCTET OCTET;

SIGNED_INT:
	'"s:' HEX_8 '"'
	| '"s:' HEX_16 '"'
	| '"s:' HEX_32 '"'
	| '"s:' HEX_64 '"';

UINT8: '"' HEX_8 '"';
UNSIGNED_INT:
	UINT8
	| '"' HEX_16 '"'
	| '"' HEX_32 '"'
	| '"' HEX_64 '"';
FLOAT: '"f:' HEX_32 '"';
DOUBLE: '"d:' HEX_64 '"';
OCTET_STRING: '"hex:' OCTET+ '"';
STRING: '"' (ESC | SAFECODEPOINT)* '"';
TRUE: 'true';
FALSE: 'false';
NULL: 'null';

LCURLY: '{';
RCURLY: '}';
LSQUARE: '[';
RSQUARE: ']';
COMMA: ',';
COLON: ':';
SQUOTE: '\'';
// WS: [ \t\n\r]+ -> skip;
SPACE: ' ';