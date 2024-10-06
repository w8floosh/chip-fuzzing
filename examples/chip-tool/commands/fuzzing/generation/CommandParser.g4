/** Taken from "The Definitive ANTLR 4 Reference" by Terence Parr */

// Derived from https://json.org

// $antlr-format alignTrailingComments true, columnLimit 150, minEmptyLines 1, maxEmptyLinesToKeep 1, reflowComments false, useTab false
// $antlr-format allowShortRulesOnASingleLine false, allowShortBlocksOnASingleLine true, alignSemicolons hanging, alignColons hanging

parser grammar CommandParser;

options {
    tokenVocab = CommandLexer;
}

payload
    : obj
    ;

obj
    : LCURLY pair (COMMA pair)* RCURLY
    | LCURLY RCURLY
    ;

pair
    : UINT8 COLON value
    ;

arr
    : LSQUARE value (COMMA value)* RSQUARE
    | LSQUARE RSQUARE
    ;

value
    : obj
    | arr
    | STRING
    | OCTET_STRING
    | SIGNED_INT
    | UNSIGNED_INT
    | FLOAT
    | DOUBLE
    | TRUE
    | FALSE
    | NULL
    ;