/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

lexer grammar StaticTSLexer;

channels { ERROR }

options {
    superClass=StaticTSLexerBase;
}

MultiLineComment:               '/*' (MultiLineComment | .)*? '*/'             -> channel(HIDDEN);
SingleLineComment:              '//' ~[\r\n\u2028\u2029]* -> channel(HIDDEN);

OpenBracket:                    '[';
CloseBracket:                   ']';
OpenParen:                      '(';
CloseParen:                     ')';
OpenBrace:                      '{' {this.ProcessOpenBrace();};
CloseBrace:                     '}' {this.ProcessCloseBrace();};
SemiColon:                      ';';
Comma:                          ',';
Assign:                         '=';
QuestionMark:                   '?';
Colon:                          ':';
Ellipsis:                       '...';
Dot:                            '.';
PlusPlus:                       '++';
MinusMinus:                     '--';
Plus:                           '+';
Minus:                          '-';
BitNot:                         '~';
Not:                            '!';
Multiply:                       '*';
Divide:                         '/';
Modulus:                        '%';
LessThan:                       '<';
MoreThan:                       '>';
LessThanEquals:                 '<=';
GreaterThanEquals:              '>=';
Equals:                        '==';
NotEquals:                      '!=';
IdentityEquals:                 '===';
IdentityNotEquals:              '!==';
BitAnd:                         '&';
BitXor:                         '^';
BitOr:                          '|';
And:                            '&&';
Or:                             '||';
MultiplyAssign:                 '*=';
DivideAssign:                   '/=';
ModulusAssign:                  '%=';
PlusAssign:                     '+=';
MinusAssign:                    '-=';
LeftShiftArithmeticAssign:      '<<=';
RightShiftArithmeticAssign:     '>>=';
RightShiftLogicalAssign:        '>>>=';
BitAndAssign:                   '&=';
BitXorAssign:                   '^=';
BitOrAssign:                    '|=';
Arrow:                          '=>';
NullCoalesce:                   '??';

/// Numeric Literals

DecimalLiteral:                 DecimalIntegerLiteral '.' FractionalPart? ExponentPart?
              |                 '.' FractionalPart ExponentPart?
              |                 DecimalIntegerLiteral ExponentPart?
              ;

/// Numeric Literals

HexIntegerLiteral:              '0' [xX] (
                                      HexDigit
                                    | HexDigit (HexDigit | '_')* HexDigit
                                 );
OctalIntegerLiteral:            '0' [oO] (
                                      [0-7]
                                    | [0-7] [0-7_]* [0-7]
                                 );
BinaryIntegerLiteral:           '0' [bB] (
                                      [01]
                                    | [01] [01_]* [01]
                                 );

/// Keywords
Abstract:                       'abstract';
As:                             'as';
Assert:                         'assert';
Async:                          'async';
Await:                          'await';
Break:                          'break';
Case:                           'case';
Class:                          'class';
Const:                          'const';
Constructor:                    'constructor';
Continue:                       'continue';
Defer:                          'defer';
Do:                             'do';
Else:                           'else';
Enum:                           'enum';
Export:                         'export';
False:                          'false';
For:                            'for';
Function:                       'function';
If:                             'if';
Import:                         'import';
Inner:                          'inner';
Instanceof:                     'instanceof';
Interface:                      'interface' ;
Launch:                         'launch';
Let:                            'let' ;
Namespace:                      'namespace';
Native:                         'native';
New:                            'new';
Null:                           'null';
Open:                           'open';
Override:                       'override';
Package:                        'package';
Panic:                          'panic';
Private:                        'private' ;
Protected:                      'protected' ;
Public:                         'public' ;
Return:                         'return';
Static:                         'static' ;
Switch:                         'switch';
Super:                          'super';
This:                           'this';
Throw:                          'throw';
True:                           'true';
Try:                            'try';
Type:                           'type';
While:                          'while';

/// Identifier Names and Identifiers
Identifier:                     IdentifierStart IdentifierPart*;

/// String Literals
StringLiteral:                 '"' DoubleStringCharacter* '"' {this.ProcessStringLiteral();}
             ;

CharLiteral: '\'' SingleCharacter '\'';

WhiteSpaces:                    [\t\u000B\u000C\u0020\u00A0\ufeff]+ -> channel(HIDDEN);
LineTerminator:                 [\r\n\u2028\u2029] -> channel(HIDDEN);

/// Comments
HtmlComment:                    '<!--' .*? '-->' -> channel(HIDDEN);
CDataComment:                   '<![CDATA[' .*? ']]>' -> channel(HIDDEN);
UnexpectedCharacter:            . -> channel(ERROR);

// Fragment rules

fragment DoubleStringCharacter
    : ~["\\\r\n]
    | '\\' EscapeSequence
    | LineContinuation
    ;

fragment SingleCharacter
    : ~['\\\r\n]
    | '\\' EscapeSequence
    | LineContinuation
    ;

fragment EscapeSequence
    : CharacterEscapeSequence
    | '0' // no digit ahead! TODO
    | HexEscapeSequence
    | UnicodeEscapeSequence
    | ExtendedUnicodeEscapeSequence
    ;

fragment CharacterEscapeSequence
    : SingleEscapeCharacter
    | NonEscapeCharacter
    ;

fragment HexEscapeSequence
    : 'x' HexDigit HexDigit
    ;

fragment UnicodeEscapeSequence
    : 'u' HexDigit HexDigit HexDigit HexDigit
    ;

fragment ExtendedUnicodeEscapeSequence
    : 'u' '{' HexDigit+ '}'
    ;

fragment SingleEscapeCharacter
    : ['"\\bfnrtv]
    ;

fragment NonEscapeCharacter
    : ~['"\\bfnrtv0-9xu\r\n]
    ;

fragment EscapeCharacter
    : SingleEscapeCharacter
    | [0-9]
    | [xu]
    ;

fragment LineContinuation
    : '\\' [\r\n\u2028\u2029]
    ;

fragment HexDigit
    : [0-9a-fA-F]
    ;

fragment DecimalIntegerLiteral
    : [0-9]
    | [1-9] [0-9_]* [0-9]
    ;

fragment FractionalPart
    : [0-9]
    | [0-9] [0-9_]* [0-9]
    ;

fragment ExponentPart
    : [eE] [+-]? DecimalIntegerLiteral
    ;

fragment IdentifierPart
    : [\p{ID_Continue}]
    | '$'
    | [\u200C\u200D]
    | '\\' UnicodeEscapeSequence
    ;

fragment IdentifierStart
    : [\p{ID_Start}]
    | [$_]
    | '\\' UnicodeEscapeSequence
    ;
