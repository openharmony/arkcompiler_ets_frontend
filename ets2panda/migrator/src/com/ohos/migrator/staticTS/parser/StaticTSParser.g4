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
/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 by Bart Kiers (original author) and Alexandre Vitorelli (contributor -> ported to CSharp)
 * Copyright (c) 2017 by Ivan Kochurkin (Positive Technologies):
    added ECMAScript 6 support, cleared and transformed to the universal grammar.
 * Copyright (c) 2018 by Juan Alvarez (contributor -> ported to Go)
 * Copyright (c) 2019 by Andrii Artiushok (contributor -> added TypeScript support)
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
parser grammar StaticTSParser;

options {
    tokenVocab=StaticTSLexer;
    superClass=StaticTSParserBase;
    contextSuperClass=StaticTSContextBase;
}

compilationUnit
    : packageDeclaration? importDeclaration* topDeclaration* EOF
    ;

packageDeclaration
    : Package qualifiedName SemiColon?
    ;

importDeclaration
    : Import importBinding (Comma importBinding)* Comma?
      { this.next(StaticTSParser.FROM) }? Identifier StringLiteral SemiColon?
    ;

importBinding
    : (Multiply | qualifiedName (Dot Multiply)?) (As Identifier)?
    ;

qualifiedName
    : Identifier (Dot Identifier)*
    ;

topDeclaration
    : Export?
    (
          classDeclaration
        | interfaceDeclaration
        | enumDeclaration
        | functionDeclaration
        | variableOrConstantDeclaration
        | typeAliasDeclaration
        | namespaceDeclaration
    )
    ;

// Namespaces
namespaceDeclaration
    : Namespace Identifier namespaceBody
    ;

namespaceBody
    : OpenBrace namespaceMember* CloseBrace
    ;

// Don't allow nested namespaces for the moment
namespaceMember
    : Export?
    (
          classDeclaration
        | interfaceDeclaration
        | enumDeclaration
        | functionDeclaration
        | variableOrConstantDeclaration
        | typeAliasDeclaration
    )
    ;

// Classes
classDeclaration
    : (Inner? (Abstract | Open) | (Abstract | Open)? Inner)?
      Class { !this.predefinedTypeAhead() }? Identifier typeParameters?
      classExtendsClause? implementsClause? classBody
    ;

accessibilityModifier
    : Public
    | Private
    | Protected
    ;

classExtendsClause
    : { this.next(StaticTSParser.EXTENDS) }? Identifier typeReference
    ;

implementsClause
    : { this.next(StaticTSParser.IMPLEMENTS) }? Identifier interfaceTypeList
    ;

classBody
    :  OpenBrace classMember* clinit=classInitializer? classMember* CloseBrace
    ;

classMember
    : accessibilityModifier?
    (
          constructorDeclaration
        | classFieldDeclaration
        | classMethodDeclaration
        | classGetterDeclaration
        | classSetterDeclaration
        | interfaceDeclaration
        | enumDeclaration
        | classDeclaration
    )
    ;

constructorDeclaration
    : Constructor typeParameters? OpenParen parameterList? CloseParen throwsAnnotation? constructorBody
    ;

parameterList
    : parameter (Comma parameter)* (Comma variadicParameter)?
    | variadicParameter
    ;

parameter
    : Identifier typeAnnotation initializer?
    ;

variadicParameter
    : Ellipsis Identifier typeAnnotation
    ;

typeAnnotation
    : Colon primaryType
    ;

constructorBody
    : OpenBrace constructorCall? statementOrLocalDeclaration* CloseBrace
    ;

constructorCall
    :   This typeArguments? arguments
      | (singleExpression Dot)? Super typeArguments? arguments
    ;

statementOrLocalDeclaration
    : statement
    | variableOrConstantDeclaration
    | interfaceDeclaration
    | classDeclaration
    | enumDeclaration
    ;

classFieldDeclaration
    : Static? (variableDeclaration | {this.next(StaticTSParser.READONLY)}? Identifier constantDeclaration) SemiColon?
    | {this.next(StaticTSParser.READONLY)}? Identifier Static? constantDeclaration SemiColon?
    ;

initializer
    : Assign singleExpression
    ;

classMethodDeclaration
    : (Static | Override | Open)? Identifier signature block                        #ClassMethodWithBody
    | (Abstract | Static? Native | Native Static)? Identifier signature SemiColon?   #AbstractOrNativeClassMethod
    ;

classInitializer
    : Static block
    ;

signature
    : typeParameters? OpenParen parameterList? CloseParen typeAnnotation throwsAnnotation?
    ;

throwsAnnotation
    : { this.next(StaticTSParser.THROWS) || this.next(StaticTSParser.RETHROWS) }? Identifier
    ;

classGetterDeclaration
    : (Static | Override | Open)? getterHeader block
    | Abstract getterHeader SemiColon?
    ;

getterHeader
    : { this.next(StaticTSParser.GET) }? Identifier Identifier OpenParen CloseParen typeAnnotation
    ;

classSetterDeclaration
    : (Static | Override | Open)? setterHeader block
    | Abstract setterHeader
    ;

setterHeader
    : { this.next(StaticTSParser.SET) }? Identifier Identifier OpenParen parameter CloseParen
    ;

// Interfaces
interfaceDeclaration
    : Interface { !this.predefinedTypeAhead() }? Identifier typeParameters?
      interfaceExtendsClause? OpenBrace interfaceBody CloseBrace
    ;

interfaceExtendsClause
    : { this.next(StaticTSParser.EXTENDS) }? Identifier interfaceTypeList
    ;

interfaceTypeList
    : typeReference (Comma typeReference)*
    ;

interfaceBody
    : interfaceMember*
    ;

interfaceMember
    : Identifier signature SemiColon?                  #InterfaceMethod
    | (Static | Private)? Identifier signature block  #InterfaceMethodWithBody
    | ({this.next(StaticTSParser.READONLY)}? Identifier)?
      variableDeclaration SemiColon?                  #InterfaceField
    | getterHeader SemiColon?                         #InterfaceGetter
    | setterHeader SemiColon?                         #InterfaceSetter
    | interfaceDeclaration                            #InterfaceInInterface
    | classDeclaration                                #ClassInInterface
    | enumDeclaration                                 #EnumInInterface
    ;

// Enums
enumDeclaration
    : Enum { !this.predefinedTypeAhead() }? Identifier OpenBrace enumBody? CloseBrace
    ;

enumBody
    : enumMember (Comma enumMember)*
    ;

enumMember
    : Identifier (Assign singleExpression)?
    ;

// Functions
functionDeclaration
    : Async? Function Identifier signature block
    ;

// Type aliases
typeAliasDeclaration
    : Type { !this.predefinedTypeAhead() }? Identifier typeParameters? Assign primaryType SemiColon?
    ;

// Variables & constants
variableOrConstantDeclaration
    : ((Let variableDeclarationList) | (Const constantDeclarationList)) SemiColon?
    ;

variableDeclarationList
    : variableDeclaration (Comma variableDeclaration)*
    ;

constantDeclarationList
    : constantDeclaration (Comma constantDeclaration)*
    ;

variableDeclaration
    : Identifier typeAnnotation initializer?
    | Identifier initializer
    ;

constantDeclaration
    : Identifier typeAnnotation? initializer
    ;

// Types
intersectionType
    : OpenParen typeReference (BitAnd typeReference)+ CloseParen
    ;

primaryType
    : predefinedType
    | typeReference
    | functionType
    | arrayType
    | nullableType
    ;

nullableType
    : (predefinedType | typeReference | functionType | arrayType | wildcardType) BitOr Null
    ;

predefinedType
    : { this.predefinedTypeAhead() }? Identifier
    ;

arrayType
    : (predefinedType | typeReference | functionType | (OpenParen nullableType CloseParen))
      {this.notLineTerminator()}? (OpenBracket CloseBracket)+
    ;

typeReference
    : typeReferencePart (Dot typeReferencePart)*
    ;

typeReferencePart
    : qualifiedName typeArguments?
    ;

functionType
    : OpenParen parameterList? CloseParen typeAnnotation throwsAnnotation?
    ;

// Generics
typeParameters
    : LessThan typeParameterList MoreThan
    ;

typeParameterList
    : typeParameter (Comma typeParameter)*
    ;

typeParameter
    : ({ this.next(StaticTSParser.IN) || this.next(StaticTSParser.OUT) }? Identifier)? Identifier constraint?
    ;

constraint
    : { this.next(StaticTSParser.EXTENDS) }? Identifier (typeReference | intersectionType)
    ;

typeArguments
    : LessThan typeArgumentList? MoreThan
    ;

typeArgumentList
    : typeArgument (Comma typeArgument)*
    ;

typeArgument
    : typeReference
    | arrayType
    | functionType
    | wildcardType
    | nullableType
    ;

wildcardType
    : { this.next(StaticTSParser.IN) }? Identifier typeReference
    | { this.next(StaticTSParser.OUT) }? Identifier typeReference?
    ;

// Statements
statement
    : block
    | assertStatement
    | ifStatement
    | iterationStatement
    | continueStatement
    | breakStatement
    | returnStatement
    | labelledStatement
    | switchStatement
    | throwStatement
    | deferStatement
    | tryStatement
    | expressionStatement
    ;

block
    : OpenBrace statementOrLocalDeclaration* CloseBrace
    ;

assertStatement
    : Assert condition=singleExpression (Colon message=singleExpression)? SemiColon?
    ;

ifStatement
    : If OpenParen singleExpression CloseParen ifStmt=statement (Else elseStmt=statement)?
    ;

iterationStatement
    : Do statement While OpenParen singleExpression CloseParen SemiColon?                                     # DoStatement
    | While OpenParen singleExpression CloseParen statement                                                  # WhileStatement
    | For OpenParen forInit? SemiColon singleExpression? SemiColon expressionSequence? CloseParen statement  # ForStatement
    | For OpenParen Let Identifier typeAnnotation? { this.next(StaticTSParser.OF) }? Identifier
      singleExpression CloseParen statement                                                                  # ForOfStatement
    ;

forInit
    : expressionSequence | Let variableDeclarationList
    ;

continueStatement
    : Continue ({this.notLineTerminator()}? Identifier)? SemiColon?
    ;

breakStatement
    : Break ({this.notLineTerminator()}? Identifier)? SemiColon?
    ;

returnStatement
    : Return ({this.notLineTerminator()}? singleExpression)? SemiColon?
    ;

labelledStatement
    : Identifier Colon statement
    ;

switchStatement
    : Switch OpenParen singleExpression CloseParen caseBlock
    ;

caseBlock
    : OpenBrace leftCases=caseClauses? defaultClause? rightCases=caseClauses? CloseBrace
    ;

caseClauses
    : caseClause+
    ;

caseClause
    : Case singleExpression ':' statement*
    ;

defaultClause
    : { this.next(StaticTSParser.DEFAULT) }? Identifier ':' statement*
    ;

throwStatement
    : Throw {this.notLineTerminator()}? singleExpression SemiColon?
    ;

tryStatement
    : Try block (catchClause+ | catchClause* defaultCatch)
    ;

catchClause
    : { this.next(StaticTSParser.CATCH) }? Identifier exceptionParameter block
    ;

exceptionParameter
    : OpenParen Identifier typeAnnotation CloseParen
    ;

defaultCatch
    : { this.next(StaticTSParser.CATCH) }? Identifier (OpenParen Identifier CloseParen)? block
    ;

deferStatement
    : Defer statement
    ;

expressionStatement
    : {this.notOpenBraceAndNotFunction()}? singleExpression SemiColon?
    ;

// Expressions
singleExpression
    : OpenParen parameterList? CloseParen typeAnnotation throwsAnnotation? Arrow lambdaBody    # LambdaExpression
    | singleExpression (QuestionMark Dot)? indexExpression                   # ArrayAccessExpression
    | singleExpression QuestionMark? Dot Identifier                          # MemberAccessExpression
    | New typeArguments? typeReference arguments? classBody?                 # NewClassInstanceExpression
    | singleExpression Dot New typeArguments? typeReference arguments? classBody? # NewInnerClassInstanceExpression
    | New primaryType indexExpression+ (OpenBracket CloseBracket)*           # NewArrayExpression
    | singleExpression typeArguments? (QuestionMark Dot)? arguments          # CallExpression
    | singleExpression {this.notLineTerminator()}? PlusPlus                  # PostIncrementExpression
    | singleExpression {this.notLineTerminator()}? MinusMinus                # PostDecreaseExpression
    | singleExpression {this.notLineTerminator()}? Not                       # NonNullExpression
    | PlusPlus singleExpression                                              # PreIncrementExpression
    | MinusMinus singleExpression                                            # PreDecreaseExpression
    | Plus singleExpression                                                  # UnaryPlusExpression
    | Minus singleExpression                                                 # UnaryMinusExpression
    | BitNot singleExpression                                                # BitNotExpression
    | Not singleExpression                                                   # NotExpression
    | singleExpression (Multiply | Divide | Modulus) singleExpression        # MultiplicativeExpression
    | singleExpression (Plus | Minus) singleExpression                       # AdditiveExpression
    | singleExpression shiftOperator singleExpression                        # BitShiftExpression
    | singleExpression (LessThan | MoreThan |
                        LessThanEquals | GreaterThanEquals) singleExpression # RelationalExpression
    | singleExpression Instanceof primaryType                                # InstanceofExpression
    | singleExpression (Equals | NotEquals |
                        IdentityEquals | IdentityNotEquals) singleExpression # EqualityExpression
    | singleExpression BitAnd singleExpression                               # BitAndExpression
    | singleExpression BitXor singleExpression                               # BitXOrExpression
    | singleExpression BitOr singleExpression                                # BitOrExpression
    | singleExpression And singleExpression                                  # LogicalAndExpression
    | singleExpression Or singleExpression                                   # LogicalOrExpression
    | singleExpression QuestionMark singleExpression Colon singleExpression  # TernaryExpression
    | singleExpression NullCoalesce singleExpression                         # NullCoalescingExpression
    | singleExpression Assign singleExpression                               # AssignmentExpression
    | singleExpression assignmentOperator singleExpression                   # AssignmentOperatorExpression
    | (typeReference Dot)? This                                              # ThisExpression
    | Identifier                                                             # IdentifierExpression
    | (typeReference Dot)? Super                                             # SuperExpression
    | literal                                                                # LiteralExpression
    | OpenBracket expressionSequence? CloseBracket                           # ArrayLiteralExpression
    | primaryType Dot Class                                                  # ClassLiteralExpression
    | OpenBrace nameValueSequence? CloseBrace                                # ClassCompositeExpression
    | OpenParen singleExpression CloseParen                                  # ParenthesizedExpression
    | singleExpression As (intersectionType | primaryType)                   # CastExpression
    | Await singleExpression                                                 # AwaitExpression
    ;


// Using '<<', '>>' and '>>>' tokens for shift operators may lead to
// an ambiguity between '>>' (or '>>>') and multiple closing triangle
// brackets used for nested type arguments, as the ANTLR lexer/parser
// has a greedy matching and will always prefer single token '>>' over
// the token sequence '>' '>'.
// To work around this, create a separate rule for shift operators and
// parse operator with a sequence of '<' and '>' tokens. Additionally,
// check that tokens have nothing between them by comparing token indices.
shiftOperator
    : first=LessThan second=LessThan {$first.index + 1 == $second.index}?
    | first=MoreThan second=MoreThan {$first.index + 1 == $second.index}?
    | first=MoreThan second=MoreThan third=MoreThan {$first.index + 1 == $second.index && $second.index + 1 == $third.index}?
    ;

lambdaBody
    : singleExpression
    | block
    ;

arguments
    : OpenParen expressionSequence? CloseParen
    ;

expressionSequence
    : singleExpression (Comma singleExpression)*
    ;

nameValueSequence
    : nameValuePair (Comma nameValuePair)*
    ;

nameValuePair
    : Identifier Colon singleExpression
    ;

indexExpression
    : OpenBracket singleExpression CloseBracket
    ;

assignmentOperator
    : MultiplyAssign
    | DivideAssign
    | ModulusAssign
    | PlusAssign
    | MinusAssign
    | LeftShiftArithmeticAssign
    | RightShiftArithmeticAssign
    | RightShiftLogicalAssign
    | BitAndAssign
    | BitXorAssign
    | BitOrAssign
    ;

literal
    : Null
    | True
    | False
    | StringLiteral
    | CharLiteral
    | numericLiteral
    ;

numericLiteral
    : DecimalLiteral
    | HexIntegerLiteral
    | OctalIntegerLiteral
    | BinaryIntegerLiteral
    ;
