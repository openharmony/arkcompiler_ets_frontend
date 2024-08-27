/**
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "ETSparser.h"
#include "ETSNolintParser.h"
#include <utility>

#include "macros.h"
#include "parser/parserFlags.h"
#include "parser/parserStatusContext.h"
#include "util/helpers.h"
#include "util/language.h"
#include "utils/arena_containers.h"
#include "varbinder/varbinder.h"
#include "varbinder/ETSBinder.h"
#include "lexer/lexer.h"
#include "lexer/ETSLexer.h"
#include "checker/types/ets/etsEnumType.h"
#include "ir/astNode.h"
#include "ir/base/classDefinition.h"
#include "ir/base/decorator.h"
#include "ir/base/catchClause.h"
#include "ir/base/classProperty.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/classStaticBlock.h"
#include "ir/base/spreadElement.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/functionExpression.h"
#include "ir/statements/functionDeclaration.h"
#include "ir/statements/expressionStatement.h"
#include "ir/statements/classDeclaration.h"
#include "ir/statements/variableDeclarator.h"
#include "ir/statements/variableDeclaration.h"
#include "ir/expressions/dummyNode.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/thisExpression.h"
#include "ir/expressions/typeofExpression.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/updateExpression.h"
#include "ir/expressions/arrowFunctionExpression.h"
#include "ir/expressions/unaryExpression.h"
#include "ir/expressions/yieldExpression.h"
#include "ir/expressions/awaitExpression.h"
#include "ir/expressions/literals/nullLiteral.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/expressions/literals/undefinedLiteral.h"
#include "ir/module/importDeclaration.h"
#include "ir/module/importDefaultSpecifier.h"
#include "ir/module/importSpecifier.h"
#include "ir/module/exportSpecifier.h"
#include "ir/module/exportNamedDeclaration.h"
#include "ir/statements/assertStatement.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/ifStatement.h"
#include "ir/statements/labelledStatement.h"
#include "ir/statements/switchStatement.h"
#include "ir/statements/throwStatement.h"
#include "ir/statements/tryStatement.h"
#include "ir/statements/whileStatement.h"
#include "ir/statements/forOfStatement.h"
#include "ir/statements/doWhileStatement.h"
#include "ir/statements/breakStatement.h"
#include "ir/statements/debuggerStatement.h"
#include "ir/ets/etsLaunchExpression.h"
#include "ir/ets/etsClassLiteral.h"
#include "ir/ets/etsPrimitiveType.h"
#include "ir/ets/etsPackageDeclaration.h"
#include "ir/ets/etsReExportDeclaration.h"
#include "ir/ets/etsWildcardType.h"
#include "ir/ets/etsNewArrayInstanceExpression.h"
#include "ir/ets/etsTuple.h"
#include "ir/ets/etsFunctionType.h"
#include "ir/ets/etsNewClassInstanceExpression.h"
#include "ir/ets/etsNewMultiDimArrayInstanceExpression.h"
#include "ir/ets/etsScript.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/ets/etsNullishTypes.h"
#include "ir/ets/etsUnionType.h"
#include "ir/ets/etsImportSource.h"
#include "ir/ets/etsImportDeclaration.h"
#include "ir/ets/etsStructDeclaration.h"
#include "ir/ets/etsParameterExpression.h"
#include "ir/module/importNamespaceSpecifier.h"
#include "ir/ts/tsAsExpression.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "ir/ts/tsEnumDeclaration.h"
#include "ir/ts/tsTypeParameterInstantiation.h"
#include "ir/ts/tsInterfaceBody.h"
#include "ir/ts/tsImportEqualsDeclaration.h"
#include "ir/ts/tsArrayType.h"
#include "ir/ts/tsQualifiedName.h"
#include "ir/ts/tsTypeReference.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ts/tsInterfaceHeritage.h"
#include "ir/ts/tsFunctionType.h"
#include "ir/ts/tsClassImplements.h"
#include "ir/ts/tsEnumMember.h"
#include "ir/ts/tsTypeAliasDeclaration.h"
#include "ir/ts/tsTypeParameterDeclaration.h"
#include "ir/ts/tsNonNullExpression.h"
#include "ir/ts/tsThisType.h"
#include "generated/signatures.h"

namespace ark::es2panda::parser {
class FunctionContext;

using namespace std::literals::string_literals;

// NOLINTNEXTLINE(google-default-arguments)
ir::Statement *ETSParser::ParseEnumDeclaration(bool isConst, bool isStatic)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::KEYW_ENUM);

    lexer::SourcePosition enumStart = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat enum keyword

    auto *key = ExpectIdentifier(false, true);

    auto *declNode = ParseEnumMembers(key, enumStart, isConst, isStatic);

    return declNode;
}

ir::Statement *ETSParser::ParsePotentialConstEnum(VariableParsingFlags flags)
{
    if ((flags & VariableParsingFlags::CONST) == 0) {
        ThrowSyntaxError("Variable declaration expected.");
    }

    return ParseEnumDeclaration(true);
}

// NOLINTBEGIN(cert-err58-cpp)
static std::string const INVALID_ENUM_TYPE = "Invalid enum initialization type"s;
static std::string const INVALID_ENUM_VALUE = "Invalid enum initialization value"s;
static std::string const MISSING_COMMA_IN_ENUM = "Missing comma between enum constants"s;
static std::string const TRAILING_COMMA_IN_ENUM = "Trailing comma is not allowed in enum constant list"s;
// NOLINTEND(cert-err58-cpp)

// Helper for ETSParser::ParseEnumMembers()
bool ETSParser::IsStringEnum()
{
    // Get the underlying type of enum (number or string). It is defined from the first element ONLY!
    Lexer()->NextToken();
    auto tokenType = Lexer()->GetToken().Type();
    while (tokenType != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE && tokenType != lexer::TokenType::PUNCTUATOR_COMMA) {
        if (tokenType == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
            Lexer()->NextToken();
            if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_STRING) {
                return true;
            }
        }
        Lexer()->NextToken();
        tokenType = Lexer()->GetToken().Type();
    }
    return false;
}

ir::TSEnumDeclaration *ETSParser::ParseEnumMembers(ir::Identifier *const key, const lexer::SourcePosition &enumStart,
                                                   const bool isConst, const bool isStatic)
{
    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        LogExpectedToken(lexer::TokenType::PUNCTUATOR_LEFT_BRACE);
    }

    Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat '{'

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        ThrowSyntaxError("An enum must have at least one enum constant");
    }

    // Get the underlying type of enum (number or string). It is defined from the first element ONLY!
    auto const pos = Lexer()->Save();
    const bool stringTypeEnum = IsStringEnum();
    Lexer()->Rewind(pos);

    ArenaVector<ir::AstNode *> members(Allocator()->Adapter());

    if (stringTypeEnum) {
        ParseStringEnum(members);
    } else {
        ParseNumberEnum(members);
    }

    auto *const enumDeclaration = AllocNode<ir::TSEnumDeclaration>(
        Allocator(), key, std::move(members),
        ir::TSEnumDeclaration::ConstructorFlags {isConst, isStatic, InAmbientContext()});
    enumDeclaration->SetRange({enumStart, Lexer()->GetToken().End()});
    if (InAmbientContext()) {
        enumDeclaration->AddModifier(ir::ModifierFlags::DECLARE);
    }

    Lexer()->NextToken();  // eat '}'

    return enumDeclaration;
}

bool ETSParser::ParseNumberEnumEnd()
{
    bool isBreak = false;
    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COMMA) {
        // enum5.sts
        LogSyntaxError(MISSING_COMMA_IN_ENUM);
        if (lexer::Token::IsPunctuatorToken((Lexer()->GetToken().Type()))) {
            /*  enum Direction {
                  Left = -1;
                  Right = 1",
                }*/
            Lexer()->GetToken().SetTokenType(lexer::TokenType::PUNCTUATOR_COMMA);
            Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat ','
        }
        /* in another case just skip the token
            enum Direction {
              Left = -1
              Right = 1,
            }
        */
    } else {
        Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat ','
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        isBreak = true;
    }
    return isBreak;
}

bool ETSParser::ParseNumberEnumHelper()
{
    bool minusSign = false;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PLUS) {
        Lexer()->NextToken();
    } else if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MINUS) {
        minusSign = true;
        Lexer()->NextToken();
    }

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_NUMBER) {
        // enum15.sts; will be zero by default
        LogSyntaxError(INVALID_ENUM_TYPE);
        Lexer()->GetToken().SetTokenType(lexer::TokenType::LITERAL_NUMBER);
        Lexer()->GetToken().SetTokenStr(ERROR_LITERAL);
    }
    return minusSign;
}

void ETSParser::ParseNumberEnum(ArenaVector<ir::AstNode *> &members)
{
    checker::ETSIntEnumType::ValueType currentValue {};

    // Lambda to parse enum member (maybe with initializer)
    auto const parseMember = [this, &members, &currentValue]() {
        auto *const ident = ExpectIdentifier(false, true);

        ir::NumberLiteral *ordinal;
        lexer::SourcePosition endLoc;

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
            // Case when user explicitly set the value for enumeration constant

            bool minusSign = false;

            Lexer()->NextToken();
            minusSign = ParseNumberEnumHelper();

            ordinal = ParseNumberLiteral()->AsNumberLiteral();
            if (minusSign) {
                ordinal->Number().Negate();
            }
            if (!ordinal->Number().CanGetValue<checker::ETSIntEnumType::ValueType>()) {
                ThrowSyntaxError(INVALID_ENUM_VALUE);
            }

            currentValue = ordinal->Number().GetValue<checker::ETSIntEnumType::ValueType>();

            endLoc = ordinal->End();
        } else {
            // Default enumeration constant value. Equal to 0 for the first item and = previous_value + 1 for all
            // the others.

            ordinal = AllocNode<ir::NumberLiteral>(lexer::Number(currentValue));

            endLoc = ident->End();
        }

        auto *const member = AllocNode<ir::TSEnumMember>(ident, ordinal);
        member->SetRange({ident->Start(), endLoc});
        members.emplace_back(member);

        ++currentValue;
    };

    parseMember();

    while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        if (ParseNumberEnumEnd()) {
            break;
        }

        parseMember();
    }
}

void ETSParser::ParseStringEnum(ArenaVector<ir::AstNode *> &members)
{
    // Lambda to parse enum member (maybe with initializer)
    auto const parseMember = [this, &members]() {
        auto *const ident = ExpectIdentifier();

        ir::StringLiteral *itemValue;

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
            // Case when user explicitly set the value for enumeration constant

            Lexer()->NextToken();
            if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_STRING) {
                // enum24.sts; will be set as "0" by default
                LogSyntaxError(INVALID_ENUM_TYPE);
                Lexer()->GetToken().SetTokenType(lexer::TokenType::LITERAL_STRING);
                Lexer()->GetToken().SetTokenStr(ERROR_LITERAL);
            }

            itemValue = ParseStringLiteral();
        } else {
            // Default item value is not allowed for string type enumerations!
            ThrowSyntaxError("All items of string-type enumeration should be explicitly initialized.");
        }

        auto *const member = AllocNode<ir::TSEnumMember>(ident, itemValue);
        member->SetRange({ident->Start(), itemValue->End()});
        members.emplace_back(member);
    };

    parseMember();

    while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COMMA) {
            // enum5.sts
            LogSyntaxError(MISSING_COMMA_IN_ENUM);
            if (lexer::Token::IsPunctuatorToken((Lexer()->GetToken().Type()))) {
                /*  enum Direction {
                      Left = "LEFT";
                      Right = "RIGHT",
                    }*/
                Lexer()->GetToken().SetTokenType(lexer::TokenType::PUNCTUATOR_COMMA);
                Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat ','
            }
            /* in another case just skip the token
                enum Direction {
                  Left = "LEFT"
                  Right = "RIGHT",
                }
            */
        } else {
            Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat ','
        }

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
            ThrowSyntaxError(TRAILING_COMMA_IN_ENUM);
        }

        parseMember();
    }
}

}  // namespace ark::es2panda::parser
