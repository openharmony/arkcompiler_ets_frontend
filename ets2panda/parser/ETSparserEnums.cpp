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
        LogSyntaxError("Variable declaration expected.");
    }

    // According to the ArkTS specification:
    // const enum is supported for source-level compatibility with TypeScript,
    // and const is skipped as it has no impact on enum semantics in ArkTS.
    return ParseEnumDeclaration(false);
}

// NOLINTBEGIN(cert-err58-cpp)
static std::string const INVALID_ENUM_TYPE = "Invalid enum initialization type"s;
static std::string const INVALID_ENUM_VALUE = "Invalid enum initialization value"s;
static std::string const INVALID_STRING_ENUM_OP_TYPE = "Invalid operational type for string enum"s;
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
        LogSyntaxError("An enum must have at least one enum constant");
        return nullptr;  // Error processing.
    }

    // Get the underlying type of enum (number or string). It is defined from the first element ONLY!
    auto const pos = Lexer()->Save();
    const bool stringTypeEnum = IsStringEnum();
    Lexer()->Rewind(pos);

    ArenaVector<ir::AstNode *> members(Allocator()->Adapter());

    lexer::SourcePosition enumEnd;
    if (stringTypeEnum) {
        enumEnd = ParseStringEnum(members);
    } else {
        enumEnd = ParseNumberEnum(members);
    }

    auto *const enumDeclaration = AllocNode<ir::TSEnumDeclaration>(
        Allocator(), key, std::move(members),
        ir::TSEnumDeclaration::ConstructorFlags {isConst, isStatic, InAmbientContext()});
    if (InAmbientContext()) {
        enumDeclaration->AddModifier(ir::ModifierFlags::DECLARE);
    }
    enumDeclaration->SetRange({enumStart, enumEnd});

    return enumDeclaration;
}

ir::Expression *ETSParser::ParseNumberEnumExpression()
{
    std::function<void(ir::AstNode *)> validateIntLiteral = [this, &validateIntLiteral](ir::AstNode *node) {
        if (node->IsIdentifier()) {
            LogSyntaxError(INVALID_ENUM_TYPE, node->Start());
        }
        if (node->IsExpression() && node->AsExpression()->IsLiteral() &&
            (!node->IsNumberLiteral() ||
             !node->AsNumberLiteral()->Number().CanGetValue<checker::ETSIntEnumType::ValueType>())) {
            LogSyntaxError(INVALID_ENUM_VALUE, node->Start());
        }
        node->Iterate(validateIntLiteral);
    };

    ir::Expression *intExpression {};
    auto endLoc = Lexer()->GetToken().Start();
    intExpression = ParseExpression();
    if (intExpression == nullptr) {
        LogSyntaxError(INVALID_ENUM_VALUE, endLoc);
        // Continue to parse the rest of Enum.
        return AllocNode<ir::NumberLiteral>(lexer::Number(0));
    }
    validateIntLiteral(intExpression);
    return intExpression;
}

ir::Expression *ETSParser::ParseStringEnumExpression()
{
    std::function<void(ir::AstNode *)> validateStringLiteral = [this, &validateStringLiteral](ir::AstNode *node) {
        if (node->IsBinaryExpression() &&
            node->AsBinaryExpression()->OperatorType() != lexer::TokenType::PUNCTUATOR_PLUS) {
            LogSyntaxError(INVALID_STRING_ENUM_OP_TYPE, node->AsBinaryExpression()->Left()->End());
        }
        if (node->IsIdentifier() ||
            (node->IsExpression() && node->AsExpression()->IsLiteral() && !node->IsStringLiteral())) {
            LogSyntaxError(INVALID_ENUM_TYPE, node->Start());
        }
        node->Iterate(validateStringLiteral);
    };

    ir::Expression *stringExpression {};
    auto endLoc = Lexer()->GetToken().Start();
    stringExpression = ParseExpression();
    if (stringExpression == nullptr) {
        LogSyntaxError(INVALID_ENUM_VALUE, endLoc);
        // Continue to parse the rest of Enum.
        return AllocNode<ir::StringLiteral>();
    }
    validateStringLiteral(stringExpression);
    return stringExpression;
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

lexer::SourcePosition ETSParser::ParseNumberEnum(ArenaVector<ir::AstNode *> &members)
{
    // Default enum number value
    ir::Expression *currentNumberExpr = AllocNode<ir::NumberLiteral>(lexer::Number(0));

    // Lambda to parse enum member (maybe with initializer)
    auto const parseMember = [this, &members, &currentNumberExpr]() {
        auto *const ident = ExpectIdentifier(false, true);

        ir::Expression *ordinal;
        lexer::SourcePosition endLoc;

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
            // Case when user explicitly set the value for enumeration constant
            Lexer()->NextToken();

            ordinal = ParseNumberEnumExpression();
            currentNumberExpr = ordinal;

            endLoc = ordinal->End();
        } else {
            // Default enumeration constant value. Equal to 0 for the first item and = previous_value + 1 for all
            // the others.
            ordinal = currentNumberExpr;

            endLoc = ident->End();
        }

        auto *const member = AllocNode<ir::TSEnumMember>(ident, ordinal);
        member->SetRange({ident->Start(), endLoc});
        members.emplace_back(member);

        // Increment the value by one
        auto incrementNode = AllocNode<ir::NumberLiteral>(lexer::Number(1));
        ir::Expression *dummyNode = currentNumberExpr->Clone(Allocator(), nullptr)->AsExpression();
        currentNumberExpr =
            AllocNode<ir::BinaryExpression>(dummyNode, incrementNode, lexer::TokenType::PUNCTUATOR_PLUS);
        return true;
    };

    lexer::SourcePosition enumEnd;
    ParseList(lexer::TokenType::PUNCTUATOR_RIGHT_BRACE, lexer::NextTokenFlags::KEYWORD_TO_IDENT, parseMember, &enumEnd,
              true);
    return enumEnd;
}

lexer::SourcePosition ETSParser::ParseStringEnum(ArenaVector<ir::AstNode *> &members)
{
    // Lambda to parse enum member (maybe with initializer)
    auto const parseMember = [this, &members]() {
        auto *const ident = ExpectIdentifier();

        ir::Expression *itemValue;

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
            // Case when user explicitly set the value for enumeration constant

            Lexer()->NextToken();

            itemValue = ParseStringEnumExpression();
        } else {
            // Default item value is not allowed for string type enumerations!
            LogSyntaxError("All items of string-type enumeration should be explicitly initialized.");
            return false;  // Error processing.
        }

        auto *const member = AllocNode<ir::TSEnumMember>(ident, itemValue);
        member->SetRange({ident->Start(), itemValue->End()});
        members.emplace_back(member);
        return true;
    };

    lexer::SourcePosition enumEnd;
    ParseList(lexer::TokenType::PUNCTUATOR_RIGHT_BRACE, lexer::NextTokenFlags::KEYWORD_TO_IDENT, parseMember, &enumEnd,
              true);
    return enumEnd;
}

}  // namespace ark::es2panda::parser
