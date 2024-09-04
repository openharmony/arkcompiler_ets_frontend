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

ir::Expression *ETSParser::ParseLaunchExpression(ExpressionParseFlags flags)
{
    lexer::SourcePosition start = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat launch

    ir::Expression *expr = ParseLeftHandSideExpression(flags);
    if (!expr->IsCallExpression()) {
        ThrowSyntaxError("Only call expressions are allowed after 'launch'", expr->Start());
    }
    auto call = expr->AsCallExpression();
    auto *launchExpression = AllocNode<ir::ETSLaunchExpression>(call);
    launchExpression->SetRange({start, call->End()});

    return launchExpression;
}

// NOLINTBEGIN(modernize-avoid-c-arrays)
static constexpr char const NO_DEFAULT_FOR_REST[] = "Rest parameter cannot have the default value.";
// NOLINTEND(modernize-avoid-c-arrays)

ir::Expression *ETSParser::ParseFunctionParameterExpression(ir::AnnotatedExpression *const paramIdent,
                                                            ir::ETSUndefinedType *defaultUndef)
{
    ir::ETSParameterExpression *paramExpression;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        if (paramIdent->IsRestElement()) {
            ThrowSyntaxError(NO_DEFAULT_FOR_REST);
        }

        auto const lexerPos = Lexer()->Save().Iterator();
        Lexer()->NextToken();  // eat '='

        if ((GetContext().Status() & ParserStatus::ALLOW_DEFAULT_VALUE) != 0) {
            ThrowSyntaxError("Default value is allowed only for optional parameters");
        }

        if (defaultUndef != nullptr) {
            ThrowSyntaxError("Not enable default value with default undefined");
        }
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS ||
            Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
            ThrowSyntaxError("You didn't set the value.");
        }

        paramExpression = AllocNode<ir::ETSParameterExpression>(paramIdent->AsIdentifier(), ParseExpression());

        std::string value = Lexer()->SourceView(lexerPos.Index(), Lexer()->Save().Iterator().Index()).Mutf8();
        while (value.back() == ' ') {
            value.pop_back();
        }
        if (value.back() == ')' || value.back() == ',') {
            value.pop_back();
        }
        paramExpression->SetLexerSaved(util::UString(value, Allocator()).View());

        paramExpression->SetRange({paramIdent->Start(), paramExpression->Initializer()->End()});
    } else if (paramIdent->IsIdentifier()) {
        auto *typeAnnotation = paramIdent->AsIdentifier()->TypeAnnotation();

        const auto typeAnnotationValue = [this, typeAnnotation,
                                          defaultUndef]() -> std::pair<ir::Expression *, std::string> {
            if (typeAnnotation == nullptr) {
                return std::make_pair(nullptr, "");
            }
            return std::make_pair(defaultUndef != nullptr ? AllocNode<ir::UndefinedLiteral>() : nullptr, "undefined");
        }();

        paramExpression =
            AllocNode<ir::ETSParameterExpression>(paramIdent->AsIdentifier(), std::get<0>(typeAnnotationValue));
        if (defaultUndef != nullptr) {
            paramExpression->SetLexerSaved(util::UString(std::get<1>(typeAnnotationValue), Allocator()).View());
        }
        paramExpression->SetRange({paramIdent->Start(), paramIdent->End()});
    } else {
        paramExpression = AllocNode<ir::ETSParameterExpression>(paramIdent->AsRestElement(), nullptr);
        paramExpression->SetRange({paramIdent->Start(), paramIdent->End()});
    }
    return paramExpression;
}

ir::Expression *ETSParser::ResolveArgumentUnaryExpr(ExpressionParseFlags flags)
{
    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::PUNCTUATOR_PLUS:
        case lexer::TokenType::PUNCTUATOR_MINUS:
        case lexer::TokenType::PUNCTUATOR_TILDE:
        case lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK:
        case lexer::TokenType::PUNCTUATOR_DOLLAR_DOLLAR:
        case lexer::TokenType::PUNCTUATOR_PLUS_PLUS:
        case lexer::TokenType::PUNCTUATOR_MINUS_MINUS:
        case lexer::TokenType::KEYW_TYPEOF: {
            return ParseUnaryOrPrefixUpdateExpression();
        }
        default: {
            return ParseLeftHandSideExpression(flags);
        }
    }
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ETSParser::ParseUnaryOrPrefixUpdateExpression(ExpressionParseFlags flags)
{
    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::PUNCTUATOR_PLUS_PLUS:
        case lexer::TokenType::PUNCTUATOR_MINUS_MINUS:
        case lexer::TokenType::PUNCTUATOR_PLUS:
        case lexer::TokenType::PUNCTUATOR_MINUS:
        case lexer::TokenType::PUNCTUATOR_TILDE:
        case lexer::TokenType::PUNCTUATOR_DOLLAR_DOLLAR:
        case lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK:
        case lexer::TokenType::KEYW_TYPEOF: {
            break;
        }
        case lexer::TokenType::KEYW_LAUNCH: {
            return ParseLaunchExpression(flags);
        }
        default: {
            return ParseLeftHandSideExpression(flags);
        }
    }

    lexer::TokenType operatorType = Lexer()->GetToken().Type();
    auto start = Lexer()->GetToken().Start();
    Lexer()->NextToken();

    ir::Expression *argument = ResolveArgumentUnaryExpr(flags);

    if (lexer::Token::IsUpdateToken(operatorType)) {
        if (!argument->IsIdentifier() && !argument->IsMemberExpression()) {
            ThrowSyntaxError("Invalid left-hand side in prefix operation");
        }
    }

    lexer::SourcePosition end = argument->End();

    ir::Expression *returnExpr = nullptr;
    if (lexer::Token::IsUpdateToken(operatorType)) {
        returnExpr = AllocNode<ir::UpdateExpression>(argument, operatorType, true);
    } else if (operatorType == lexer::TokenType::KEYW_TYPEOF) {
        returnExpr = AllocNode<ir::TypeofExpression>(argument);
    } else {
        returnExpr = AllocNode<ir::UnaryExpression>(argument, operatorType);
    }

    returnExpr->SetRange({start, end});

    return returnExpr;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ETSParser::ParseDefaultPrimaryExpression(ExpressionParseFlags flags)
{
    auto startLoc = Lexer()->GetToken().Start();
    auto savedPos = Lexer()->Save();
    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::POTENTIAL_CLASS_LITERAL |
                                           TypeAnnotationParsingOptions::IGNORE_FUNCTION_TYPE |
                                           TypeAnnotationParsingOptions::DISALLOW_UNION;
    ir::TypeNode *potentialType = ParseTypeAnnotation(&options);

    if (potentialType != nullptr) {
        if (potentialType->IsTSArrayType()) {
            return potentialType;
        }

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD) {
            Lexer()->NextToken();  // eat '.'
        }

        if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_CLASS || IsStructKeyword()) {
            Lexer()->NextToken();  // eat 'class' and 'struct'
            auto *classLiteral = AllocNode<ir::ETSClassLiteral>(potentialType);
            classLiteral->SetRange({startLoc, Lexer()->GetToken().End()});
            return classLiteral;
        }
    }

    Lexer()->Rewind(savedPos);

    Lexer()->NextToken();
    bool pretendArrow = Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_ARROW;
    Lexer()->Rewind(savedPos);

    if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT && !pretendArrow) {
        return ParsePrimaryExpressionIdent(flags);
    }

    ThrowSyntaxError({"Unexpected token '", lexer::TokenToString(Lexer()->GetToken().Type()), "'."});
    return nullptr;
}

ir::Expression *ETSParser::ParsePrimaryExpressionWithLiterals(ExpressionParseFlags flags)
{
    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::LITERAL_TRUE:
        case lexer::TokenType::LITERAL_FALSE: {
            return ParseBooleanLiteral();
        }
        case lexer::TokenType::LITERAL_NULL: {
            return ParseNullLiteral();
        }
        case lexer::TokenType::KEYW_UNDEFINED: {
            return ParseUndefinedLiteral();
        }
        case lexer::TokenType::LITERAL_NUMBER: {
            return ParseCoercedNumberLiteral();
        }
        case lexer::TokenType::LITERAL_STRING: {
            return ParseStringLiteral();
        }
        case lexer::TokenType::LITERAL_CHAR: {
            return ParseCharLiteral();
        }
        default: {
            return ParseDefaultPrimaryExpression(flags);
        }
    }
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ETSParser::ParsePrimaryExpression(ExpressionParseFlags flags)
{
    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS: {
            return ParseCoverParenthesizedExpressionAndArrowParameterList(flags);
        }
        case lexer::TokenType::KEYW_THIS: {
            return ParseThisExpression();
        }
        case lexer::TokenType::KEYW_SUPER: {
            return ParseSuperExpression();
        }
        case lexer::TokenType::KEYW_NEW: {
            return ParseNewExpression();
        }
        case lexer::TokenType::KEYW_ASYNC: {
            return ParseAsyncExpression();
        }
        case lexer::TokenType::KEYW_AWAIT: {
            return ParseAwaitExpression();
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET: {
            return ParseArrayExpression(CarryPatternFlags(flags));
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_BRACE: {
            return ParseObjectExpression(CarryPatternFlags(flags));
        }
        case lexer::TokenType::PUNCTUATOR_BACK_TICK: {
            return ParseTemplateLiteral();
        }
        case lexer::TokenType::KEYW_TYPE: {
            ThrowSyntaxError("Type alias is allowed only as top-level declaration");
        }
        case lexer::TokenType::PUNCTUATOR_FORMAT: {
            return ParseExpressionFormatPlaceholder();
        }
        case lexer::TokenType::KEYW_TYPEOF: {
            return ParseUnaryOrPrefixUpdateExpression();
        }
        default: {
            return ParsePrimaryExpressionWithLiterals(flags);
        }
    }
}

bool IsPunctuartorSpecialCharacter(lexer::TokenType tokenType)
{
    switch (tokenType) {
        case lexer::TokenType::PUNCTUATOR_COLON:
        case lexer::TokenType::PUNCTUATOR_COMMA:
        case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET:
        case lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET:
        case lexer::TokenType::PUNCTUATOR_LESS_THAN:
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN:
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR:
            return true;
        default:
            return false;
    }
}

bool ETSParser::IsArrowFunctionExpressionStart()
{
    const auto savedPos = Lexer()->Save();
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
    Lexer()->NextToken();
    auto tokenType = Lexer()->GetToken().Type();

    size_t openBrackets = 1;
    bool expectIdentifier = true;
    while (tokenType != lexer::TokenType::EOS && openBrackets > 0) {
        switch (tokenType) {
            case lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS:
                --openBrackets;
                break;
            case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS:
                ++openBrackets;
                break;
            case lexer::TokenType::PUNCTUATOR_COMMA:
                expectIdentifier = true;
                break;
            case lexer::TokenType::PUNCTUATOR_SEMI_COLON:
                Lexer()->Rewind(savedPos);
                return false;
            default:
                if (!expectIdentifier) {
                    break;
                }
                if (tokenType != lexer::TokenType::LITERAL_IDENT &&
                    tokenType != lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD) {
                    Lexer()->Rewind(savedPos);
                    return false;
                }
                expectIdentifier = false;
        }
        Lexer()->NextToken();
        tokenType = Lexer()->GetToken().Type();
    }

    while (tokenType != lexer::TokenType::EOS && tokenType != lexer::TokenType::PUNCTUATOR_ARROW) {
        if (lexer::Token::IsPunctuatorToken(tokenType) && !IsPunctuartorSpecialCharacter(tokenType)) {
            break;
        }
        Lexer()->NextToken();
        tokenType = Lexer()->GetToken().Type();
    }
    Lexer()->Rewind(savedPos);
    return tokenType == lexer::TokenType::PUNCTUATOR_ARROW;
}

ir::ArrowFunctionExpression *ETSParser::ParseArrowFunctionExpression()
{
    auto newStatus = ParserStatus::ARROW_FUNCTION;
    auto *func = ParseFunction(newStatus);
    auto *arrowFuncNode = AllocNode<ir::ArrowFunctionExpression>(func);
    arrowFuncNode->SetRange(func->Range());
    return arrowFuncNode;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ETSParser::ParseCoverParenthesizedExpressionAndArrowParameterList(ExpressionParseFlags flags)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
    if (IsArrowFunctionExpressionStart()) {
        return ParseArrowFunctionExpression();
    }

    lexer::SourcePosition start = Lexer()->GetToken().Start();
    Lexer()->NextToken();

    ExpressionParseFlags newFlags = ExpressionParseFlags::ACCEPT_COMMA;
    if ((flags & ExpressionParseFlags::INSTANCEOF) != 0) {
        newFlags |= ExpressionParseFlags::INSTANCEOF;
    };

    ir::Expression *expr = ParseExpression(newFlags);

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError("Unexpected token, expected ')'");
    }

    expr->SetGrouped();
    expr->SetRange({start, Lexer()->GetToken().End()});
    Lexer()->NextToken();

    return expr;
}

std::optional<ir::Expression *> ETSParser::GetPostPrimaryExpression(ir::Expression *returnExpression,
                                                                    lexer::SourcePosition startLoc,
                                                                    bool ignoreCallExpression,
                                                                    [[maybe_unused]] bool *isChainExpression)
{
    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::PUNCTUATOR_QUESTION_DOT:
            if (*isChainExpression) {
                return std::nullopt;  // terminate current chain
            }
            *isChainExpression = true;
            Lexer()->NextToken();  // eat ?.

            if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
                return ParseElementAccess(returnExpression, true);
            }

            if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
                return ParseCallExpression(returnExpression, true, false);
            }

            return ParsePropertyAccess(returnExpression, true);
        case lexer::TokenType::PUNCTUATOR_PERIOD:
            Lexer()->NextToken();  // eat period

            return ParsePropertyAccess(returnExpression);
        case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET:
            return ParseElementAccess(returnExpression);
        case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_LESS_THAN:
            if (ParsePotentialGenericFunctionCall(returnExpression, &returnExpression, startLoc,
                                                  ignoreCallExpression)) {
                return std::nullopt;
            }

            return returnExpression;
        case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS:
            if (ignoreCallExpression) {
                return std::nullopt;
            }
            return ParseCallExpression(returnExpression, false, false);
        case lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK: {
            const bool shouldBreak = ParsePotentialNonNullExpression(&returnExpression, startLoc);
            if (shouldBreak) {
                return std::nullopt;
            }

            return returnExpression;
        }
        case lexer::TokenType::PUNCTUATOR_FORMAT:
            ThrowUnexpectedToken(lexer::TokenType::PUNCTUATOR_FORMAT);
        case lexer::TokenType::PUNCTUATOR_ARROW:
            ThrowUnexpectedToken(lexer::TokenType::PUNCTUATOR_ARROW);
        default:
            return std::nullopt;
    }
}

ir::Expression *ETSParser::ParsePostPrimaryExpression(ir::Expression *primaryExpr, lexer::SourcePosition startLoc,
                                                      bool ignoreCallExpression,
                                                      [[maybe_unused]] bool *isChainExpression)
{
    ir::Expression *returnExpression = primaryExpr;

    while (true) {
        auto expr = GetPostPrimaryExpression(returnExpression, startLoc, ignoreCallExpression, isChainExpression);
        if (expr.has_value()) {
            returnExpression = expr.value();
            continue;
        }

        break;
    }

    return returnExpression;
}

ir::Expression *ETSParser::ParsePotentialAsExpression(ir::Expression *primaryExpr)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::KEYW_AS);
    Lexer()->NextToken();

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
    ir::TypeNode *type = ParseTypeAnnotation(&options);

    auto *asExpression = AllocNode<ir::TSAsExpression>(primaryExpr, type, false);
    asExpression->SetRange(primaryExpr->Range());
    return asExpression;
}

//  Extracted from 'ParseNewExpression()' to reduce function's size
ir::ClassDefinition *ETSParser::CreateClassDefinitionForNewExpression(ArenaVector<ir::Expression *> &arguments,
                                                                      ir::TypeNode *typeReference,
                                                                      ir::TypeNode *baseTypeReference)
{
    lexer::SourcePosition endLoc = typeReference->End();

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        if (baseTypeReference != nullptr) {
            ThrowSyntaxError("Can not use 'new' on primitive types.", baseTypeReference->Start());
        }

        Lexer()->NextToken();

        while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
            ir::Expression *argument = ParseExpression();
            arguments.push_back(argument);

            if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
                Lexer()->NextToken();
                continue;
            }
        }

        endLoc = Lexer()->GetToken().End();
        Lexer()->NextToken();
    }

    ir::ClassDefinition *classDefinition {};

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        ArenaVector<ir::TSClassImplements *> implements(Allocator()->Adapter());
        auto modifiers = ir::ClassDefinitionModifiers::ANONYMOUS | ir::ClassDefinitionModifiers::HAS_SUPER;
        auto [ctor, properties, bodyRange] = ParseClassBody(modifiers);

        auto newIdent = AllocNode<ir::Identifier>("#0", Allocator());
        classDefinition = AllocNode<ir::ClassDefinition>(
            "#0", newIdent, nullptr, nullptr, std::move(implements), ctor,  // remove name
            typeReference->Clone(Allocator(), nullptr), std::move(properties), modifiers, ir::ModifierFlags::NONE,
            Language(Language::Id::ETS));

        classDefinition->SetRange(bodyRange);
    }

    return classDefinition;
}

ir::Expression *ETSParser::ParseNewExpression()
{
    lexer::SourcePosition start = Lexer()->GetToken().Start();

    Lexer()->NextToken();  // eat new

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
    ir::TypeNode *baseTypeReference = ParseBaseTypeReference(&options);
    ir::TypeNode *typeReference = baseTypeReference;
    if (typeReference == nullptr) {
        options |= TypeAnnotationParsingOptions::IGNORE_FUNCTION_TYPE | TypeAnnotationParsingOptions::ALLOW_WILDCARD |
                   TypeAnnotationParsingOptions::POTENTIAL_NEW_ARRAY;
        typeReference = ParseTypeReference(&options);
        if (typeReference == nullptr) {
            typeReference = ParseTypeAnnotation(&options);
        }
    } else if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        ThrowSyntaxError("Invalid { after base types.");
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
        Lexer()->NextToken();
        ir::Expression *dimension = ParseExpression();

        auto endLoc = Lexer()->GetToken().End();
        ExpectToken(lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET);

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
            auto *arrInstance = AllocNode<ir::ETSNewArrayInstanceExpression>(typeReference, dimension);
            arrInstance->SetRange({start, endLoc});
            return arrInstance;
        }

        ArenaVector<ir::Expression *> dimensions(Allocator()->Adapter());
        dimensions.push_back(dimension);

        do {
            Lexer()->NextToken();
            dimensions.push_back(ParseExpression());

            endLoc = Lexer()->GetToken().End();
            ExpectToken(lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET);
        } while (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET);

        auto *multiArray = AllocNode<ir::ETSNewMultiDimArrayInstanceExpression>(typeReference, std::move(dimensions));
        multiArray->SetRange({start, endLoc});
        return multiArray;
    }

    ArenaVector<ir::Expression *> arguments(Allocator()->Adapter());
    ir::ClassDefinition *classDefinition =
        CreateClassDefinitionForNewExpression(arguments, typeReference, baseTypeReference);

    auto *newExprNode =
        AllocNode<ir::ETSNewClassInstanceExpression>(typeReference, std::move(arguments), classDefinition);
    newExprNode->SetRange({start, Lexer()->GetToken().End()});

    return newExprNode;
}

ir::Expression *ETSParser::ParseAsyncExpression()
{
    Lexer()->NextToken();  // eat 'async'
    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS ||
        !IsArrowFunctionExpressionStart()) {
        ThrowSyntaxError("Unexpected token. expected '('");
    }

    auto newStatus = ParserStatus::NEED_RETURN_TYPE | ParserStatus::ARROW_FUNCTION | ParserStatus::ASYNC_FUNCTION;
    auto *func = ParseFunction(newStatus);
    auto *arrowFuncNode = AllocNode<ir::ArrowFunctionExpression>(func);
    arrowFuncNode->SetRange(func->Range());
    return arrowFuncNode;
}

ir::Expression *ETSParser::ParseAwaitExpression()
{
    lexer::SourcePosition start = Lexer()->GetToken().Start();
    Lexer()->NextToken();
    ir::Expression *argument = ParseExpression();
    auto *awaitExpression = AllocNode<ir::AwaitExpression>(argument);
    awaitExpression->SetRange({start, Lexer()->GetToken().End()});
    return awaitExpression;
}

ir::ThisExpression *ETSParser::ParseThisExpression()
{
    auto *thisExpression = TypedParser::ParseThisExpression();

    if (Lexer()->GetToken().NewLine()) {
        return thisExpression;
    }

    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::PUNCTUATOR_PERIOD:
        case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS:
        case lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS:
        case lexer::TokenType::PUNCTUATOR_SEMI_COLON:
        case lexer::TokenType::PUNCTUATOR_COLON:
        case lexer::TokenType::PUNCTUATOR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_STRICT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_COMMA:
        case lexer::TokenType::PUNCTUATOR_QUESTION_MARK:
        case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET:
        case lexer::TokenType::KEYW_INSTANCEOF:
        case lexer::TokenType::KEYW_AS: {
            break;
        }
        default: {
            ThrowUnexpectedToken(Lexer()->GetToken().Type());
            break;
        }
    }

    return thisExpression;
}

ir::Expression *ETSParser::ParsePotentialExpressionSequence(ir::Expression *expr, ExpressionParseFlags flags)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA &&
        (flags & ExpressionParseFlags::ACCEPT_COMMA) != 0 && (flags & ExpressionParseFlags::IN_FOR) != 0U) {
        return ParseSequenceExpression(expr, (flags & ExpressionParseFlags::ACCEPT_REST) != 0);
    }

    return expr;
}

bool ETSParser::ParsePotentialNonNullExpression(ir::Expression **expression, const lexer::SourcePosition startLoc)
{
    if (expression == nullptr || Lexer()->GetToken().NewLine()) {
        return true;
    }

    const auto nonNullExpr = AllocNode<ir::TSNonNullExpression>(*expression);
    nonNullExpr->SetRange({startLoc, Lexer()->GetToken().End()});

    *expression = nonNullExpr;

    Lexer()->NextToken();

    return false;
}

void ETSParser::ValidateInstanceOfExpression(ir::Expression *expr)
{
    ValidateGroupedExpression(expr);
    lexer::TokenType tokenType = Lexer()->GetToken().Type();
    if (tokenType == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        auto options = TypeAnnotationParsingOptions::NO_OPTS;

        // Run checks to validate type declarations
        // Should provide helpful messages with incorrect declarations like the following:
        // `instanceof A<String;`
        ParseTypeParameterDeclaration(&options);

        // Display error message even when type declaration is correct
        // `instanceof A<String>;`
        ThrowSyntaxError("Invalid right-hand side in 'instanceof' expression");
    }
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ETSParser::ParseExpression(ExpressionParseFlags flags)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_YIELD &&
        (flags & ExpressionParseFlags::DISALLOW_YIELD) == 0U) {
        ir::YieldExpression *yieldExpr = ParseYieldExpression();

        return ParsePotentialExpressionSequence(yieldExpr, flags);
    }

    ir::Expression *unaryExpressionNode = ParseUnaryOrPrefixUpdateExpression(flags);
    if ((flags & ExpressionParseFlags::INSTANCEOF) != 0) {
        ValidateInstanceOfExpression(unaryExpressionNode);
    }

    ir::Expression *assignmentExpression = ParseAssignmentExpression(unaryExpressionNode, flags);

    if (Lexer()->GetToken().NewLine()) {
        return assignmentExpression;
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA &&
        (flags & ExpressionParseFlags::ACCEPT_COMMA) != 0U && (flags & ExpressionParseFlags::IN_FOR) != 0U) {
        return ParseSequenceExpression(assignmentExpression, (flags & ExpressionParseFlags::ACCEPT_REST) != 0U);
    }

    return assignmentExpression;
}

}  // namespace ark::es2panda::parser
