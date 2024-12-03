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

#include "lexer/lexer.h"
#include "ir/expressions/literals/undefinedLiteral.h"
#include "ir/ets/etsTuple.h"

namespace ark::es2panda::parser {
class FunctionContext;

using namespace std::literals::string_literals;

ir::Expression *ETSParser::ParseLaunchExpression(ExpressionParseFlags flags)
{
    lexer::SourcePosition start = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat launch

    lexer::SourcePosition exprStart = Lexer()->GetToken().Start();
    ir::Expression *expr = ParseLeftHandSideExpression(flags);
    if (expr == nullptr || !expr->IsCallExpression()) {
        LogSyntaxError("Only call expressions are allowed after 'launch'", exprStart);
        return nullptr;
    }
    auto call = expr->AsCallExpression();
    auto *launchExpression = AllocNode<ir::ETSLaunchExpression>(call);
    launchExpression->SetRange({start, call->End()});

    return launchExpression;
}

// NOLINTBEGIN(modernize-avoid-c-arrays)
static constexpr char const NO_DEFAULT_FOR_REST[] = "Rest parameter cannot have the default value.";
// NOLINTEND(modernize-avoid-c-arrays)

static std::string GetArgumentsSourceView(lexer::Lexer *lexer, const util::StringView::Iterator &lexerPos)
{
    std::string value = lexer->SourceView(lexerPos.Index(), lexer->Save().Iterator().Index()).Mutf8();
    while (value.back() == ' ') {
        value.pop_back();
    }

    if (value.back() == ')' || value.back() == ',') {
        value.pop_back();
    }

    return value;
}

ir::Expression *ETSParser::ParseFunctionParameterExpression(ir::AnnotatedExpression *const paramIdent,
                                                            ir::ETSUndefinedType *defaultUndef)
{
    ir::ETSParameterExpression *paramExpression;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        auto const lexerPos = Lexer()->Save().Iterator();
        Lexer()->NextToken();  // eat '='

        if (paramIdent->IsRestElement()) {
            LogSyntaxError(NO_DEFAULT_FOR_REST);
        }

        if ((GetContext().Status() & ParserStatus::ALLOW_DEFAULT_VALUE) != 0) {
            LogSyntaxError("Default value is allowed only for optional parameters");
        }

        if (defaultUndef != nullptr) {
            LogSyntaxError("Not enable default value with default undefined");
        }
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS ||
            Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
            LogSyntaxError("You didn't set the value.");
        }

        auto defaultValue = ParseExpression();
        if (!paramIdent->IsIdentifier() || defaultValue == nullptr) {  // Error processing.
            return nullptr;
        }

        paramExpression = AllocNode<ir::ETSParameterExpression>(paramIdent->AsIdentifier(), defaultValue);

        std::string value = GetArgumentsSourceView(Lexer(), lexerPos);
        paramExpression->SetLexerSaved(util::UString(value, Allocator()).View());
        paramExpression->SetRange({paramIdent->Start(), paramExpression->Initializer()->End()});
    } else if (paramIdent == nullptr) {  // Error processing.
        return nullptr;
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
    auto tokenFlags = lexer::NextTokenFlags::NONE;
    lexer::TokenType operatorType = Lexer()->GetToken().Type();

    switch (operatorType) {
        case lexer::TokenType::PUNCTUATOR_MINUS:
            tokenFlags = lexer::NextTokenFlags::UNARY_MINUS;
            [[fallthrough]];
        case lexer::TokenType::PUNCTUATOR_PLUS_PLUS:
        case lexer::TokenType::PUNCTUATOR_MINUS_MINUS:
        case lexer::TokenType::PUNCTUATOR_PLUS:
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

    auto start = Lexer()->GetToken().Start();
    Lexer()->NextToken(tokenFlags);

    ir::Expression *argument = ResolveArgumentUnaryExpr(flags);

    if (argument == nullptr) {
        return nullptr;
    }

    if (lexer::Token::IsUpdateToken(operatorType)) {
        if (!argument->IsIdentifier() && !argument->IsMemberExpression()) {
            LogSyntaxError("Invalid left-hand side in prefix operation");
        }
    }

    lexer::SourcePosition end = argument->End();

    ir::Expression *returnExpr = nullptr;
    if (lexer::Token::IsUpdateToken(operatorType)) {
        returnExpr = AllocNode<ir::UpdateExpression>(argument, operatorType, true);
    } else if (operatorType == lexer::TokenType::KEYW_TYPEOF) {
        returnExpr = AllocNode<ir::TypeofExpression>(argument);
    } else if (operatorType == lexer::TokenType::PUNCTUATOR_MINUS) {
        returnExpr = !argument->IsNumberLiteral() ? AllocNode<ir::UnaryExpression>(argument, operatorType) : argument;
    } else {
        returnExpr = AllocNode<ir::UnaryExpression>(argument, operatorType);
    }

    returnExpr->SetRange({start, end});

    return returnExpr;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ETSParser::ParsePropertyDefinition(ExpressionParseFlags flags)
{
    ir::PropertyKind propertyKind = ir::PropertyKind::INIT;
    ParserStatus methodStatus = ParserStatus::NO_OPTS;

    const auto startPos = Lexer()->Save();
    Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
    lexer::SourcePosition start = Lexer()->GetToken().Start();

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD) {
        return ParseSpreadElement(flags);
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
        if (ParsePropertyModifiers(flags, &propertyKind, &methodStatus)) {
            return ParseShorthandProperty(&startPos);
        }
    } else if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY) {
        ParseGeneratorPropertyModifier(flags, &methodStatus);
    }

    bool isComputed = Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET;
    ir::Expression *key = ParsePropertyKey(flags);

    ir::Expression *value = ParsePropertyValue(&propertyKind, &methodStatus, flags);
    if (key == nullptr || value == nullptr) {  // Error processing.
        return nullptr;
    }

    lexer::SourcePosition end = value->End();

    auto *returnProperty =
        AllocNode<ir::Property>(propertyKind, key, value, methodStatus != ParserStatus::NO_OPTS, isComputed);
    returnProperty->SetRange({start, end});

    return returnProperty;
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

    LogSyntaxError({"Unexpected token '", lexer::TokenToString(Lexer()->GetToken().Type()), "'."});
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
            return ParseNumberLiteral();
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
            LogSyntaxError("Type alias is allowed only as top-level declaration");
            ParseTypeAliasDeclaration();  // Try to parse type alias and drop the result.
            return nullptr;
        }
        case lexer::TokenType::PUNCTUATOR_FORMAT: {
            return ParseExpressionFormatPlaceholder();
        }
        case lexer::TokenType::KEYW_TYPEOF: {
            return ParseUnaryOrPrefixUpdateExpression();
        }
        case lexer::TokenType::KEYW_IMPORT: {
            return ParseETSImportExpression();
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
        lexer::NextTokenFlags flag = lexer::NextTokenFlags::NONE;
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
            // (DZ) need for correct processing of possible number literals
            case lexer::TokenType::PUNCTUATOR_MINUS:
                flag = lexer::NextTokenFlags::UNARY_MINUS;
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
        Lexer()->NextToken(flag);
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
        LogExpectedToken(lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS);
    }

    if (expr == nullptr) {  // Error processing.
        return nullptr;
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
        case lexer::TokenType::PUNCTUATOR_ARROW:
            LogUnexpectedToken(Lexer()->GetToken().Type());
            [[fallthrough]];
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

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::REPORT_ERROR;
    ir::TypeNode *type = ParseTypeAnnotation(&options);

    if (type == nullptr) {
        // Error processing
        // Failed to parse type annotation for AsExpression
        return nullptr;
    }

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
            LogSyntaxError("Can not use 'new' on primitive types.", baseTypeReference->Start());
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

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::REPORT_ERROR;
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
        LogSyntaxError("Invalid { after base types.");
        Lexer()->NextToken();  // eat '{'
    }

    if (typeReference == nullptr) {  // Error processing.
        return nullptr;
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
        LogExpectedToken(lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
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

ir::Expression *ETSParser::ParseETSImportExpression()
{
    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();
    ExpectToken(lexer::TokenType::KEYW_IMPORT);
    ExpectToken(lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
    ir::Expression *source = ParseExpression();
    lexer::SourcePosition endLoc = Lexer()->GetToken().Start();
    ExpectToken(lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS);

    auto *importExpression = AllocNode<ir::ImportExpression>(source);
    importExpression->SetRange({startLoc, endLoc});
    return importExpression;
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
        LogSyntaxError("Invalid right-hand side in 'instanceof' expression");
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
    if (unaryExpressionNode == nullptr) {
        return nullptr;
    }

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
