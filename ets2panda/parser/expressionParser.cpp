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

#include "lexer/token/tokenType.h"
#include "parser/parserFlags.h"
#include "ir/astNode.h"
#include "ir/base/classDefinition.h"
#include "ir/base/decorator.h"
#include "ir/base/metaProperty.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/property.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/spreadElement.h"
#include "ir/base/templateElement.h"
#include "ir/expression.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/arrowFunctionExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/awaitExpression.h"
#include "ir/expressions/binaryExpression.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/chainExpression.h"
#include "ir/expressions/classExpression.h"
#include "ir/expressions/conditionalExpression.h"
#include "ir/expressions/directEvalExpression.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/importExpression.h"
#include "ir/expressions/literals/bigIntLiteral.h"
#include "ir/expressions/literals/booleanLiteral.h"
#include "ir/expressions/literals/nullLiteral.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/regExpLiteral.h"
#include "ir/expressions/literals/charLiteral.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/expressions/literals/undefinedLiteral.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/newExpression.h"
#include "ir/expressions/objectExpression.h"
#include "ir/expressions/omittedExpression.h"
#include "ir/expressions/sequenceExpression.h"
#include "ir/expressions/superExpression.h"
#include "ir/expressions/taggedTemplateExpression.h"
#include "ir/expressions/templateLiteral.h"
#include "ir/expressions/thisExpression.h"
#include "ir/expressions/typeofExpression.h"
#include "ir/expressions/unaryExpression.h"
#include "ir/expressions/updateExpression.h"
#include "ir/expressions/yieldExpression.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/classDeclaration.h"
#include "ir/ts/tsAsExpression.h"
#include "ir/ts/tsNonNullExpression.h"
#include "ir/validationInfo.h"
#include "lexer/lexer.h"
#include "lexer/regexp/regexp.h"
#include "lexer/token/letters.h"
#include "lexer/token/sourceLocation.h"
#include "lexer/token/token.h"
#include "macros.h"

#include <memory>

#include "parser/parserStatusContext.h"
#include "parserImpl.h"

namespace ark::es2panda::parser {
ir::YieldExpression *ParserImpl::ParseYieldExpression()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::KEYW_YIELD);

    lexer::SourcePosition startLoc = lexer_->GetToken().Start();
    lexer::SourcePosition endLoc = lexer_->GetToken().End();

    if ((lexer_->GetToken().Flags() & lexer::TokenFlags::HAS_ESCAPE) != 0) {
        ThrowSyntaxError("Unexpected identifier");
    }

    lexer_->NextToken();

    bool isDelegate = false;
    ir::Expression *argument = nullptr;

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY && !lexer_->GetToken().NewLine()) {
        isDelegate = true;
        lexer_->NextToken();

        argument = ParseExpression();
        endLoc = argument->End();
    } else if (!lexer_->GetToken().NewLine() && lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE &&
               lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS &&
               lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET &&
               lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COMMA &&
               lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SEMI_COLON &&
               lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON &&
               lexer_->GetToken().Type() != lexer::TokenType::EOS) {
        argument = ParseExpression();
        endLoc = argument->End();
    }

    auto *yieldNode = AllocNode<ir::YieldExpression>(argument, isDelegate);
    yieldNode->SetRange({startLoc, endLoc});

    return yieldNode;
}

ir::Expression *ParserImpl::ParsePotentialExpressionSequence(ir::Expression *expr, ExpressionParseFlags flags)
{
    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA &&
        (flags & ExpressionParseFlags::ACCEPT_COMMA) != 0) {
        return ParseSequenceExpression(expr, (flags & ExpressionParseFlags::ACCEPT_REST) != 0);
    }

    return expr;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ParserImpl::ParseExpression(ExpressionParseFlags flags)
{
    if (lexer_->GetToken().Type() == lexer::TokenType::KEYW_YIELD &&
        (flags & ExpressionParseFlags::DISALLOW_YIELD) == 0U) {
        ir::YieldExpression *yieldExpr = ParseYieldExpression();

        return ParsePotentialExpressionSequence(yieldExpr, flags);
    }

    ir::Expression *unaryExpressionNode = ParseUnaryOrPrefixUpdateExpression(flags);
    ir::Expression *assignmentExpression = ParseAssignmentExpression(unaryExpressionNode, flags);

    if (lexer_->GetToken().NewLine()) {
        return assignmentExpression;
    }

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA &&
        (flags & ExpressionParseFlags::ACCEPT_COMMA) != 0U) {
        return ParseSequenceExpression(assignmentExpression, (flags & ExpressionParseFlags::ACCEPT_REST) != 0U);
    }

    return assignmentExpression;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::ArrayExpression *ParserImpl::ParseArrayExpression(ExpressionParseFlags flags)
{
    lexer::SourcePosition startLoc = lexer_->GetToken().Start();

    ArenaVector<ir::Expression *> elements(Allocator()->Adapter());

    lexer_->NextToken();

    bool trailingComma = false;
    bool inPattern = (flags & ExpressionParseFlags::MUST_BE_PATTERN) != 0;

    while (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
        if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
            auto *omitted = AllocNode<ir::OmittedExpression>();
            omitted->SetRange(lexer_->GetToken().Loc());
            elements.push_back(omitted);
            lexer_->NextToken();
            continue;
        }

        ir::Expression *element {};
        if (inPattern) {
            element = ParsePatternElement();
        } else if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD) {
            element = ParseSpreadElement(ExpressionParseFlags::POTENTIALLY_IN_PATTERN);
        } else {
            element = ParseExpression(ExpressionParseFlags::POTENTIALLY_IN_PATTERN);
        }

        bool containsRest = element->IsRestElement();

        elements.push_back(element);

        if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
            if (containsRest) {
                ThrowSyntaxError("Rest element must be last element", startLoc);
            }

            lexer_->NextToken();  // eat comma

            if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
                trailingComma = true;
                break;
            }

            continue;
        }

        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
            ThrowSyntaxError("Unexpected token, expected ',' or ']'");
        }
    }

    auto nodeType = inPattern ? ir::AstNodeType::ARRAY_PATTERN : ir::AstNodeType::ARRAY_EXPRESSION;
    auto *arrayExpressionNode =
        AllocNode<ir::ArrayExpression>(nodeType, std::move(elements), Allocator(), trailingComma);
    arrayExpressionNode->SetRange({startLoc, lexer_->GetToken().End()});
    lexer_->NextToken();

    if (inPattern) {
        arrayExpressionNode->SetDeclaration();
    }

    ParseArrayExpressionErrorCheck(arrayExpressionNode, flags, inPattern);
    return arrayExpressionNode;
}

void ParserImpl::ParseArrayExpressionErrorCheck(ir::ArrayExpression *arrayExpressionNode,
                                                const ExpressionParseFlags flags, const bool inPattern)
{
    if ((flags & ExpressionParseFlags::POTENTIALLY_IN_PATTERN) == 0) {
        if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION &&
            !arrayExpressionNode->ConvertibleToArrayPattern()) {
            ThrowSyntaxError("Invalid left-hand side in array destructuring pattern", arrayExpressionNode->Start());
        } else if (!inPattern && lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
            ir::ValidationInfo info = arrayExpressionNode->ValidateExpression();
            if (info.Fail()) {
                ThrowSyntaxError(info.msg.Utf8(), info.pos);
            }
        }
    }
}

ParserStatus ParserImpl::ValidateArrowParameter(ir::Expression *expr, [[maybe_unused]] bool *seenOptional)
{
    switch (expr->Type()) {
        case ir::AstNodeType::SPREAD_ELEMENT: {
            if (!expr->AsSpreadElement()->ConvertibleToRest(true)) {
                ThrowSyntaxError("Invalid rest element.");
            }

            [[fallthrough]];
        }
        case ir::AstNodeType::REST_ELEMENT: {
            ValidateArrowParameterBindings(expr->AsRestElement()->Argument());
            return ParserStatus::HAS_COMPLEX_PARAM;
        }
        case ir::AstNodeType::IDENTIFIER: {
            ValidateArrowParameterBindings(expr);
            return ParserStatus::NO_OPTS;
        }
        case ir::AstNodeType::OBJECT_EXPRESSION: {
            if (ir::ObjectExpression *objectPattern = expr->AsObjectExpression();
                !objectPattern->ConvertibleToObjectPattern()) {
                ThrowSyntaxError("Invalid destructuring assignment target");
            }

            ValidateArrowParameterBindings(expr);
            return ParserStatus::HAS_COMPLEX_PARAM;
        }
        case ir::AstNodeType::ARRAY_EXPRESSION: {
            if (ir::ArrayExpression *arrayPattern = expr->AsArrayExpression();
                !arrayPattern->ConvertibleToArrayPattern()) {
                ThrowSyntaxError("Invalid destructuring assignment target");
            }

            ValidateArrowParameterBindings(expr);
            return ParserStatus::HAS_COMPLEX_PARAM;
        }
        case ir::AstNodeType::ASSIGNMENT_EXPRESSION: {
            ValidateArrowParameterAssignment(expr->AsAssignmentExpression());
            ValidateArrowParameterBindings(expr);
            return ParserStatus::HAS_COMPLEX_PARAM;
        }
        default: {
            break;
        }
    }
    ThrowSyntaxError("Insufficient formal parameter in arrow function.");
    return ParserStatus::NO_OPTS;
}

void ParserImpl::ValidateArrowParameterAssignment(ir::AssignmentExpression *expr)
{
    if (expr->Right()->IsYieldExpression()) {
        ThrowSyntaxError("yield is not allowed in arrow function parameters");
    } else if (expr->Right()->IsAwaitExpression()) {
        ThrowSyntaxError("await is not allowed in arrow function parameters");
    } else if (!expr->ConvertibleToAssignmentPattern()) {
        ThrowSyntaxError("Invalid destructuring assignment target");
    }
}

ir::ArrowFunctionExpression *ParserImpl::ParseArrowFunctionExpressionBody(ArrowFunctionContext *arrowFunctionContext,
                                                                          ArrowFunctionDescriptor *desc,
                                                                          ir::TSTypeParameterDeclaration *typeParamDecl,
                                                                          ir::TypeNode *returnTypeAnnotation)
{
    context_.Status() |= desc->newStatus;

    lexer_->NextToken();  // eat '=>'
    ir::ScriptFunction *funcNode {};

    ir::AstNode *body = nullptr;
    lexer::SourcePosition endLoc;
    lexer::SourcePosition bodyStart = lexer_->GetToken().Start();

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        body = ParseExpression();
        endLoc = body->AsExpression()->End();
        arrowFunctionContext->AddFlag(ir::ScriptFunctionFlags::EXPRESSION);
    } else {
        lexer_->NextToken();
        auto statements = ParseStatementList();
        body = AllocNode<ir::BlockStatement>(Allocator(), std::move(statements));
        body->SetRange({bodyStart, lexer_->GetToken().End()});

        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
            ThrowSyntaxError("Expected a '}'");
        }

        lexer_->NextToken();
        endLoc = body->End();
    }

    // clang-format off
    funcNode = AllocNode<ir::ScriptFunction>(
        Allocator(), ir::ScriptFunction::ScriptFunctionData {
                        body,
                        ir::FunctionSignature(typeParamDecl, std::move(desc->params), returnTypeAnnotation),
                        arrowFunctionContext->Flags(),
                        {},
                        false,
                        context_.GetLanguage()});
    // clang-format on
    funcNode->SetRange({desc->startLoc, endLoc});

    auto *arrowFuncNode = AllocNode<ir::ArrowFunctionExpression>(funcNode);
    arrowFuncNode->SetRange(funcNode->Range());

    return arrowFuncNode;
}

ArrowFunctionDescriptor ParserImpl::ConvertToArrowParameter(ir::Expression *expr, bool isAsync)
{
    auto arrowStatus = isAsync ? ParserStatus::ASYNC_FUNCTION : ParserStatus::NO_OPTS;
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());

    if (expr == nullptr) {
        return ArrowFunctionDescriptor {std::move(params), lexer_->GetToken().Start(), arrowStatus};
    }

    bool seenOptional = false;

    switch (expr->Type()) {
        case ir::AstNodeType::REST_ELEMENT:
        case ir::AstNodeType::IDENTIFIER:
        case ir::AstNodeType::OBJECT_EXPRESSION:
        case ir::AstNodeType::ASSIGNMENT_EXPRESSION:
        case ir::AstNodeType::ARRAY_EXPRESSION: {
            arrowStatus |= ValidateArrowParameter(expr, &seenOptional);

            params.push_back(expr);
            break;
        }
        case ir::AstNodeType::SEQUENCE_EXPRESSION: {
            auto &sequence = expr->AsSequenceExpression()->Sequence();

            for (auto *it : sequence) {
                arrowStatus |= ValidateArrowParameter(it, &seenOptional);
            }

            params.swap(sequence);
            break;
        }
        case ir::AstNodeType::CALL_EXPRESSION: {
            if (isAsync) {
                auto *callExpression = expr->AsCallExpression();
                auto &arguments = callExpression->Arguments();

                if (callExpression->HasTrailingComma()) {
                    ASSERT(!arguments.empty());
                    ThrowSyntaxError("Rest parameter must be last formal parameter", arguments.back()->End());
                }

                for (auto *it : arguments) {
                    arrowStatus |= ValidateArrowParameter(it, &seenOptional);
                }

                params.swap(arguments);
                break;
            }

            [[fallthrough]];
        }
        default: {
            ThrowSyntaxError("Unexpected token, arrow (=>)");
        }
    }

    return ArrowFunctionDescriptor {std::move(params), expr->Start(), arrowStatus};
}

ir::ArrowFunctionExpression *ParserImpl::ParseArrowFunctionExpression(ir::Expression *expr,
                                                                      ir::TSTypeParameterDeclaration *typeParamDecl,
                                                                      ir::TypeNode *returnTypeAnnotation, bool isAsync)
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_ARROW);

    if (lexer_->GetToken().NewLine()) {
        ThrowSyntaxError(
            "expected '=>' on the same line after an argument list, "
            "got line terminator");
    }

    ArrowFunctionContext arrowFunctionContext(this, isAsync);
    FunctionParameterContext functionParamContext(&context_);
    ArrowFunctionDescriptor desc = ConvertToArrowParameter(expr, isAsync);

    return ParseArrowFunctionExpressionBody(&arrowFunctionContext, &desc, typeParamDecl, returnTypeAnnotation);
}

void ParserImpl::ValidateArrowFunctionRestParameter([[maybe_unused]] ir::SpreadElement *restElement)
{
    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError("Rest parameter must be last formal parameter");
    }
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ParserImpl::ParseCoverParenthesizedExpressionAndArrowParameterList(
    [[maybe_unused]] ExpressionParseFlags flags)
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
    lexer::SourcePosition start = lexer_->GetToken().Start();
    lexer_->NextToken();

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD) {
        ir::SpreadElement *restElement = ParseSpreadElement(ExpressionParseFlags::MUST_BE_PATTERN);

        restElement->SetGrouped();
        restElement->SetStart(start);

        ValidateArrowFunctionRestParameter(restElement);

        lexer_->NextToken();

        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_ARROW) {
            ThrowSyntaxError("Unexpected token");
        }

        return ParseArrowFunctionExpression(restElement, nullptr, nullptr, false);
    }

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        lexer_->NextToken();

        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_ARROW) {
            ThrowSyntaxError("Unexpected token");
        }

        auto *arrowExpr = ParseArrowFunctionExpression(nullptr, nullptr, nullptr, false);
        arrowExpr->SetStart(start);
        arrowExpr->AsArrowFunctionExpression()->Function()->SetStart(start);

        return arrowExpr;
    }

    ir::Expression *expr = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA | ExpressionParseFlags::ACCEPT_REST |
                                           ExpressionParseFlags::POTENTIALLY_IN_PATTERN);

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError("Unexpected token, expected ')'");
    }

    expr->SetGrouped();
    expr->SetRange({start, lexer_->GetToken().End()});
    lexer_->NextToken();

    return expr;
}

void ParserImpl::CheckInvalidDestructuring(const ir::AstNode *object) const
{
    object->Iterate([this](ir::AstNode *childNode) -> void {
        switch (childNode->Type()) {
            case ir::AstNodeType::ASSIGNMENT_PATTERN: {
                ThrowSyntaxError("Invalid property initializer");
                break;
            }
            case ir::AstNodeType::REST_ELEMENT:
            case ir::AstNodeType::PROPERTY:
            case ir::AstNodeType::OBJECT_EXPRESSION: {
                CheckInvalidDestructuring(childNode);
                break;
            }
            default: {
                break;
            }
        }
    });
}

bool ParserImpl::ValidateGroupedExpression(ir::Expression *lhsExpression)
{
    if (lhsExpression == nullptr) {  // Error processing.
        return false;
    }

    lexer::TokenType tokenType = lexer_->GetToken().Type();
    if (lhsExpression->IsGrouped() && tokenType != lexer::TokenType::PUNCTUATOR_ARROW) {
        if (lhsExpression->IsSequenceExpression()) {
            for (auto *seq : lhsExpression->AsSequenceExpression()->Sequence()) {
                ValidateParenthesizedExpression(seq);
            }
        } else {
            ValidateParenthesizedExpression(lhsExpression);
        }
    }

    return true;
}

void ParserImpl::ValidateParenthesizedExpression(ir::Expression *lhsExpression)
{
    switch (lhsExpression->Type()) {
        case ir::AstNodeType::IDENTIFIER: {
            auto info = lhsExpression->AsIdentifier()->ValidateExpression();
            if (info.Fail()) {
                ThrowSyntaxError(info.msg.Utf8(), info.pos);
            }
            break;
        }
        case ir::AstNodeType::MEMBER_EXPRESSION: {
            break;
        }
        case ir::AstNodeType::ARRAY_EXPRESSION: {
            auto info = lhsExpression->AsArrayExpression()->ValidateExpression();
            if (info.Fail()) {
                ThrowSyntaxError(info.msg.Utf8(), info.pos);
            }
            break;
        }
        case ir::AstNodeType::OBJECT_EXPRESSION: {
            auto info = lhsExpression->AsObjectExpression()->ValidateExpression();
            if (info.Fail()) {
                ThrowSyntaxError(info.msg.Utf8(), info.pos);
            }
            break;
        }
        case ir::AstNodeType::ASSIGNMENT_EXPRESSION: {
            if (lhsExpression->AsAssignmentExpression()->ConvertibleToAssignmentPattern(false)) {
                break;
            }
            [[fallthrough]];
        }
        case ir::AstNodeType::SPREAD_ELEMENT: {
            ThrowSyntaxError("Invalid left-hand side in assignment expression");
        }
        default: {
            break;
        }
    }
}

ir::Expression *ParserImpl::ParsePrefixAssertionExpression()
{
    ThrowSyntaxError({"Unexpected token '", lexer::TokenToString(lexer_->GetToken().Type()), "'."});
    return nullptr;
}

ir::Expression *ParserImpl::ParseAssignmentExpression(ir::Expression *lhsExpression, ExpressionParseFlags flags)
{
    if (!ValidateGroupedExpression(lhsExpression)) {
        return nullptr;  // Error processing.
    }

    lexer::TokenType tokenType = lexer_->GetToken().Type();
    switch (tokenType) {
        case lexer::TokenType::PUNCTUATOR_QUESTION_MARK: {
            lexer_->NextToken();
            ir::Expression *consequent = ParseExpression();

            if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
                ThrowSyntaxError("Unexpected token, expected ':'");
            }

            lexer_->NextToken();
            ir::Expression *alternate = ParseExpression();

            auto *conditionalExpr = AllocNode<ir::ConditionalExpression>(lhsExpression, consequent, alternate);
            conditionalExpr->SetRange({lhsExpression->Start(), alternate->End()});
            return conditionalExpr;
        }
        case lexer::TokenType::PUNCTUATOR_ARROW: {
            if (lexer_->GetToken().NewLine()) {
                ThrowSyntaxError("Uncaught SyntaxError: expected expression, got '=>'");
            }

            return ParseArrowFunctionExpression(lhsExpression, nullptr, nullptr, false);
        }
        case lexer::TokenType::PUNCTUATOR_SUBSTITUTION: {
            ValidateAssignmentTarget(flags, lhsExpression);

            lexer_->NextToken();
            ir::Expression *assignmentExpression = ParseExpression(CarryPatternFlags(flags));

            auto *binaryAssignmentExpression =
                AllocNode<ir::AssignmentExpression>(lhsExpression, assignmentExpression, tokenType);

            binaryAssignmentExpression->SetRange({lhsExpression->Start(), assignmentExpression->End()});
            return binaryAssignmentExpression;
        }
        case lexer::TokenType::KEYW_AS: {
            if (auto asExpression = ParsePotentialAsExpression(lhsExpression); asExpression != nullptr) {
                return ParseAssignmentExpression(asExpression);
            }
            break;
        }
        default: {
            auto expression = ParseAssignmentBinaryExpression(tokenType, lhsExpression, flags);
            if (expression == nullptr) {
                expression = ParseAssignmentEqualExpression(tokenType, lhsExpression, flags);
            }

            if (expression != nullptr) {
                return expression;
            }

            break;
        }
    }

    return lhsExpression;
}

ir::Expression *ParserImpl::ParseAssignmentBinaryExpression(const lexer::TokenType tokenType,
                                                            ir::Expression *lhsExpression,
                                                            const ExpressionParseFlags flags)
{
    switch (tokenType) {
        case lexer::TokenType::KEYW_IN: {
            if ((flags & ExpressionParseFlags::STOP_AT_IN) != 0) {
                break;
            }

            [[fallthrough]];
        }
        case lexer::TokenType::PUNCTUATOR_NULLISH_COALESCING:
        case lexer::TokenType::PUNCTUATOR_LOGICAL_OR:
        case lexer::TokenType::PUNCTUATOR_LOGICAL_AND:
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR:
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR:
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND:
        case lexer::TokenType::PUNCTUATOR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_STRICT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_LESS_THAN:
        case lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL:
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN:
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL:
        case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_PLUS:
        case lexer::TokenType::PUNCTUATOR_MINUS:
        case lexer::TokenType::PUNCTUATOR_MULTIPLY:
        case lexer::TokenType::PUNCTUATOR_DIVIDE:
        case lexer::TokenType::PUNCTUATOR_MOD:
        case lexer::TokenType::KEYW_INSTANCEOF:
        case lexer::TokenType::PUNCTUATOR_EXPONENTIATION: {
            return ParseAssignmentExpression(ParseBinaryExpression(lhsExpression));
        }
        default:
            break;
    }

    return nullptr;
}

ir::Expression *ParserImpl::ParseAssignmentEqualExpression(const lexer::TokenType tokenType,
                                                           ir::Expression *lhsExpression,
                                                           const ExpressionParseFlags flags)
{
    switch (tokenType) {
        case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_PLUS_EQUAL:
        case lexer::TokenType::PUNCTUATOR_MINUS_EQUAL:
        case lexer::TokenType::PUNCTUATOR_MULTIPLY_EQUAL:
        case lexer::TokenType::PUNCTUATOR_DIVIDE_EQUAL:
        case lexer::TokenType::PUNCTUATOR_MOD_EQUAL:
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND_EQUAL:
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_EXPONENTIATION_EQUAL: {
            ValidateLvalueAssignmentTarget(lhsExpression);

            lexer_->NextToken();
            ir::Expression *assignmentExpression = ParseExpression(CarryPatternFlags(flags));

            auto *binaryAssignmentExpression =
                AllocNode<ir::AssignmentExpression>(lhsExpression, assignmentExpression, tokenType);

            binaryAssignmentExpression->SetRange({lhsExpression->Start(), assignmentExpression->End()});
            return binaryAssignmentExpression;
        }
        case lexer::TokenType::PUNCTUATOR_LOGICAL_AND_EQUAL:
        case lexer::TokenType::PUNCTUATOR_LOGICAL_OR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_LOGICAL_NULLISH_EQUAL: {
            ThrowUnexpectedToken(tokenType);
        }
        default:
            break;
    }

    return nullptr;
}

ir::TemplateLiteral *ParserImpl::ParseTemplateLiteral()
{
    lexer::SourcePosition startLoc = lexer_->GetToken().Start();

    ArenaVector<ir::TemplateElement *> quasis(Allocator()->Adapter());
    ArenaVector<ir::Expression *> expressions(Allocator()->Adapter());

    while (true) {
        lexer_->ResetTokenEnd();
        const auto startPos = lexer_->Save();

        lexer_->ScanString<lexer::LEX_CHAR_BACK_TICK>();
        util::StringView cooked = lexer_->GetToken().String();

        lexer_->Rewind(startPos);
        auto [raw, end, scanExpression] = lexer_->ScanTemplateString();

        auto *element = AllocNode<ir::TemplateElement>(raw.View(), cooked);
        element->SetRange({lexer::SourcePosition {startPos.Iterator().Index(), startPos.Line()},
                           lexer::SourcePosition {end, lexer_->Line()}});
        quasis.push_back(element);

        if (!scanExpression) {
            lexer_->ScanTemplateStringEnd();
            break;
        }

        ir::Expression *expression = nullptr;

        {
            lexer::TemplateLiteralParserContext ctx(lexer_);
            lexer_->PushTemplateContext(&ctx);
            lexer_->NextToken();
            expression = ParseExpression();
        }

        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
            ThrowSyntaxError("Unexpected token, expected '}'.");
        }

        expressions.push_back(expression);
    }

    auto *templateNode = AllocNode<ir::TemplateLiteral>(std::move(quasis), std::move(expressions));
    templateNode->SetRange({startLoc, lexer_->GetToken().End()});

    lexer_->NextToken();

    return templateNode;
}

ir::Expression *ParserImpl::ParseNewExpression()
{
    lexer::SourcePosition start = lexer_->GetToken().Start();

    lexer_->NextToken();  // eat new

    // parse callee part of NewExpression
    ir::Expression *callee = ParseMemberExpression(true);
    if (callee->IsImportExpression() && !callee->IsGrouped()) {
        ThrowSyntaxError("Cannot use new with import(...)");
    }

    ArenaVector<ir::Expression *> arguments(Allocator()->Adapter());

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        lexer::SourcePosition endLoc = callee->End();
        auto *newExprNode = AllocNode<ir::NewExpression>(callee, std::move(arguments));
        newExprNode->SetRange({start, endLoc});

        return newExprNode;
    }

    lexer_->NextToken();  // eat left parenthesis

    // parse argument part of NewExpression
    while (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ir::Expression *argument = nullptr;

        if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD) {
            argument = ParseSpreadElement();
        } else {
            argument = ParseExpression();
        }

        arguments.push_back(argument);

        if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
            lexer_->NextToken();  // eat comma
        }

        if (lexer_->GetToken().Type() == lexer::TokenType::EOS) {
            ThrowSyntaxError("Unexpected token in argument parsing");
        }
    }

    auto *newExprNode = AllocNode<ir::NewExpression>(callee, std::move(arguments));
    newExprNode->SetRange({start, lexer_->GetToken().End()});

    lexer_->NextToken();

    return newExprNode;
}

ir::Expression *ParserImpl::ParseLeftHandSideExpression(ExpressionParseFlags flags)
{
    return ParseMemberExpression(false, flags);
}

ir::MetaProperty *ParserImpl::ParsePotentialNewTarget()
{
    lexer::SourceRange loc = lexer_->GetToken().Loc();

    if (lexer_->Lookahead() == lexer::LEX_CHAR_DOT) {
        lexer_->NextToken();
        lexer_->NextToken();

        if (lexer_->GetToken().KeywordType() == lexer::TokenType::KEYW_TARGET) {
            if ((context_.Status() & ParserStatus::ALLOW_NEW_TARGET) == 0) {
                ThrowSyntaxError("'new.Target' is not allowed here");
            }

            if ((lexer_->GetToken().Flags() & lexer::TokenFlags::HAS_ESCAPE) != 0) {
                ThrowSyntaxError("'new.Target' must not contain escaped characters");
            }

            auto *metaProperty = AllocNode<ir::MetaProperty>(ir::MetaProperty::MetaPropertyKind::NEW_TARGET);
            metaProperty->SetRange(loc);
            lexer_->NextToken();
            return metaProperty;
        }
    }

    return nullptr;
}

ir::Identifier *ParserImpl::ParsePrimaryExpressionIdent([[maybe_unused]] ExpressionParseFlags flags)
{
    auto *identNode = AllocNode<ir::Identifier>(lexer_->GetToken().Ident(), Allocator());
    identNode->SetRange(lexer_->GetToken().Loc());

    lexer_->NextToken();
    return identNode;
}

ir::BooleanLiteral *ParserImpl::ParseBooleanLiteral()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::LITERAL_TRUE ||
           lexer_->GetToken().Type() == lexer::TokenType::LITERAL_FALSE);

    auto *booleanNode = AllocNode<ir::BooleanLiteral>(lexer_->GetToken().Type() == lexer::TokenType::LITERAL_TRUE);
    booleanNode->SetRange(lexer_->GetToken().Loc());

    lexer_->NextToken();
    return booleanNode;
}

ir::NullLiteral *ParserImpl::ParseNullLiteral()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::LITERAL_NULL);
    auto *nullNode = AllocNode<ir::NullLiteral>();
    nullNode->SetRange(lexer_->GetToken().Loc());

    lexer_->NextToken();
    return nullNode;
}

ir::Literal *ParserImpl::ParseNumberLiteral()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::LITERAL_NUMBER);

    ir::Literal *numberNode {};

    if ((lexer_->GetToken().Flags() & lexer::TokenFlags::NUMBER_BIGINT) != 0U) {
        numberNode = AllocNode<ir::BigIntLiteral>(lexer_->GetToken().BigInt());
    } else {
        numberNode = AllocNode<ir::NumberLiteral>(lexer_->GetToken().GetNumber());
    }

    numberNode->SetRange(lexer_->GetToken().Loc());

    lexer_->NextToken();
    return numberNode;
}

ir::CharLiteral *ParserImpl::ParseCharLiteral()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::LITERAL_CHAR);

    auto *charNode = AllocNode<ir::CharLiteral>(lexer_->GetToken().Utf16());
    charNode->SetRange(lexer_->GetToken().Loc());

    lexer_->NextToken();
    return charNode;
}

ir::StringLiteral *ParserImpl::ParseStringLiteral()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::LITERAL_STRING);

    auto *stringNode = AllocNode<ir::StringLiteral>(lexer_->GetToken().String());
    stringNode->SetRange(lexer_->GetToken().Loc());

    lexer_->NextToken();
    return stringNode;
}

ir::UndefinedLiteral *ParserImpl::ParseUndefinedLiteral()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::KEYW_UNDEFINED);
    auto *undefinedNode = AllocNode<ir::UndefinedLiteral>();
    undefinedNode->SetRange(lexer_->GetToken().Loc());

    lexer_->NextToken();
    return undefinedNode;
}

ir::ThisExpression *ParserImpl::ParseThisExpression()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::KEYW_THIS);

    auto *thisExprNode = AllocNode<ir::ThisExpression>();
    thisExprNode->SetRange(lexer_->GetToken().Loc());

    lexer_->NextToken();
    return thisExprNode;
}

ir::RegExpLiteral *ParserImpl::ParseRegularExpression()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_DIVIDE ||
           lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_DIVIDE_EQUAL);

    lexer_->ResetTokenEnd();
    auto regexp = lexer_->ScanRegExp();

    lexer::RegExpParser reParser(regexp, Allocator(), *this);

    reParser.ParsePattern();

    auto *regexpNode = AllocNode<ir::RegExpLiteral>(regexp.patternStr, regexp.flags, regexp.flagsStr);
    regexpNode->SetRange(lexer_->GetToken().Loc());

    lexer_->NextToken();
    return regexpNode;
}

ir::SuperExpression *ParserImpl::ParseSuperExpression()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::KEYW_SUPER);

    auto *superExprNode = AllocNode<ir::SuperExpression>();
    superExprNode->SetRange(lexer_->GetToken().Loc());

    lexer_->NextToken();  // eat super

    if ((lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD ||
         lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) &&
        (context_.Status() & ParserStatus::ALLOW_SUPER) != 0U) {
        return superExprNode;
    }

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS &&
        (context_.Status() & ParserStatus::ALLOW_SUPER_CALL) != 0U) {
        return superExprNode;
    }

    ThrowSyntaxError("Unexpected super keyword");
}

ir::Expression *ParserImpl::ParsePrimaryExpressionWithLiterals(ExpressionParseFlags flags)
{
    switch (lexer_->GetToken().Type()) {
        case lexer::TokenType::LITERAL_IDENT: {
            return ParsePrimaryExpressionIdent(flags);
        }
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
        default: {
            break;
        }
    }

    ThrowSyntaxError({"Unexpected token '", lexer::TokenToString(lexer_->GetToken().Type()), "'."});
    return nullptr;
}

ir::Expression *ParserImpl::ParseHashMaskOperator()
{
    ValidatePrivateIdentifier();
    auto *privateIdent = AllocNode<ir::Identifier>(lexer_->GetToken().Ident(), Allocator());
    privateIdent->SetPrivate(true);
    lexer_->NextToken();

    if (lexer_->GetToken().Type() != lexer::TokenType::KEYW_IN) {
        ThrowSyntaxError("Unexpected private identifier");
    }

    return privateIdent;
}

ir::Expression *ParserImpl::ParseClassExpression()
{
    lexer::SourcePosition startLoc = lexer_->GetToken().Start();
    ir::ClassDefinition *classDefinition = ParseClassDefinition(ir::ClassDefinitionModifiers::ID_REQUIRED);

    auto *classExpr = AllocNode<ir::ClassExpression>(classDefinition);
    classExpr->SetRange({startLoc, classDefinition->End()});

    return classExpr;
}

ir::Expression *ParserImpl::ParsePunctuators(ExpressionParseFlags flags)
{
    switch (lexer_->GetToken().Type()) {
        case lexer::TokenType::PUNCTUATOR_DIVIDE:
        case lexer::TokenType::PUNCTUATOR_DIVIDE_EQUAL: {
            return ParseRegularExpression();
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET: {
            return ParseArrayExpression(CarryPatternFlags(flags));
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS: {
            return ParseCoverParenthesizedExpressionAndArrowParameterList();
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_BRACE: {
            return ParseObjectExpression(CarryPatternFlags(flags));
        }
        case lexer::TokenType::PUNCTUATOR_BACK_TICK: {
            return ParseTemplateLiteral();
        }
        case lexer::TokenType::PUNCTUATOR_HASH_MARK: {
            return ParseHashMaskOperator();
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN: {
            return ParsePrefixAssertionExpression();
        }
        default: {
            UNREACHABLE();
        }
    }
    return nullptr;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ParserImpl::ParsePrimaryExpression(ExpressionParseFlags flags)
{
    switch (lexer_->GetToken().Type()) {
        case lexer::TokenType::KEYW_IMPORT: {
            return ParseImportExpression();
        }
        case lexer::TokenType::PUNCTUATOR_DIVIDE:
        case lexer::TokenType::PUNCTUATOR_DIVIDE_EQUAL:
        case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET:
        case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS:
        case lexer::TokenType::PUNCTUATOR_LEFT_BRACE:
        case lexer::TokenType::PUNCTUATOR_BACK_TICK:
        case lexer::TokenType::PUNCTUATOR_HASH_MARK:
        case lexer::TokenType::PUNCTUATOR_LESS_THAN: {
            return ParsePunctuators(flags);
        }
        case lexer::TokenType::KEYW_FUNCTION: {
            return ParseFunctionExpression();
        }
        case lexer::TokenType::KEYW_CLASS: {
            return ParseClassExpression();
        }
        case lexer::TokenType::KEYW_THIS: {
            return ParseThisExpression();
        }
        case lexer::TokenType::KEYW_TYPEOF: {
            return ParseUnaryOrPrefixUpdateExpression();
        }
        case lexer::TokenType::KEYW_SUPER: {
            return ParseSuperExpression();
        }
        case lexer::TokenType::KEYW_NEW: {
            ir::MetaProperty *newTarget = ParsePotentialNewTarget();

            if (newTarget != nullptr) {
                return newTarget;
            }

            return ParseNewExpression();
        }
        default: {
            break;
        }
    }

    return ParsePrimaryExpressionWithLiterals(flags);
}

static constexpr size_t GetOperatorPrecedenceArithmeticAndComparison(const lexer::TokenType operatorType)
{
    switch (operatorType) {
        case lexer::TokenType::PUNCTUATOR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_STRICT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL: {
            constexpr auto PRECEDENCE = 8;
            return PRECEDENCE;
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN:
        case lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL:
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN:
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL:
        case lexer::TokenType::KEYW_INSTANCEOF:
        case lexer::TokenType::KEYW_IN: {
            constexpr auto PRECEDENCE = 9;
            return PRECEDENCE;
        }
        case lexer::TokenType::PUNCTUATOR_PLUS:
        case lexer::TokenType::PUNCTUATOR_MINUS: {
            constexpr auto PRECEDENCE = 12;
            return PRECEDENCE;
        }
        case lexer::TokenType::PUNCTUATOR_MULTIPLY:
        case lexer::TokenType::PUNCTUATOR_DIVIDE:
        case lexer::TokenType::PUNCTUATOR_MOD: {
            constexpr auto PRECEDENCE = 13;
            return PRECEDENCE;
        }
        default: {
            UNREACHABLE();
        }
    }
}

static constexpr size_t GetOperatorPrecedence(const lexer::TokenType operatorType)
{
    ASSERT(operatorType == lexer::TokenType::KEYW_AS || lexer::Token::IsBinaryToken(operatorType));

    switch (operatorType) {
        case lexer::TokenType::PUNCTUATOR_NULLISH_COALESCING: {
            constexpr auto PRECEDENCE = 1;
            return PRECEDENCE;
        }
        case lexer::TokenType::PUNCTUATOR_LOGICAL_OR: {
            constexpr auto PRECEDENCE = 2;
            return PRECEDENCE;
        }
        case lexer::TokenType::PUNCTUATOR_LOGICAL_AND: {
            constexpr auto PRECEDENCE = 4;
            return PRECEDENCE;
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR: {
            constexpr auto PRECEDENCE = 5;
            return PRECEDENCE;
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR: {
            constexpr auto PRECEDENCE = 6;
            return PRECEDENCE;
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND: {
            constexpr auto PRECEDENCE = 7;
            return PRECEDENCE;
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT: {
            constexpr auto PRECEDENCE = 10;
            return PRECEDENCE;
        }
        case lexer::TokenType::KEYW_AS: {
            constexpr auto PRECEDENCE = 11;
            return PRECEDENCE;
        }
        case lexer::TokenType::PUNCTUATOR_EXPONENTIATION: {
            constexpr auto PRECEDENCE = 14;
            return PRECEDENCE;
        }
        default: {
            return GetOperatorPrecedenceArithmeticAndComparison(operatorType);
        }
    }
}

static inline bool ShouldBinaryExpressionBeAmended(const ir::BinaryExpression *const binaryExpression,
                                                   const lexer::TokenType operatorType)
{
    return GetOperatorPrecedence(binaryExpression->OperatorType()) <= GetOperatorPrecedence(operatorType) &&
           !binaryExpression->IsGrouped() &&
           (operatorType != lexer::TokenType::PUNCTUATOR_EXPONENTIATION ||
            binaryExpression->OperatorType() != lexer::TokenType::PUNCTUATOR_EXPONENTIATION);
}

static inline bool ShouldAsExpressionBeAmended(const ir::TSAsExpression *const asExpression,
                                               const lexer::TokenType operatorType)
{
    return GetOperatorPrecedence(lexer::TokenType::KEYW_AS) <= GetOperatorPrecedence(operatorType) &&
           !asExpression->IsGrouped() && operatorType != lexer::TokenType::PUNCTUATOR_EXPONENTIATION;
}

static inline bool ShouldExpressionBeAmended(const ir::Expression *const expression,
                                             const lexer::TokenType operatorType)
{
    bool shouldBeAmended = false;

    if (expression->IsBinaryExpression()) {
        shouldBeAmended = ShouldBinaryExpressionBeAmended(expression->AsBinaryExpression(), operatorType);
    } else if (expression->IsTSAsExpression()) {
        shouldBeAmended = ShouldAsExpressionBeAmended(expression->AsTSAsExpression(), operatorType);
    }

    return shouldBeAmended;
}

static inline bool AreLogicalAndNullishMixedIncorrectly(const ir::Expression *const expression,
                                                        const lexer::TokenType operatorType)
{
    return ((operatorType == lexer::TokenType::PUNCTUATOR_LOGICAL_OR ||
             operatorType == lexer::TokenType::PUNCTUATOR_LOGICAL_AND) &&
            expression->IsBinaryExpression() &&
            expression->AsBinaryExpression()->OperatorType() == lexer::TokenType::PUNCTUATOR_NULLISH_COALESCING &&
            !expression->IsGrouped()) ||
           (operatorType == lexer::TokenType::PUNCTUATOR_NULLISH_COALESCING && expression->IsBinaryExpression() &&
            (expression->AsBinaryExpression()->OperatorType() == lexer::TokenType::PUNCTUATOR_LOGICAL_OR ||
             expression->AsBinaryExpression()->OperatorType() == lexer::TokenType::PUNCTUATOR_LOGICAL_AND) &&
            !expression->IsGrouped());
}

static inline ir::Expression *GetAmendedChildExpression(ir::Expression *const expression)
{
    ir::Expression *amendedChild = nullptr;

    if (expression->IsBinaryExpression()) {
        amendedChild = expression->AsBinaryExpression()->Left();
    } else if (expression->IsTSAsExpression()) {
        amendedChild = expression->AsTSAsExpression()->Expr();
    } else {
        UNREACHABLE();
    }

    return amendedChild;
}

static inline void SetAmendedChildExpression(ir::Expression *const parent, ir::Expression *const amended)
{
    if (parent->IsBinaryExpression()) {
        parent->AsBinaryExpression()->SetLeft(amended);
        amended->SetParent(parent);
    } else if (parent->IsTSAsExpression()) {
        parent->AsTSAsExpression()->SetExpr(amended);
        amended->SetParent(parent);
    } else {
        UNREACHABLE();
    }
}

void ParserImpl::CreateAmendedBinaryExpression(ir::Expression *const left, ir::Expression *const right,
                                               const lexer::TokenType operatorType)
{
    auto *amended = GetAmendedChildExpression(right);

    amended->SetParent(nullptr);  // Next line overwrite parent
    auto *binaryExpr = AllocNode<ir::BinaryExpression>(left, amended, operatorType);

    binaryExpr->SetRange({left->Start(), amended->End()});
    SetAmendedChildExpression(right, binaryExpr);
}

ir::Expression *ParserImpl::ParseExpressionOrTypeAnnotation([[maybe_unused]] lexer::TokenType type,
                                                            [[maybe_unused]] ExpressionParseFlags flags)
{
    return ParseExpression(ExpressionParseFlags::DISALLOW_YIELD);
}

ir::Expression *ParserImpl::ParseBinaryExpression(ir::Expression *left, ExpressionParseFlags flags)
{
    lexer::TokenType operatorType = lexer_->GetToken().Type();
    ASSERT(lexer::Token::IsBinaryToken(operatorType));

    if (operatorType == lexer::TokenType::PUNCTUATOR_EXPONENTIATION) {
        if ((left->IsUnaryExpression() || left->IsTypeofExpression()) && !left->IsGrouped()) {
            ThrowSyntaxError(
                "Illegal expression. Wrap left hand side or entire "
                "exponentiation in parentheses.");
        }
    }

    lexer_->NextToken();

    ExpressionParseFlags newFlags = ExpressionParseFlags::DISALLOW_YIELD;
    if ((operatorType == lexer::TokenType::KEYW_INSTANCEOF) || ((flags & ExpressionParseFlags::INSTANCEOF) != 0)) {
        newFlags |= ExpressionParseFlags::INSTANCEOF;
    }

    ir::Expression *rightExpr = ParseExpressionOrTypeAnnotation(operatorType, ExpressionParseFlags::DISALLOW_YIELD);
    ir::ConditionalExpression *conditionalExpr = nullptr;

    if (rightExpr->IsConditionalExpression() && !rightExpr->IsGrouped()) {
        conditionalExpr = rightExpr->AsConditionalExpression();
        rightExpr = conditionalExpr->Test();
    }

    if (ShouldExpressionBeAmended(rightExpr, operatorType)) {
        if (AreLogicalAndNullishMixedIncorrectly(rightExpr, operatorType)) {
            ThrowSyntaxError("Nullish coalescing operator ?? requires parens when mixing with logical operators.");
        }

        bool shouldBeAmended = true;

        ir::Expression *expression = rightExpr;
        ir::Expression *parentExpression = nullptr;

        while (shouldBeAmended && GetAmendedChildExpression(expression)->IsBinaryExpression()) {
            parentExpression = expression;
            parentExpression->SetStart(left->Start());

            expression = GetAmendedChildExpression(expression);

            shouldBeAmended = ShouldExpressionBeAmended(expression, operatorType);
        }

        CreateAmendedBinaryExpression(left, shouldBeAmended ? expression : parentExpression, operatorType);
    } else {
        if (AreLogicalAndNullishMixedIncorrectly(rightExpr, operatorType)) {
            ThrowSyntaxError("Nullish coalescing operator ?? requires parens when mixing with logical operators.");
        }
        const lexer::SourcePosition &endPos = rightExpr->End();
        rightExpr = AllocNode<ir::BinaryExpression>(left, rightExpr, operatorType);
        rightExpr->SetRange({left->Start(), endPos});
    }

    if (conditionalExpr != nullptr) {
        conditionalExpr->SetStart(rightExpr->Start());
        conditionalExpr->SetTest(rightExpr);
        return conditionalExpr;
    }

    return rightExpr;
}

ArenaVector<ir::Expression *> ParserImpl::ParseCallExpressionArguments(bool &trailingComma)
{
    ArenaVector<ir::Expression *> arguments(Allocator()->Adapter());

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_FORMAT &&
        lexer_->Lookahead() == static_cast<char32_t>(ARRAY_FORMAT_NODE)) {
        arguments = std::move(ParseExpressionsArrayFormatPlaceholder());
        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
            ThrowSyntaxError("Expected a ')'");
        }
    } else {
        while (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
            trailingComma = false;
            ir::Expression *argument {};
            if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD) {
                argument = ParseSpreadElement();
            } else {
                argument = ParseExpression();
            }

            arguments.push_back(argument);

            if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
                lexer_->NextToken();
                trailingComma = true;
            } else if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
                ThrowSyntaxError("Expected a ')'");
            }
        }
    }

    return arguments;
}

ir::CallExpression *ParserImpl::ParseCallExpression(ir::Expression *callee, bool isOptionalChain, bool handleEval)
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
    bool trailingComma {};

    while (true) {
        lexer_->NextToken();
        ArenaVector<ir::Expression *> arguments = ParseCallExpressionArguments(trailingComma);
        ir::CallExpression *callExpr {};

        if (!isOptionalChain && handleEval && callee->IsIdentifier() && callee->AsIdentifier()->Name().Is("eval")) {
            auto parserStatus = static_cast<uint32_t>(context_.Status() | ParserStatus::DIRECT_EVAL);
            callExpr = AllocNode<ir::DirectEvalExpression>(callee, std::move(arguments), nullptr, isOptionalChain,
                                                           parserStatus);
        } else {
            callExpr =
                AllocNode<ir::CallExpression>(callee, std::move(arguments), nullptr, isOptionalChain, trailingComma);
        }

        callExpr->SetRange({callee->Start(), lexer_->GetToken().End()});
        isOptionalChain = false;

        lexer_->NextToken();

        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
            ParseTrailingBlock(callExpr);
            return callExpr;
        }

        callee = callExpr;
    }

    UNREACHABLE();
}

ir::Expression *ParserImpl::ParseOptionalChain(ir::Expression *leftSideExpr)
{
    ir::Expression *returnExpression = nullptr;

    bool isPrivate = false;

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_HASH_MARK) {
        isPrivate = true;
        ValidatePrivateIdentifier();
    }

    const auto tokenType = lexer_->GetToken().Type();
    if (tokenType == lexer::TokenType::LITERAL_IDENT) {
        auto *identNode = AllocNode<ir::Identifier>(lexer_->GetToken().Ident(), Allocator());
        identNode->SetPrivate(isPrivate);
        identNode->SetRange(lexer_->GetToken().Loc());

        returnExpression = AllocNode<ir::MemberExpression>(leftSideExpr, identNode,
                                                           ir::MemberExpressionKind::PROPERTY_ACCESS, false, true);
        returnExpression->SetRange({leftSideExpr->Start(), identNode->End()});
        lexer_->NextToken();
    }

    if (tokenType == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
        lexer_->NextToken();  // eat '['
        ir::Expression *propertyNode = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA);

        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
            ThrowSyntaxError("Unexpected token");
        }

        returnExpression = AllocNode<ir::MemberExpression>(leftSideExpr, propertyNode,
                                                           ir::MemberExpressionKind::ELEMENT_ACCESS, true, true);
        returnExpression->SetRange({leftSideExpr->Start(), lexer_->GetToken().End()});
        lexer_->NextToken();
    }

    if (tokenType == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        returnExpression = ParseCallExpression(leftSideExpr, true);
    }

    // Static semantic
    if (tokenType == lexer::TokenType::PUNCTUATOR_BACK_TICK ||
        lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_BACK_TICK) {
        ThrowSyntaxError("Tagged Template Literals are not allowed in optionalChain");
    }

    return returnExpression;
}

ir::ArrowFunctionExpression *ParserImpl::ParsePotentialArrowExpression(ir::Expression **returnExpression,
                                                                       const lexer::SourcePosition &startLoc)
{
    switch (lexer_->GetToken().Type()) {
        case lexer::TokenType::KEYW_FUNCTION: {
            *returnExpression = ParseFunctionExpression(ParserStatus::ASYNC_FUNCTION);
            (*returnExpression)->SetStart(startLoc);
            break;
        }
        case lexer::TokenType::LITERAL_IDENT: {
            ir::Expression *identRef = ParsePrimaryExpression();
            ASSERT(identRef->IsIdentifier());

            if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_ARROW) {
                ThrowSyntaxError("Unexpected token, expected '=>'");
            }

            ir::ArrowFunctionExpression *arrowFuncExpr = ParseArrowFunctionExpression(identRef, nullptr, nullptr, true);
            arrowFuncExpr->SetStart(startLoc);

            return arrowFuncExpr;
        }
        case lexer::TokenType::PUNCTUATOR_ARROW: {
            ir::ArrowFunctionExpression *arrowFuncExpr =
                ParseArrowFunctionExpression(*returnExpression, nullptr, nullptr, true);
            arrowFuncExpr->SetStart(startLoc);
            return arrowFuncExpr;
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS: {
            ir::CallExpression *callExpression = ParseCallExpression(*returnExpression, false);

            if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_ARROW) {
                ir::ArrowFunctionExpression *arrowFuncExpr =
                    ParseArrowFunctionExpression(callExpression, nullptr, nullptr, true);
                arrowFuncExpr->SetStart(startLoc);

                return arrowFuncExpr;
            }

            *returnExpression = callExpression;
            break;
        }
        default: {
            break;
        }
    }

    return nullptr;
}

bool ParserImpl::ParsePotentialGenericFunctionCall([[maybe_unused]] ir::Expression *primaryExpr,
                                                   [[maybe_unused]] ir::Expression **returnExpression,
                                                   [[maybe_unused]] const lexer::SourcePosition &startLoc,
                                                   [[maybe_unused]] bool ignoreCallExpression)
{
    return true;
}

bool ParserImpl::ParsePotentialNonNullExpression([[maybe_unused]] ir::Expression **returnExpression,
                                                 [[maybe_unused]] lexer::SourcePosition startLoc)
{
    return true;
}

ir::Expression *ParserImpl::ParsePotentialAsExpression([[maybe_unused]] ir::Expression *primaryExpression)
{
    return nullptr;
}

ir::MemberExpression *ParserImpl::ParseElementAccess(ir::Expression *primaryExpr, bool isOptional)
{
    lexer_->NextToken();  // eat '['
    ir::Expression *propertyNode = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA);

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
        ThrowSyntaxError("Unexpected token");
    }

    auto *memberExpr = AllocNode<ir::MemberExpression>(primaryExpr, propertyNode,
                                                       ir::MemberExpressionKind::ELEMENT_ACCESS, true, isOptional);
    memberExpr->SetRange({primaryExpr->Start(), lexer_->GetToken().End()});
    lexer_->NextToken();
    return memberExpr;
}

ir::MemberExpression *ParserImpl::ParsePrivatePropertyAccess(ir::Expression *primaryExpr)
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_HASH_MARK);

    lexer::SourcePosition memberStart = lexer_->GetToken().Start();
    ValidatePrivateIdentifier();

    auto *privateIdent = AllocNode<ir::Identifier>(lexer_->GetToken().Ident(), Allocator());
    privateIdent->SetRange({memberStart, lexer_->GetToken().End()});
    privateIdent->SetPrivate(true);
    lexer_->NextToken();

    auto *memberExpr = AllocNode<ir::MemberExpression>(primaryExpr, privateIdent,
                                                       ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
    memberExpr->SetRange({primaryExpr->Start(), privateIdent->End()});
    return memberExpr;
}

ir::MemberExpression *ParserImpl::ParsePropertyAccess(ir::Expression *primaryExpr, bool isOptional)
{
    ir::Identifier *ident = ExpectIdentifier(true);
    if (ident == nullptr) {  // Error processing.
        return nullptr;
    }

    auto *memberExpr = AllocNode<ir::MemberExpression>(primaryExpr, ident, ir::MemberExpressionKind::PROPERTY_ACCESS,
                                                       false, isOptional);
    memberExpr->SetRange({primaryExpr->Start(), ident->End()});

    return memberExpr;
}

ir::Expression *ParserImpl::ParsePostPrimaryExpression(ir::Expression *primaryExpr, lexer::SourcePosition startLoc,
                                                       bool ignoreCallExpression, bool *isChainExpression)
{
    ir::Expression *returnExpr = primaryExpr;
    while (true) {
        switch (lexer_->GetToken().Type()) {
            case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET: {
                returnExpr = ParseElementAccess(returnExpr);
                continue;
            }
            case lexer::TokenType::LITERAL_IDENT: {
                if (auto *asExpression = ParsePotentialAsExpression(returnExpr); asExpression != nullptr) {
                    return asExpression;
                }
                break;
            }
            case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT:
            case lexer::TokenType::PUNCTUATOR_LESS_THAN: {
                if (ParsePotentialGenericFunctionCall(primaryExpr, &returnExpr, startLoc, ignoreCallExpression)) {
                    break;
                }
                continue;
            }
            case lexer::TokenType::PUNCTUATOR_BACK_TICK: {
                returnExpr = ParsePostPrimaryExpressionBackTick(returnExpr, startLoc);
                continue;
            }
            case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS: {
                if (ignoreCallExpression) {
                    break;
                }
                returnExpr = ParseCallExpression(returnExpr, false);
                continue;
            }
            case lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK: {
                if (ParsePotentialNonNullExpression(&returnExpr, startLoc)) {
                    break;
                }
                continue;
            }
            default: {
                auto tmp = ParsePostPrimaryExpressionDot(returnExpr, lexer_->GetToken().Type(), isChainExpression);
                if (tmp != nullptr) {
                    returnExpr = tmp;
                    continue;
                }
            }
        }
        break;
    }
    return returnExpr;
}

ir::Expression *ParserImpl::ParsePostPrimaryExpressionBackTick(ir::Expression *returnExpression,
                                                               const lexer::SourcePosition startLoc)
{
    ir::TemplateLiteral *propertyNode = ParseTemplateLiteral();
    lexer::SourcePosition endLoc = propertyNode->End();

    returnExpression = AllocNode<ir::TaggedTemplateExpression>(returnExpression, propertyNode, nullptr);
    returnExpression->SetRange({startLoc, endLoc});

    return returnExpression;
}

ir::Expression *ParserImpl::ParsePostPrimaryExpressionDot(ir::Expression *returnExpression,
                                                          const lexer::TokenType tokenType, bool *isChainExpression)
{
    switch (tokenType) {
        case lexer::TokenType::PUNCTUATOR_QUESTION_DOT: {
            *isChainExpression = true;
            lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat ?.
            return ParseOptionalChain(returnExpression);
        }
        case lexer::TokenType::PUNCTUATOR_PERIOD: {
            lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat period

            if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_HASH_MARK) {
                return ParsePrivatePropertyAccess(returnExpression);
            }

            return ParsePropertyAccess(returnExpression);
        }
        default: {
            break;
        }
    }

    return nullptr;
}

void ParserImpl::ValidateUpdateExpression(ir::Expression *returnExpression, bool isChainExpression)
{
    if ((!returnExpression->IsMemberExpression() && !returnExpression->IsIdentifier() &&
         !returnExpression->IsTSNonNullExpression()) ||
        isChainExpression) {
        ThrowSyntaxError("Invalid left-hand side operator.");
    }

    if (returnExpression->IsIdentifier()) {
        const util::StringView &returnExpressionStr = returnExpression->AsIdentifier()->Name();

        if (returnExpressionStr.Is("eval")) {
            ThrowSyntaxError("Assigning to 'eval' in strict mode is invalid");
        }

        if (returnExpressionStr.Is("arguments")) {
            ThrowSyntaxError("Assigning to 'arguments' in strict mode is invalid");
        }
    }
}

ir::Expression *ParserImpl::SetupChainExpr(ir::Expression *const top, lexer::SourcePosition startLoc)
{
    auto expr = top;
    while (expr->IsTSNonNullExpression()) {
        expr = expr->AsTSNonNullExpression()->Expr();
    }
    auto chainParent = expr->Parent();

    lexer::SourcePosition endLoc = expr->End();
    auto chain = AllocNode<ir::ChainExpression>(expr);
    chain->SetRange({startLoc, endLoc});

    if (expr == top) {
        return chain;
    }
    chainParent->AsTSNonNullExpression()->SetExpr(chain);
    chain->SetParent(chainParent);
    return top;
}

ir::Expression *ParserImpl::ParseMemberExpression(bool ignoreCallExpression, ExpressionParseFlags flags)
{
    bool isAsync = lexer_->GetToken().IsAsyncModifier();
    lexer::SourcePosition startLoc = lexer_->GetToken().Start();
    ir::Expression *returnExpression = ParsePrimaryExpression(flags);
    if (returnExpression == nullptr) {  // Error processing.
        return nullptr;
    }

    if (lexer_->GetToken().NewLine() && returnExpression->IsArrowFunctionExpression()) {
        return returnExpression;
    }

    if (isAsync && !lexer_->GetToken().NewLine()) {
        context_.Status() |= ParserStatus::ASYNC_FUNCTION;
        ir::ArrowFunctionExpression *arrow = ParsePotentialArrowExpression(&returnExpression, startLoc);

        if (arrow != nullptr) {
            return arrow;
        }
    }

    bool isChainExpression;
    ir::Expression *prevExpression;
    do {
        isChainExpression = false;
        prevExpression = returnExpression;
        returnExpression =
            ParsePostPrimaryExpression(returnExpression, startLoc, ignoreCallExpression, &isChainExpression);
        if (isChainExpression) {
            returnExpression = SetupChainExpr(returnExpression, startLoc);
        }
    } while (prevExpression != returnExpression);

    if (!lexer_->GetToken().NewLine() && lexer::Token::IsUpdateToken(lexer_->GetToken().Type())) {
        lexer::SourcePosition start = returnExpression->Start();

        ValidateUpdateExpression(returnExpression, isChainExpression);

        returnExpression = AllocNode<ir::UpdateExpression>(returnExpression, lexer_->GetToken().Type(), false);

        returnExpression->SetRange({start, lexer_->GetToken().End()});
        lexer_->NextToken();
    }

    return returnExpression;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ParserImpl::ParsePatternElement(ExpressionParseFlags flags, bool allowDefault)
{
    ir::Expression *returnNode = nullptr;

    switch (lexer_->GetToken().Type()) {
        case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET: {
            returnNode = ParseArrayExpression(ExpressionParseFlags::MUST_BE_PATTERN);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD: {
            if ((flags & ExpressionParseFlags::IN_REST) != 0) {
                ThrowSyntaxError("Unexpected token");
            }
            returnNode = ParseSpreadElement(ExpressionParseFlags::MUST_BE_PATTERN);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_BRACE: {
            returnNode =
                ParseObjectExpression(ExpressionParseFlags::MUST_BE_PATTERN | ExpressionParseFlags::OBJECT_PATTERN);
            break;
        }
        case lexer::TokenType::LITERAL_IDENT: {
            returnNode = AllocNode<ir::Identifier>(lexer_->GetToken().Ident(), Allocator());
            returnNode->SetRange(lexer_->GetToken().Loc());
            lexer_->NextToken();
            break;
        }
        default: {
            ThrowSyntaxError("Unexpected token, expected an identifier.");
        }
    }

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        return returnNode;
    }

    ParsePatternElementErrorCheck(flags, allowDefault);

    ir::Expression *rightNode = ParseExpression();

    auto *assignmentExpression = AllocNode<ir::AssignmentExpression>(
        ir::AstNodeType::ASSIGNMENT_PATTERN, returnNode, rightNode, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    assignmentExpression->SetRange({returnNode->Start(), rightNode->End()});

    return assignmentExpression;
}

void ParserImpl::ParsePatternElementErrorCheck(const ExpressionParseFlags flags, const bool allowDefault)
{
    if ((flags & ExpressionParseFlags::IN_REST) != 0) {
        ThrowSyntaxError("Unexpected token, expected ')'");
    }

    if (!allowDefault) {
        ThrowSyntaxError("Invalid destructuring assignment target");
    }

    lexer_->NextToken();

    if (context_.IsGenerator() && lexer_->GetToken().Type() == lexer::TokenType::KEYW_YIELD) {
        ThrowSyntaxError("Yield is not allowed in generator parameters");
    }

    if (context_.IsAsync() && lexer_->GetToken().Type() == lexer::TokenType::KEYW_AWAIT) {
        ThrowSyntaxError("Illegal await-expression in formal parameters of async function");
    }
}

void ParserImpl::CheckPropertyKeyAsyncModifier(ParserStatus *methodStatus)
{
    const auto asyncPos = lexer_->Save();
    lexer_->NextToken();

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS &&
        lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON &&
        lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COMMA &&
        lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        if (lexer_->GetToken().NewLine()) {
            ThrowSyntaxError(
                "Async methods cannot have a line terminator between "
                "'async' and the property name");
        }

        *methodStatus |= ParserStatus::ASYNC_FUNCTION;
    } else {
        lexer_->Rewind(asyncPos);
    }
}

static bool IsAccessorDelimiter(char32_t cp)
{
    switch (cp) {
        case lexer::LEX_CHAR_LEFT_PAREN:
        case lexer::LEX_CHAR_COLON:
        case lexer::LEX_CHAR_COMMA:
        case lexer::LEX_CHAR_RIGHT_BRACE: {
            return true;
        }
        default: {
            return false;
        }
    }
}

static bool IsShorthandDelimiter(char32_t cp)
{
    switch (cp) {
        case lexer::LEX_CHAR_EQUALS:
        case lexer::LEX_CHAR_COMMA:
        case lexer::LEX_CHAR_RIGHT_BRACE: {
            return true;
        }
        default: {
            return false;
        }
    }
}

void ParserImpl::ValidateAccessor(ExpressionParseFlags flags, lexer::TokenFlags currentTokenFlags)
{
    if ((flags & ExpressionParseFlags::MUST_BE_PATTERN) != 0) {
        ThrowSyntaxError("Unexpected token");
    }

    if ((currentTokenFlags & lexer::TokenFlags::HAS_ESCAPE) != 0) {
        ThrowSyntaxError("Keyword must not contain escaped characters");
    }
}

ir::Property *ParserImpl::ParseShorthandProperty(const lexer::LexerPosition *startPos)
{
    char32_t nextCp = lexer_->Lookahead();
    lexer::TokenType keywordType = lexer_->GetToken().KeywordType();

    /* Rewind the lexer to the beginning of the ident to reparse as common
     * identifier */
    lexer_->Rewind(*startPos);
    lexer_->NextToken();
    lexer::SourcePosition start = lexer_->GetToken().Start();

    if (lexer_->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Expected an identifier");
    }

    const util::StringView &ident = lexer_->GetToken().Ident();

    auto *key = AllocNode<ir::Identifier>(ident, Allocator());
    key->SetRange(lexer_->GetToken().Loc());

    ir::Expression *value = AllocNode<ir::Identifier>(ident, Allocator());
    value->SetRange(lexer_->GetToken().Loc());

    lexer::SourcePosition end;

    if (nextCp == lexer::LEX_CHAR_EQUALS) {
        CheckRestrictedBinding(keywordType);

        lexer_->NextToken();  // substitution
        lexer_->NextToken();  // eat substitution

        ir::Expression *rightNode = ParseExpression();

        auto *assignmentExpression = AllocNode<ir::AssignmentExpression>(
            ir::AstNodeType::ASSIGNMENT_PATTERN, value, rightNode, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
        assignmentExpression->SetRange({value->Start(), rightNode->End()});
        end = rightNode->End();
        value = assignmentExpression;
    } else {
        end = lexer_->GetToken().End();
        lexer_->NextToken();
    }

    auto *returnProperty = AllocNode<ir::Property>(key, value);
    returnProperty->SetRange({start, end});

    return returnProperty;
}

bool ParserImpl::ParsePropertyModifiers(ExpressionParseFlags flags, ir::PropertyKind *propertyKind,
                                        ParserStatus *methodStatus)
{
    if (lexer_->GetToken().IsAsyncModifier()) {
        CheckPropertyKeyAsyncModifier(methodStatus);
    }

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY) {
        if ((flags & ExpressionParseFlags::MUST_BE_PATTERN) != 0) {
            ThrowSyntaxError("Unexpected token");
        }

        lexer_->NextToken();
        *methodStatus |= ParserStatus::GENERATOR_FUNCTION;
    }

    lexer::TokenFlags currentTokenFlags = lexer_->GetToken().Flags();
    char32_t nextCp = lexer_->Lookahead();
    lexer::TokenType keywordType = lexer_->GetToken().KeywordType();
    // Parse getter property
    if (keywordType == lexer::TokenType::KEYW_GET && !IsAccessorDelimiter(nextCp)) {
        ValidateAccessor(flags, currentTokenFlags);

        *propertyKind = ir::PropertyKind::GET;
        lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);

        return false;
    }

    // Parse setter property
    if (keywordType == lexer::TokenType::KEYW_SET && !IsAccessorDelimiter(nextCp)) {
        ValidateAccessor(flags, currentTokenFlags);

        *propertyKind = ir::PropertyKind::SET;
        lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);

        return false;
    }

    // Parse shorthand property or assignment pattern
    return (IsShorthandDelimiter(nextCp) && (*methodStatus & ParserStatus::ASYNC_FUNCTION) == 0);
}

void ParserImpl::ParseGeneratorPropertyModifier(ExpressionParseFlags flags, ParserStatus *methodStatus)
{
    if ((flags & ExpressionParseFlags::MUST_BE_PATTERN) != 0) {
        ThrowSyntaxError("Unexpected token");
    }

    lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
    *methodStatus |= ParserStatus::GENERATOR_FUNCTION;
}

ir::Expression *ParserImpl::ParsePropertyKey(ExpressionParseFlags flags)
{
    ir::Expression *key = nullptr;

    switch (lexer_->GetToken().Type()) {
        case lexer::TokenType::LITERAL_IDENT: {
            const util::StringView &ident = lexer_->GetToken().Ident();
            key = AllocNode<ir::Identifier>(ident, Allocator());
            key->SetRange(lexer_->GetToken().Loc());
            break;
        }
        case lexer::TokenType::LITERAL_STRING: {
            const util::StringView &string = lexer_->GetToken().String();
            key = AllocNode<ir::StringLiteral>(string);
            key->SetRange(lexer_->GetToken().Loc());
            break;
        }
        case lexer::TokenType::LITERAL_NUMBER: {
            if ((lexer_->GetToken().Flags() & lexer::TokenFlags::NUMBER_BIGINT) != 0) {
                key = AllocNode<ir::BigIntLiteral>(lexer_->GetToken().BigInt());
            } else {
                key = AllocNode<ir::NumberLiteral>(lexer_->GetToken().GetNumber());
            }

            key->SetRange(lexer_->GetToken().Loc());
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET: {
            lexer_->NextToken();  // eat left square bracket

            key = ParseExpression(flags | ExpressionParseFlags::ACCEPT_COMMA);

            if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
                ThrowSyntaxError("Unexpected token, expected ']'");
            }
            break;
        }
        default: {
            ThrowSyntaxError("Unexpected token in property key");
        }
    }

    lexer_->NextToken();
    return key;
}

ir::Expression *ParserImpl::ParsePropertyValue(const ir::PropertyKind *propertyKind, const ParserStatus *methodStatus,
                                               ExpressionParseFlags flags)
{
    bool isMethod = (*methodStatus & ParserStatus::FUNCTION) != 0;
    bool inPattern = (flags & ExpressionParseFlags::MUST_BE_PATTERN) != 0;

    if (!isMethod && !ir::Property::IsAccessorKind(*propertyKind)) {
        // If the actual property is not getter/setter nor method, the following
        // token must be ':'
        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
            ThrowSyntaxError("Unexpected token, expected ':'");
        }

        lexer_->NextToken();  // eat colon

        if (!inPattern) {
            return ParseExpression(flags);
        }

        return ParsePatternElement();
    }

    if (inPattern) {
        ThrowSyntaxError("Object pattern can't contain methods");
    }

    ParserStatus newStatus = *methodStatus | ParserStatus::FUNCTION | ParserStatus::ALLOW_SUPER;

    if (*propertyKind != ir::PropertyKind::SET) {
        newStatus |= ParserStatus::NEED_RETURN_TYPE;
    }

    ir::ScriptFunction *methodDefinitonNode = ParseFunction(newStatus);
    methodDefinitonNode->AddFlag(ir::ScriptFunctionFlags::METHOD);

    size_t paramsSize = methodDefinitonNode->Params().size();

    auto *value = AllocNode<ir::FunctionExpression>(methodDefinitonNode);
    value->SetRange(methodDefinitonNode->Range());

    if (*propertyKind == ir::PropertyKind::SET && paramsSize != 1) {
        ThrowSyntaxError("Setter must have exactly one formal parameter");
    }

    if (*propertyKind == ir::PropertyKind::GET && paramsSize != 0) {
        ThrowSyntaxError("Getter must not have formal parameters");
    }

    return value;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ParserImpl::ParsePropertyDefinition([[maybe_unused]] ExpressionParseFlags flags)
{
    ir::PropertyKind propertyKind = ir::PropertyKind::INIT;
    ParserStatus methodStatus = ParserStatus::NO_OPTS;

    const auto startPos = lexer_->Save();
    lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
    lexer::SourcePosition start = lexer_->GetToken().Start();

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD) {
        return ParseSpreadElement(flags);
    }

    if (lexer_->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
        if (ParsePropertyModifiers(flags, &propertyKind, &methodStatus)) {
            return ParseShorthandProperty(&startPos);
        }
    } else if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY) {
        ParseGeneratorPropertyModifier(flags, &methodStatus);
    }

    bool isComputed = lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET;
    ir::Expression *key = ParsePropertyKey(flags);

    // Parse method property
    if ((lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS ||
         lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) &&
        !ir::Property::IsAccessorKind(propertyKind)) {
        methodStatus |= ParserStatus::FUNCTION | ParserStatus::ALLOW_SUPER;
        propertyKind = ir::PropertyKind::INIT;
    } else if ((methodStatus & (ParserStatus::GENERATOR_FUNCTION | ParserStatus::ASYNC_FUNCTION)) != 0) {
        ThrowSyntaxError("Unexpected identifier");
    }

    ir::Expression *value = ParsePropertyValue(&propertyKind, &methodStatus, flags);
    lexer::SourcePosition end = value->End();

    ASSERT(key);
    ASSERT(value);

    auto *returnProperty =
        AllocNode<ir::Property>(propertyKind, key, value, methodStatus != ParserStatus::NO_OPTS, isComputed);
    returnProperty->SetRange({start, end});

    return returnProperty;
}

bool ParserImpl::ParsePropertyEnd()
{
    // Property definiton must end with ',' or '}' otherwise we throw SyntaxError
    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COMMA &&
        lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        ThrowSyntaxError("Unexpected token, expected ',' or '}'");
    }

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA &&
        lexer_->Lookahead() == lexer::LEX_CHAR_RIGHT_BRACE) {
        lexer_->NextToken();
        return true;
    }

    return false;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::ObjectExpression *ParserImpl::ParseObjectExpression(ExpressionParseFlags flags)
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE);
    lexer::SourcePosition start = lexer_->GetToken().Start();
    ArenaVector<ir::Expression *> properties(Allocator()->Adapter());
    bool trailingComma = false;
    bool inPattern = (flags & ExpressionParseFlags::MUST_BE_PATTERN) != 0;

    if (lexer_->Lookahead() == lexer::LEX_CHAR_RIGHT_BRACE) {
        lexer_->NextToken();
    }

    while (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        ir::Expression *property = ParsePropertyDefinition(flags | ExpressionParseFlags::POTENTIALLY_IN_PATTERN);
        properties.push_back(property);
        trailingComma = ParsePropertyEnd();
    }

    auto nodeType = inPattern ? ir::AstNodeType::OBJECT_PATTERN : ir::AstNodeType::OBJECT_EXPRESSION;
    auto *objectExpression =
        AllocNode<ir::ObjectExpression>(nodeType, Allocator(), std::move(properties), trailingComma);
    objectExpression->SetRange({start, lexer_->GetToken().End()});
    lexer_->NextToken();

    if (inPattern) {
        objectExpression->SetDeclaration();
    }

    if ((flags & ExpressionParseFlags::POTENTIALLY_IN_PATTERN) == 0) {
        if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION &&
            !objectExpression->ConvertibleToObjectPattern()) {
            ThrowSyntaxError("Invalid left-hand side in array destructuring pattern", objectExpression->Start());
        } else if (!inPattern && lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
            ir::ValidationInfo info = objectExpression->ValidateExpression();
            if (info.Fail()) {
                ThrowSyntaxError(info.msg.Utf8(), info.pos);
            }
        }
    }

    return objectExpression;
}

ir::SequenceExpression *ParserImpl::ParseSequenceExpression(ir::Expression *startExpr, bool acceptRest)
{
    lexer::SourcePosition start = startExpr->Start();

    ArenaVector<ir::Expression *> sequence(Allocator()->Adapter());
    sequence.push_back(startExpr);

    while (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
        lexer_->NextToken();

        if (acceptRest && lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD) {
            ir::SpreadElement *expr = ParseSpreadElement(ExpressionParseFlags::MUST_BE_PATTERN);
            sequence.push_back(expr);
            break;
        }

        if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS && lexer_->CheckArrow()) {
            break;
        }

        sequence.push_back(ParseExpression());
    }

    lexer::SourcePosition end = sequence.back()->End();
    auto *sequenceNode = AllocNode<ir::SequenceExpression>(std::move(sequence));
    sequenceNode->SetRange({start, end});

    return sequenceNode;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ParserImpl::ParseUnaryOrPrefixUpdateExpression(ExpressionParseFlags flags)
{
    if (!lexer_->GetToken().IsUnary()) {
        return ParseLeftHandSideExpression(flags);
    }

    lexer::TokenType operatorType = lexer_->GetToken().Type();
    lexer::SourcePosition start = lexer_->GetToken().Start();
    lexer_->NextToken();

    ir::Expression *argument =
        lexer_->GetToken().IsUnary() ? ParseUnaryOrPrefixUpdateExpression() : ParseLeftHandSideExpression();

    if (lexer::Token::IsUpdateToken(operatorType)) {
        if (!argument->IsIdentifier() && !argument->IsMemberExpression() && !argument->IsTSNonNullExpression()) {
            ThrowSyntaxError("Invalid left-hand side in prefix operation");
        }

        if (argument->IsIdentifier()) {
            const util::StringView &argumentStr = argument->AsIdentifier()->Name();

            if (argumentStr.Is("eval")) {
                ThrowSyntaxError("Assigning to 'eval' in strict mode is invalid");
            } else if (argumentStr.Is("arguments")) {
                ThrowSyntaxError("Assigning to 'arguments' in strict mode is invalid");
            }
        }
    }

    if (operatorType == lexer::TokenType::KEYW_DELETE) {
        if (argument->IsIdentifier()) {
            ThrowSyntaxError("Deleting local variable in strict mode");
        }

        if (argument->IsMemberExpression() && argument->AsMemberExpression()->Property()->IsIdentifier() &&
            argument->AsMemberExpression()->Property()->AsIdentifier()->IsPrivateIdent()) {
            ThrowSyntaxError("Private fields can not be deleted");
        }
    }

    lexer::SourcePosition end = argument->End();

    ir::Expression *returnExpr = nullptr;

    if (lexer::Token::IsUpdateToken(operatorType)) {
        returnExpr = AllocNode<ir::UpdateExpression>(argument, operatorType, true);
    } else if (operatorType == lexer::TokenType::KEYW_AWAIT) {
        returnExpr = AllocNode<ir::AwaitExpression>(argument);
    } else if (operatorType == lexer::TokenType::KEYW_TYPEOF) {
        returnExpr = AllocNode<ir::TypeofExpression>(argument);
    } else {
        returnExpr = AllocNode<ir::UnaryExpression>(argument, operatorType);
    }

    returnExpr->SetRange({start, end});

    return returnExpr;
}

ir::Expression *ParserImpl::ParseImportExpression()
{
    lexer::SourcePosition startLoc = lexer_->GetToken().Start();
    lexer::SourcePosition endLoc = lexer_->GetToken().End();
    lexer_->NextToken();  // eat import

    // parse import.Meta
    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD) {
        if (!context_.IsModule()) {
            ThrowSyntaxError("'import.Meta' may appear only with 'sourceType: module'");
        } else if (GetOptions().isDirectEval) {
            ThrowSyntaxError("'import.Meta' is not allowed in direct eval in module code.");
        }

        lexer_->NextToken();  // eat dot

        if (lexer_->GetToken().Type() != lexer::TokenType::LITERAL_IDENT ||
            lexer_->GetToken().KeywordType() != lexer::TokenType::KEYW_META) {
            ThrowSyntaxError("The only valid meta property for import is import.Meta");
        }

        auto *metaProperty = AllocNode<ir::MetaProperty>(ir::MetaProperty::MetaPropertyKind::IMPORT_META);
        metaProperty->SetRange({startLoc, endLoc});

        lexer_->NextToken();
        return metaProperty;
    }

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        ThrowSyntaxError("Unexpected token");
    }

    lexer_->NextToken();  // eat left parentheses

    ir::Expression *source = ParseExpression();

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError("Unexpected token");
    }

    auto *importExpression = AllocNode<ir::ImportExpression>(source);
    importExpression->SetRange({startLoc, lexer_->GetToken().End()});

    lexer_->NextToken();  // eat right paren
    return importExpression;
}

bool ParserImpl::IsNamedFunctionExpression()
{
    return lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS;
}

ir::FunctionExpression *ParserImpl::ParseFunctionExpression(ParserStatus newStatus)
{
    lexer::SourcePosition startLoc = lexer_->GetToken().Start();
    ir::Identifier *ident = nullptr;

    if ((newStatus & ParserStatus::ARROW_FUNCTION) == 0) {
        ParserStatus savedStatus = context_.Status();
        context_.Status() |= static_cast<ParserStatus>(newStatus & ParserStatus::ASYNC_FUNCTION);

        lexer_->NextToken();

        if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY) {
            newStatus |= ParserStatus::GENERATOR_FUNCTION;
            lexer_->NextToken();
        }

        if (IsNamedFunctionExpression()) {
            CheckRestrictedBinding(lexer_->GetToken().KeywordType());
            ident = ExpectIdentifier(false, true);
        }

        context_.Status() = savedStatus;
    }

    ir::ScriptFunction *functionNode = ParseFunction(newStatus);
    functionNode->SetStart(startLoc);

    auto *funcExpr = AllocNode<ir::FunctionExpression>(ident, functionNode);
    funcExpr->SetRange(functionNode->Range());

    return funcExpr;
}
}  // namespace ark::es2panda::parser
