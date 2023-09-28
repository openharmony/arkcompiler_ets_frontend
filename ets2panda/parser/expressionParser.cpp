/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "plugins/ecmascript/es2panda/lexer/token/tokenType.h"
#include "plugins/ecmascript/es2panda/parser/parserFlags.h"
#include "plugins/ecmascript/es2panda/compiler/core/compilerContext.h"
#include "plugins/ecmascript/es2panda/ir/astNode.h"
#include "plugins/ecmascript/es2panda/ir/base/classDefinition.h"
#include "plugins/ecmascript/es2panda/ir/base/decorator.h"
#include "plugins/ecmascript/es2panda/ir/base/metaProperty.h"
#include "plugins/ecmascript/es2panda/ir/base/methodDefinition.h"
#include "plugins/ecmascript/es2panda/ir/base/property.h"
#include "plugins/ecmascript/es2panda/ir/base/scriptFunction.h"
#include "plugins/ecmascript/es2panda/ir/base/spreadElement.h"
#include "plugins/ecmascript/es2panda/ir/base/templateElement.h"
#include "plugins/ecmascript/es2panda/ir/expression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/arrayExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/arrowFunctionExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/assignmentExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/awaitExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/binaryExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/callExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/chainExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/classExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/conditionalExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/directEvalExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/functionExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"
#include "plugins/ecmascript/es2panda/ir/expressions/importExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/bigIntLiteral.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/booleanLiteral.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/nullLiteral.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/numberLiteral.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/regExpLiteral.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/charLiteral.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/stringLiteral.h"
#include "plugins/ecmascript/es2panda/ir/expressions/memberExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/newExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/objectExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/omittedExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/sequenceExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/superExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/taggedTemplateExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/templateLiteral.h"
#include "plugins/ecmascript/es2panda/ir/expressions/thisExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/unaryExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/updateExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/yieldExpression.h"
#include "plugins/ecmascript/es2panda/ir/statements/blockStatement.h"
#include "plugins/ecmascript/es2panda/ir/statements/classDeclaration.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsAsExpression.h"
#include "plugins/ecmascript/es2panda/ir/validationInfo.h"
#include "plugins/ecmascript/es2panda/lexer/lexer.h"
#include "plugins/ecmascript/es2panda/lexer/regexp/regexp.h"
#include "plugins/ecmascript/es2panda/lexer/token/letters.h"
#include "plugins/ecmascript/es2panda/lexer/token/sourceLocation.h"
#include "plugins/ecmascript/es2panda/lexer/token/token.h"
#include "macros.h"

#include <memory>

#include "parserImpl.h"

namespace panda::es2panda::parser {
ir::YieldExpression *ParserImpl::ParseYieldExpression()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::KEYW_YIELD);

    lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    lexer::SourcePosition end_loc = lexer_->GetToken().End();

    if ((lexer_->GetToken().Flags() & lexer::TokenFlags::HAS_ESCAPE) != 0) {
        ThrowSyntaxError("Unexpected identifier");
    }

    lexer_->NextToken();

    bool is_delegate = false;
    ir::Expression *argument = nullptr;

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY && !lexer_->GetToken().NewLine()) {
        is_delegate = true;
        lexer_->NextToken();

        argument = ParseExpression();
        end_loc = argument->End();
    } else if (!lexer_->GetToken().NewLine() && lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE &&
               lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS &&
               lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET &&
               lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COMMA &&
               lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SEMI_COLON &&
               lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON &&
               lexer_->GetToken().Type() != lexer::TokenType::EOS) {
        argument = ParseExpression();
        end_loc = argument->End();
    }

    auto *yield_node = AllocNode<ir::YieldExpression>(argument, is_delegate);
    yield_node->SetRange({start_loc, end_loc});

    return yield_node;
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
        ir::YieldExpression *yield_expr = ParseYieldExpression();

        return ParsePotentialExpressionSequence(yield_expr, flags);
    }

    ir::Expression *unary_expression_node = ParseUnaryOrPrefixUpdateExpression(flags);
    ir::Expression *assignment_expression = ParseAssignmentExpression(unary_expression_node, flags);

    if (lexer_->GetToken().NewLine()) {
        return assignment_expression;
    }

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA &&
        (flags & ExpressionParseFlags::ACCEPT_COMMA) != 0U) {
        return ParseSequenceExpression(assignment_expression, (flags & ExpressionParseFlags::ACCEPT_REST) != 0U);
    }

    return assignment_expression;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::ArrayExpression *ParserImpl::ParseArrayExpression(ExpressionParseFlags flags)
{
    lexer::SourcePosition start_loc = lexer_->GetToken().Start();

    ArenaVector<ir::Expression *> elements(Allocator()->Adapter());

    lexer_->NextToken();

    bool trailing_comma = false;
    bool in_pattern = (flags & ExpressionParseFlags::MUST_BE_PATTERN) != 0;

    while (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
        if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
            auto *omitted = AllocNode<ir::OmittedExpression>();
            omitted->SetRange(lexer_->GetToken().Loc());
            elements.push_back(omitted);
            lexer_->NextToken();
            continue;
        }

        ir::Expression *element {};
        if (in_pattern) {
            element = ParsePatternElement();
        } else if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD) {
            element = ParseSpreadElement(ExpressionParseFlags::POTENTIALLY_IN_PATTERN);
        } else {
            element = ParseExpression(ExpressionParseFlags::POTENTIALLY_IN_PATTERN);
        }

        bool contains_rest = element->IsRestElement();

        elements.push_back(element);

        if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
            if (contains_rest) {
                ThrowSyntaxError("Rest element must be last element", start_loc);
            }

            lexer_->NextToken();  // eat comma

            if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
                trailing_comma = true;
                break;
            }

            continue;
        }

        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
            ThrowSyntaxError("Unexpected token, expected ',' or ']'");
        }
    }

    auto node_type = in_pattern ? ir::AstNodeType::ARRAY_PATTERN : ir::AstNodeType::ARRAY_EXPRESSION;
    auto *array_expression_node =
        AllocNode<ir::ArrayExpression>(node_type, std::move(elements), Allocator(), trailing_comma);
    array_expression_node->SetRange({start_loc, lexer_->GetToken().End()});
    lexer_->NextToken();

    if (in_pattern) {
        array_expression_node->SetDeclaration();
    }

    if ((flags & ExpressionParseFlags::POTENTIALLY_IN_PATTERN) == 0) {
        if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION &&
            !array_expression_node->ConvertibleToArrayPattern()) {
            ThrowSyntaxError("Invalid left-hand side in array destructuring pattern", array_expression_node->Start());
        } else if (!in_pattern && lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
            ir::ValidationInfo info = array_expression_node->ValidateExpression();
            if (info.Fail()) {
                ThrowSyntaxError(info.msg.Utf8(), info.pos);
            }
        }
    }

    return array_expression_node;
}

ParserStatus ParserImpl::ValidateArrowParameter(ir::Expression *expr, [[maybe_unused]] bool *seen_optional)
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
            ir::ObjectExpression *object_pattern = expr->AsObjectExpression();

            if (!object_pattern->ConvertibleToObjectPattern()) {
                ThrowSyntaxError("Invalid destructuring assignment target");
            }

            ValidateArrowParameterBindings(expr);
            return ParserStatus::HAS_COMPLEX_PARAM;
        }
        case ir::AstNodeType::ARRAY_EXPRESSION: {
            ir::ArrayExpression *array_pattern = expr->AsArrayExpression();

            if (!array_pattern->ConvertibleToArrayPattern()) {
                ThrowSyntaxError("Invalid destructuring assignment target");
            }

            ValidateArrowParameterBindings(expr);
            return ParserStatus::HAS_COMPLEX_PARAM;
        }
        case ir::AstNodeType::ASSIGNMENT_EXPRESSION: {
            auto *assignment_expr = expr->AsAssignmentExpression();
            if (assignment_expr->Right()->IsYieldExpression()) {
                ThrowSyntaxError("yield is not allowed in arrow function parameters");
            }

            if (assignment_expr->Right()->IsAwaitExpression()) {
                ThrowSyntaxError("await is not allowed in arrow function parameters");
            }

            if (!assignment_expr->ConvertibleToAssignmentPattern()) {
                ThrowSyntaxError("Invalid destructuring assignment target");
            }

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

ir::ArrowFunctionExpression *ParserImpl::ParseArrowFunctionExpressionBody(
    ArrowFunctionContext *arrow_function_context, binder::FunctionScope *function_scope, ArrowFunctionDescriptor *desc,
    ir::TSTypeParameterDeclaration *type_param_decl, ir::TypeNode *return_type_annotation)
{
    context_.Status() |= desc->new_status;

    function_scope->BindParamScope(desc->param_scope);
    desc->param_scope->BindFunctionScope(function_scope);

    lexer_->NextToken();  // eat '=>'
    ir::ScriptFunction *func_node {};

    ir::AstNode *body = nullptr;
    lexer::SourcePosition end_loc;
    lexer::SourcePosition body_start = lexer_->GetToken().Start();

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        body = ParseExpression();
        end_loc = body->AsExpression()->End();
        arrow_function_context->AddFlag(ir::ScriptFunctionFlags::EXPRESSION);
    } else {
        lexer_->NextToken();
        auto statements = ParseStatementList();
        body = AllocNode<ir::BlockStatement>(Allocator(), function_scope, std::move(statements));
        body->SetRange({body_start, lexer_->GetToken().End()});

        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
            ThrowSyntaxError("Expected a '}'");
        }

        lexer_->NextToken();
        end_loc = body->End();
    }

    func_node = AllocNode<ir::ScriptFunction>(function_scope, std::move(desc->params), type_param_decl, body,
                                              return_type_annotation, arrow_function_context->Flags(), false);
    func_node->SetRange({desc->start_loc, end_loc});
    function_scope->BindNode(func_node);
    desc->param_scope->BindNode(func_node);

    auto *arrow_func_node = AllocNode<ir::ArrowFunctionExpression>(Allocator(), func_node);
    arrow_func_node->SetRange(func_node->Range());

    return arrow_func_node;
}

ArrowFunctionDescriptor ParserImpl::ConvertToArrowParameter(ir::Expression *expr, bool is_async,
                                                            binder::FunctionParamScope *param_scope)
{
    auto arrow_status = is_async ? ParserStatus::ASYNC_FUNCTION : ParserStatus::NO_OPTS;
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());

    if (expr == nullptr) {
        return ArrowFunctionDescriptor {std::move(params), param_scope, lexer_->GetToken().Start(), arrow_status};
    }

    bool seen_optional = false;

    switch (expr->Type()) {
        case ir::AstNodeType::REST_ELEMENT:
        case ir::AstNodeType::IDENTIFIER:
        case ir::AstNodeType::OBJECT_EXPRESSION:
        case ir::AstNodeType::ASSIGNMENT_EXPRESSION:
        case ir::AstNodeType::ARRAY_EXPRESSION: {
            arrow_status |= ValidateArrowParameter(expr, &seen_optional);

            params.push_back(expr);
            break;
        }
        case ir::AstNodeType::SEQUENCE_EXPRESSION: {
            auto &sequence = expr->AsSequenceExpression()->Sequence();

            for (auto *it : sequence) {
                arrow_status |= ValidateArrowParameter(it, &seen_optional);
            }

            params.swap(sequence);
            break;
        }
        case ir::AstNodeType::CALL_EXPRESSION: {
            if (is_async) {
                auto *call_expression = expr->AsCallExpression();
                auto &arguments = call_expression->Arguments();

                if (call_expression->HasTrailingComma()) {
                    ASSERT(!arguments.empty());
                    ThrowSyntaxError("Rest parameter must be last formal parameter", arguments.back()->End());
                }

                for (auto *it : arguments) {
                    arrow_status |= ValidateArrowParameter(it, &seen_optional);
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

    for (auto *param : params) {
        Binder()->AddParamDecl(param);
    }

    return ArrowFunctionDescriptor {std::move(params), param_scope, expr->Start(), arrow_status};
}

ir::ArrowFunctionExpression *ParserImpl::ParseArrowFunctionExpression(ir::Expression *expr,
                                                                      ir::TSTypeParameterDeclaration *type_param_decl,
                                                                      ir::TypeNode *return_type_annotation,
                                                                      bool is_async)
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_ARROW);

    if (lexer_->GetToken().NewLine()) {
        ThrowSyntaxError(
            "expected '=>' on the same line after an argument list, "
            "got line terminator");
    }

    ArrowFunctionContext arrow_function_context(this, is_async);
    FunctionParameterContext function_param_context(&context_, Binder());
    ArrowFunctionDescriptor desc =
        ConvertToArrowParameter(expr, is_async, function_param_context.LexicalScope().GetScope());

    auto function_ctx = binder::LexicalScope<binder::FunctionScope>(Binder());
    return ParseArrowFunctionExpressionBody(&arrow_function_context, function_ctx.GetScope(), &desc, type_param_decl,
                                            return_type_annotation);
}

void ParserImpl::ValidateArrowFunctionRestParameter([[maybe_unused]] ir::SpreadElement *rest_element)
{
    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError("Rest parameter must be last formal parameter");
    }
}

ir::Expression *ParserImpl::ParseCoverParenthesizedExpressionAndArrowParameterList()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
    lexer::SourcePosition start = lexer_->GetToken().Start();
    lexer_->NextToken();

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD) {
        ir::SpreadElement *rest_element = ParseSpreadElement(ExpressionParseFlags::MUST_BE_PATTERN);

        rest_element->SetGrouped();
        rest_element->SetStart(start);

        ValidateArrowFunctionRestParameter(rest_element);

        lexer_->NextToken();

        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_ARROW) {
            ThrowSyntaxError("Unexpected token");
        }

        return ParseArrowFunctionExpression(rest_element, nullptr, nullptr, false);
    }

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        lexer_->NextToken();

        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_ARROW) {
            ThrowSyntaxError("Unexpected token");
        }

        auto *arrow_expr = ParseArrowFunctionExpression(nullptr, nullptr, nullptr, false);
        arrow_expr->SetStart(start);
        arrow_expr->AsArrowFunctionExpression()->Function()->SetStart(start);

        return arrow_expr;
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
    object->Iterate([this](ir::AstNode *child_node) -> void {
        switch (child_node->Type()) {
            case ir::AstNodeType::ASSIGNMENT_PATTERN: {
                ThrowSyntaxError("Invalid property initializer");
                break;
            }
            case ir::AstNodeType::REST_ELEMENT:
            case ir::AstNodeType::PROPERTY:
            case ir::AstNodeType::OBJECT_EXPRESSION: {
                CheckInvalidDestructuring(child_node);
                break;
            }
            default: {
                break;
            }
        }
    });
}

void ParserImpl::ValidateParenthesizedExpression(ir::Expression *lhs_expression)
{
    switch (lhs_expression->Type()) {
        case ir::AstNodeType::IDENTIFIER: {
            auto info = lhs_expression->AsIdentifier()->ValidateExpression();
            if (info.Fail()) {
                ThrowSyntaxError(info.msg.Utf8(), info.pos);
            }
            break;
        }
        case ir::AstNodeType::MEMBER_EXPRESSION: {
            break;
        }
        case ir::AstNodeType::ARRAY_EXPRESSION: {
            auto info = lhs_expression->AsArrayExpression()->ValidateExpression();
            if (info.Fail()) {
                ThrowSyntaxError(info.msg.Utf8(), info.pos);
            }
            break;
        }
        case ir::AstNodeType::OBJECT_EXPRESSION: {
            auto info = lhs_expression->AsObjectExpression()->ValidateExpression();
            if (info.Fail()) {
                ThrowSyntaxError(info.msg.Utf8(), info.pos);
            }
            break;
        }
        case ir::AstNodeType::ASSIGNMENT_EXPRESSION: {
            if (lhs_expression->AsAssignmentExpression()->ConvertibleToAssignmentPattern(false)) {
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

ir::Expression *ParserImpl::ParseAssignmentExpression(ir::Expression *lhs_expression, ExpressionParseFlags flags)
{
    lexer::TokenType token_type = lexer_->GetToken().Type();
    if (lhs_expression->IsGrouped() && token_type != lexer::TokenType::PUNCTUATOR_ARROW) {
        if (lhs_expression->IsSequenceExpression()) {
            for (auto *seq : lhs_expression->AsSequenceExpression()->Sequence()) {
                ValidateParenthesizedExpression(seq);
            }
        } else {
            ValidateParenthesizedExpression(lhs_expression);
        }
    }

    switch (token_type) {
        case lexer::TokenType::PUNCTUATOR_QUESTION_MARK: {
            lexer_->NextToken();
            ir::Expression *consequent = ParseExpression();

            if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
                ThrowSyntaxError("Unexpected token, expected ':'");
            }

            lexer_->NextToken();
            ir::Expression *alternate = ParseExpression();

            auto *conditional_expr = AllocNode<ir::ConditionalExpression>(lhs_expression, consequent, alternate);
            conditional_expr->SetRange({lhs_expression->Start(), alternate->End()});
            return conditional_expr;
        }
        case lexer::TokenType::PUNCTUATOR_ARROW: {
            if (lexer_->GetToken().NewLine()) {
                ThrowSyntaxError("Uncaught SyntaxError: expected expression, got '=>'");
            }

            return ParseArrowFunctionExpression(lhs_expression, nullptr, nullptr, false);
        }
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
            ir::Expression *binary_expression = ParseBinaryExpression(lhs_expression);

            return ParseAssignmentExpression(binary_expression);
        }
        case lexer::TokenType::PUNCTUATOR_SUBSTITUTION: {
            ValidateAssignmentTarget(flags, lhs_expression);

            lexer_->NextToken();
            ir::Expression *assignment_expression = ParseExpression(CarryPatternFlags(flags));

            auto *binary_assignment_expression =
                AllocNode<ir::AssignmentExpression>(lhs_expression, assignment_expression, token_type);

            binary_assignment_expression->SetRange({lhs_expression->Start(), assignment_expression->End()});
            return binary_assignment_expression;
        }
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
        case lexer::TokenType::PUNCTUATOR_LOGICAL_AND_EQUAL:
        case lexer::TokenType::PUNCTUATOR_LOGICAL_OR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_LOGICAL_NULLISH_EQUAL:
        case lexer::TokenType::PUNCTUATOR_EXPONENTIATION_EQUAL: {
            ValidateLvalueAssignmentTarget(lhs_expression);

            lexer_->NextToken();
            ir::Expression *assignment_expression = ParseExpression(CarryPatternFlags(flags));

            auto *binary_assignment_expression =
                AllocNode<ir::AssignmentExpression>(lhs_expression, assignment_expression, token_type);

            binary_assignment_expression->SetRange({lhs_expression->Start(), assignment_expression->End()});
            return binary_assignment_expression;
        }
        case lexer::TokenType::KEYW_AS: {
            auto as_expression = ParsePotentialAsExpression(lhs_expression);
            if (as_expression != nullptr) {
                return ParseAssignmentExpression(as_expression);
            }
            break;
        }
        default:
            break;
    }

    return lhs_expression;
}

ir::TemplateLiteral *ParserImpl::ParseTemplateLiteral()
{
    lexer::SourcePosition start_loc = lexer_->GetToken().Start();

    ArenaVector<ir::TemplateElement *> quasis(Allocator()->Adapter());
    ArenaVector<ir::Expression *> expressions(Allocator()->Adapter());

    while (true) {
        lexer_->ResetTokenEnd();
        const auto start_pos = lexer_->Save();

        lexer_->ScanString<lexer::LEX_CHAR_BACK_TICK>();
        util::StringView cooked = lexer_->GetToken().String();

        lexer_->Rewind(start_pos);
        auto [raw, end, scan_expression] = lexer_->ScanTemplateString();

        auto *element = AllocNode<ir::TemplateElement>(raw.View(), cooked);
        element->SetRange({lexer::SourcePosition {start_pos.Iterator().Index(), start_pos.Line()},
                           lexer::SourcePosition {end, lexer_->Line()}});
        quasis.push_back(element);

        if (!scan_expression) {
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

    auto *template_node = AllocNode<ir::TemplateLiteral>(std::move(quasis), std::move(expressions));
    template_node->SetRange({start_loc, lexer_->GetToken().End()});

    lexer_->NextToken();

    return template_node;
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
        lexer::SourcePosition end_loc = callee->End();
        auto *new_expr_node = AllocNode<ir::NewExpression>(callee, std::move(arguments));
        new_expr_node->SetRange({start, end_loc});

        return new_expr_node;
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

    auto *new_expr_node = AllocNode<ir::NewExpression>(callee, std::move(arguments));
    new_expr_node->SetRange({start, lexer_->GetToken().End()});

    lexer_->NextToken();

    return new_expr_node;
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

            auto *meta_property = AllocNode<ir::MetaProperty>(ir::MetaProperty::MetaPropertyKind::NEW_TARGET);
            meta_property->SetRange(loc);
            lexer_->NextToken();
            return meta_property;
        }
    }

    return nullptr;
}

ir::Identifier *ParserImpl::ParsePrimaryExpressionIdent([[maybe_unused]] ExpressionParseFlags flags)
{
    auto *ident_node = AllocNode<ir::Identifier>(lexer_->GetToken().Ident(), Allocator());
    ident_node->SetReference();
    ident_node->SetRange(lexer_->GetToken().Loc());

    lexer_->NextToken();
    return ident_node;
}

ir::BooleanLiteral *ParserImpl::ParseBooleanLiteral()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::LITERAL_TRUE ||
           lexer_->GetToken().Type() == lexer::TokenType::LITERAL_FALSE);

    auto *boolean_node = AllocNode<ir::BooleanLiteral>(lexer_->GetToken().Type() == lexer::TokenType::LITERAL_TRUE);
    boolean_node->SetRange(lexer_->GetToken().Loc());

    lexer_->NextToken();
    return boolean_node;
}

ir::NullLiteral *ParserImpl::ParseNullLiteral()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::LITERAL_NULL);
    auto *null_node = AllocNode<ir::NullLiteral>();
    null_node->SetRange(lexer_->GetToken().Loc());

    lexer_->NextToken();
    return null_node;
}

ir::Literal *ParserImpl::ParseNumberLiteral()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::LITERAL_NUMBER);

    ir::Literal *number_node {};

    if ((lexer_->GetToken().Flags() & lexer::TokenFlags::NUMBER_BIGINT) != 0U) {
        number_node = AllocNode<ir::BigIntLiteral>(lexer_->GetToken().BigInt());
    } else {
        number_node = AllocNode<ir::NumberLiteral>(lexer_->GetToken().GetNumber());
    }

    number_node->SetRange(lexer_->GetToken().Loc());

    lexer_->NextToken();
    return number_node;
}

ir::CharLiteral *ParserImpl::ParseCharLiteral()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::LITERAL_CHAR);

    auto *char_node = AllocNode<ir::CharLiteral>(lexer_->GetToken().Utf16());
    char_node->SetRange(lexer_->GetToken().Loc());

    lexer_->NextToken();
    return char_node;
}

ir::StringLiteral *ParserImpl::ParseStringLiteral()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::LITERAL_STRING);

    auto *string_node = AllocNode<ir::StringLiteral>(lexer_->GetToken().String());
    string_node->SetRange(lexer_->GetToken().Loc());

    lexer_->NextToken();
    return string_node;
}

ir::ThisExpression *ParserImpl::ParseThisExpression()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::KEYW_THIS);

    auto *this_expr_node = AllocNode<ir::ThisExpression>();
    this_expr_node->SetRange(lexer_->GetToken().Loc());

    lexer_->NextToken();
    return this_expr_node;
}

ir::RegExpLiteral *ParserImpl::ParseRegularExpression()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_DIVIDE ||
           lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_DIVIDE_EQUAL);

    lexer_->ResetTokenEnd();
    auto regexp = lexer_->ScanRegExp();

    lexer::RegExpParser re_parser(regexp, Allocator());

    try {
        re_parser.ParsePattern();
    } catch (lexer::RegExpError &e) {
        ThrowSyntaxError(e.message.c_str());
    }

    auto *regexp_node = AllocNode<ir::RegExpLiteral>(regexp.pattern_str, regexp.flags, regexp.flags_str);
    regexp_node->SetRange(lexer_->GetToken().Loc());

    lexer_->NextToken();
    return regexp_node;
}

ir::SuperExpression *ParserImpl::ParseSuperExpression()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::KEYW_SUPER);

    auto *super_expr_node = AllocNode<ir::SuperExpression>();
    super_expr_node->SetRange(lexer_->GetToken().Loc());

    lexer_->NextToken();  // eat super

    if ((lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD ||
         lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) &&
        (context_.Status() & ParserStatus::ALLOW_SUPER) != 0U) {
        return super_expr_node;
    }

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS &&
        (context_.Status() & ParserStatus::ALLOW_SUPER_CALL) != 0U) {
        return super_expr_node;
    }

    ThrowSyntaxError("Unexpected super keyword");
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ParserImpl::ParsePrimaryExpression(ExpressionParseFlags flags)
{
    switch (lexer_->GetToken().Type()) {
        case lexer::TokenType::KEYW_IMPORT: {
            return ParseImportExpression();
        }
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
        case lexer::TokenType::LITERAL_NUMBER: {
            return ParseNumberLiteral();
        }
        case lexer::TokenType::LITERAL_STRING: {
            return ParseStringLiteral();
        }
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
        case lexer::TokenType::KEYW_FUNCTION: {
            return ParseFunctionExpression();
        }
        case lexer::TokenType::KEYW_CLASS: {
            lexer::SourcePosition start_loc = lexer_->GetToken().Start();
            ir::ClassDefinition *class_definition = ParseClassDefinition(ir::ClassDefinitionModifiers::ID_REQUIRED);

            auto *class_expr = AllocNode<ir::ClassExpression>(class_definition);
            class_expr->SetRange({start_loc, class_definition->End()});

            return class_expr;
        }
        case lexer::TokenType::KEYW_THIS: {
            return ParseThisExpression();
        }
        case lexer::TokenType::KEYW_SUPER: {
            return ParseSuperExpression();
        }
        case lexer::TokenType::KEYW_NEW: {
            ir::MetaProperty *new_target = ParsePotentialNewTarget();

            if (new_target != nullptr) {
                return new_target;
            }

            return ParseNewExpression();
        }
        case lexer::TokenType::PUNCTUATOR_BACK_TICK: {
            return ParseTemplateLiteral();
        }
        case lexer::TokenType::PUNCTUATOR_HASH_MARK: {
            ValidatePrivateIdentifier();
            auto *private_ident = AllocNode<ir::Identifier>(lexer_->GetToken().Ident(), Allocator());
            private_ident->SetPrivate(true);
            private_ident->SetReference();
            lexer_->NextToken();

            if (lexer_->GetToken().Type() != lexer::TokenType::KEYW_IN) {
                ThrowSyntaxError("Unexpected private identifier");
            }

            return private_ident;
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN: {
            return ParsePrefixAssertionExpression();
        }
        default: {
            break;
        }
    }

    ThrowSyntaxError({"Unexpected token '", lexer::TokenToString(lexer_->GetToken().Type()), "'."});
    return nullptr;
}

static size_t GetOperatorPrecedence(const lexer::TokenType operator_type)
{
    ASSERT(operator_type == lexer::TokenType::KEYW_AS || lexer::Token::IsBinaryToken(operator_type));

    switch (operator_type) {
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
        case lexer::TokenType::PUNCTUATOR_PLUS:
        case lexer::TokenType::PUNCTUATOR_MINUS: {
            constexpr auto PRECEDENCE = 12;
            return PRECEDENCE;
        }
        case lexer::TokenType::PUNCTUATOR_MULTIPLY:
        case lexer::TokenType::PUNCTUATOR_DIVIDE:
        case lexer::TokenType::PUNCTUATOR_MOD: {
            const auto precedence = 13;
            return precedence;
        }
        case lexer::TokenType::PUNCTUATOR_EXPONENTIATION: {
            constexpr auto PRECEDENCE = 14;
            return PRECEDENCE;
        }
        default: {
            UNREACHABLE();
        }
    }
}

static inline bool ShouldBinaryExpressionBeAmended(const ir::BinaryExpression *const binary_expression,
                                                   const lexer::TokenType operator_type)
{
    return GetOperatorPrecedence(binary_expression->OperatorType()) <= GetOperatorPrecedence(operator_type) &&
           !binary_expression->IsGrouped() &&
           (operator_type != lexer::TokenType::PUNCTUATOR_EXPONENTIATION ||
            binary_expression->OperatorType() != lexer::TokenType::PUNCTUATOR_EXPONENTIATION);
}

static inline bool ShouldAsExpressionBeAmended(const ir::TSAsExpression *const as_expression,
                                               const lexer::TokenType operator_type)
{
    return GetOperatorPrecedence(lexer::TokenType::KEYW_AS) <= GetOperatorPrecedence(operator_type) &&
           !as_expression->IsGrouped() && operator_type != lexer::TokenType::PUNCTUATOR_EXPONENTIATION;
}

static inline bool ShouldExpressionBeAmended(const ir::Expression *const expression,
                                             const lexer::TokenType operator_type)
{
    bool should_be_amended = false;

    if (expression->IsBinaryExpression()) {
        should_be_amended = ShouldBinaryExpressionBeAmended(expression->AsBinaryExpression(), operator_type);
    } else if (expression->IsTSAsExpression()) {
        should_be_amended = ShouldAsExpressionBeAmended(expression->AsTSAsExpression(), operator_type);
    }

    return should_be_amended;
}

static inline bool AreLogicalAndNullishMixedIncorrectly(const ir::Expression *const expression,
                                                        const lexer::TokenType operator_type)
{
    return ((operator_type == lexer::TokenType::PUNCTUATOR_LOGICAL_OR ||
             operator_type == lexer::TokenType::PUNCTUATOR_LOGICAL_AND) &&
            expression->IsBinaryExpression() &&
            expression->AsBinaryExpression()->OperatorType() == lexer::TokenType::PUNCTUATOR_NULLISH_COALESCING &&
            !expression->IsGrouped()) ||
           (operator_type == lexer::TokenType::PUNCTUATOR_NULLISH_COALESCING && expression->IsBinaryExpression() &&
            (expression->AsBinaryExpression()->OperatorType() == lexer::TokenType::PUNCTUATOR_LOGICAL_OR ||
             expression->AsBinaryExpression()->OperatorType() == lexer::TokenType::PUNCTUATOR_LOGICAL_AND) &&
            !expression->IsGrouped());
}

static inline ir::Expression *GetAmendedChildExpression(ir::Expression *const expression)
{
    ir::Expression *amended_child = nullptr;

    if (expression->IsBinaryExpression()) {
        amended_child = expression->AsBinaryExpression()->Left();
    } else if (expression->IsTSAsExpression()) {
        amended_child = expression->AsTSAsExpression()->Expr();
    } else {
        UNREACHABLE();
    }

    return amended_child;
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
                                               const lexer::TokenType operator_type)
{
    auto *amended = GetAmendedChildExpression(right);

    auto *binary_expr = AllocNode<ir::BinaryExpression>(left, amended, operator_type);

    binary_expr->SetRange({left->Start(), amended->End()});
    SetAmendedChildExpression(right, binary_expr);
}

ir::Expression *ParserImpl::ParseBinaryExpression(ir::Expression *left)
{
    lexer::TokenType operator_type = lexer_->GetToken().Type();
    ASSERT(lexer::Token::IsBinaryToken(operator_type));

    if (operator_type == lexer::TokenType::PUNCTUATOR_EXPONENTIATION) {
        if (left->IsUnaryExpression() && !left->IsGrouped()) {
            ThrowSyntaxError(
                "Illegal expression. Wrap left hand side or entire "
                "exponentiation in parentheses.");
        }
    }

    lexer_->NextToken();

    ir::Expression *right_expr = ParseExpression(ExpressionParseFlags::DISALLOW_YIELD);
    ir::ConditionalExpression *conditional_expr = nullptr;

    if (right_expr->IsConditionalExpression() && !right_expr->IsGrouped()) {
        conditional_expr = right_expr->AsConditionalExpression();
        right_expr = conditional_expr->Test();
    }

    if (ShouldExpressionBeAmended(right_expr, operator_type)) {
        if (AreLogicalAndNullishMixedIncorrectly(right_expr, operator_type)) {
            ThrowSyntaxError("Nullish coalescing operator ?? requires parens when mixing with logical operators.");
        }

        bool should_be_amended = true;

        ir::Expression *expression = right_expr;
        ir::Expression *parent_expression = nullptr;

        while (should_be_amended && GetAmendedChildExpression(expression)->IsBinaryExpression()) {
            parent_expression = expression;
            parent_expression->SetStart(left->Start());

            expression = GetAmendedChildExpression(expression);

            should_be_amended = ShouldExpressionBeAmended(expression, operator_type);
        }

        CreateAmendedBinaryExpression(left, should_be_amended ? expression : parent_expression, operator_type);
    } else {
        if (AreLogicalAndNullishMixedIncorrectly(right_expr, operator_type)) {
            ThrowSyntaxError("Nullish coalescing operator ?? requires parens when mixing with logical operators.");
        }
        const lexer::SourcePosition &end_pos = right_expr->End();
        right_expr = AllocNode<ir::BinaryExpression>(left, right_expr, operator_type);
        right_expr->SetRange({left->Start(), end_pos});
    }

    if (conditional_expr != nullptr) {
        conditional_expr->SetStart(right_expr->Start());
        conditional_expr->SetTest(right_expr);
        return conditional_expr;
    }

    return right_expr;
}

ir::CallExpression *ParserImpl::ParseCallExpression(ir::Expression *callee, bool is_optional_chain, bool handle_eval)
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
    bool trailing_comma {};

    while (true) {
        lexer_->NextToken();
        ArenaVector<ir::Expression *> arguments(Allocator()->Adapter());

        while (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
            trailing_comma = false;
            ir::Expression *argument {};
            if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD) {
                argument = ParseSpreadElement();
            } else {
                argument = ParseExpression();
            }

            arguments.push_back(argument);

            if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
                lexer_->NextToken();
                trailing_comma = true;
            } else if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
                ThrowSyntaxError("Expected a ')'");
            }
        }

        ir::CallExpression *call_expr {};

        if (!is_optional_chain && handle_eval && callee->IsIdentifier() && callee->AsIdentifier()->Name().Is("eval")) {
            auto parser_status = static_cast<uint32_t>(context_.Status() | ParserStatus::DIRECT_EVAL);
            call_expr = AllocNode<ir::DirectEvalExpression>(callee, std::move(arguments), nullptr, is_optional_chain,
                                                            parser_status);

            Binder()->PropagateDirectEval();
        } else {
            call_expr =
                AllocNode<ir::CallExpression>(callee, std::move(arguments), nullptr, is_optional_chain, trailing_comma);
        }

        call_expr->SetRange({callee->Start(), lexer_->GetToken().End()});
        is_optional_chain = false;

        lexer_->NextToken();

        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
            ParseTrailingBlock(call_expr);
            return call_expr;
        }

        callee = call_expr;
    }

    UNREACHABLE();
    return nullptr;
}

ir::Expression *ParserImpl::ParseOptionalChain(ir::Expression *left_side_expr)
{
    ir::Expression *return_expression = nullptr;

    bool is_private = false;

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_HASH_MARK) {
        is_private = true;
        ValidatePrivateIdentifier();
    }

    const auto token_type = lexer_->GetToken().Type();
    if (token_type == lexer::TokenType::LITERAL_IDENT) {
        auto *ident_node = AllocNode<ir::Identifier>(lexer_->GetToken().Ident(), Allocator());
        ident_node->SetReference();
        ident_node->SetPrivate(is_private);
        ident_node->SetRange(lexer_->GetToken().Loc());

        return_expression = AllocNode<ir::MemberExpression>(left_side_expr, ident_node,
                                                            ir::MemberExpressionKind::PROPERTY_ACCESS, false, true);
        return_expression->SetRange({left_side_expr->Start(), ident_node->End()});
        lexer_->NextToken();
    }

    if (token_type == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
        lexer_->NextToken();  // eat '['
        ir::Expression *property_node = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA);

        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
            ThrowSyntaxError("Unexpected token");
        }

        return_expression = AllocNode<ir::MemberExpression>(left_side_expr, property_node,
                                                            ir::MemberExpressionKind::ELEMENT_ACCESS, true, true);
        return_expression->SetRange({left_side_expr->Start(), lexer_->GetToken().End()});
        lexer_->NextToken();
    }

    if (token_type == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        return_expression = ParseCallExpression(left_side_expr, true);
    }

    // Static semantic
    if (token_type == lexer::TokenType::PUNCTUATOR_BACK_TICK ||
        lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_BACK_TICK) {
        ThrowSyntaxError("Tagged Template Literals are not allowed in optionalChain");
    }

    return return_expression;
}

ir::ArrowFunctionExpression *ParserImpl::ParsePotentialArrowExpression(ir::Expression **return_expression,
                                                                       const lexer::SourcePosition &start_loc)
{
    switch (lexer_->GetToken().Type()) {
        case lexer::TokenType::KEYW_FUNCTION: {
            *return_expression = ParseFunctionExpression(ParserStatus::ASYNC_FUNCTION);
            (*return_expression)->SetStart(start_loc);
            break;
        }
        case lexer::TokenType::LITERAL_IDENT: {
            ir::Expression *ident_ref = ParsePrimaryExpression();
            ASSERT(ident_ref->IsIdentifier());

            if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_ARROW) {
                ThrowSyntaxError("Unexpected token, expected '=>'");
            }

            ir::ArrowFunctionExpression *arrow_func_expr =
                ParseArrowFunctionExpression(ident_ref, nullptr, nullptr, true);
            arrow_func_expr->SetStart(start_loc);

            return arrow_func_expr;
        }
        case lexer::TokenType::PUNCTUATOR_ARROW: {
            ir::ArrowFunctionExpression *arrow_func_expr =
                ParseArrowFunctionExpression(*return_expression, nullptr, nullptr, true);
            arrow_func_expr->SetStart(start_loc);
            return arrow_func_expr;
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS: {
            ir::CallExpression *call_expression = ParseCallExpression(*return_expression, false);

            if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_ARROW) {
                ir::ArrowFunctionExpression *arrow_func_expr =
                    ParseArrowFunctionExpression(call_expression, nullptr, nullptr, true);
                arrow_func_expr->SetStart(start_loc);

                return arrow_func_expr;
            }

            *return_expression = call_expression;
            break;
        }
        default: {
            break;
        }
    }

    return nullptr;
}

bool ParserImpl::ParsePotentialGenericFunctionCall([[maybe_unused]] ir::Expression *primary_expr,
                                                   [[maybe_unused]] ir::Expression **return_expression,
                                                   [[maybe_unused]] const lexer::SourcePosition &start_loc,
                                                   [[maybe_unused]] bool ignore_call_expression)
{
    return true;
}

bool ParserImpl::ParsePotentialNonNullExpression([[maybe_unused]] ir::Expression **return_expression,
                                                 [[maybe_unused]] lexer::SourcePosition start_loc)
{
    return true;
}

ir::Expression *ParserImpl::ParsePotentialAsExpression([[maybe_unused]] ir::Expression *primary_expression)
{
    return nullptr;
}

ir::MemberExpression *ParserImpl::ParseElementAccess(ir::Expression *primary_expr, bool is_optional)
{
    lexer_->NextToken();  // eat '['
    ir::Expression *property_node = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA);

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
        ThrowSyntaxError("Unexpected token");
    }

    auto *member_expr = AllocNode<ir::MemberExpression>(primary_expr, property_node,
                                                        ir::MemberExpressionKind::ELEMENT_ACCESS, true, is_optional);
    member_expr->SetRange({primary_expr->Start(), lexer_->GetToken().End()});
    lexer_->NextToken();
    return member_expr;
}

ir::MemberExpression *ParserImpl::ParsePrivatePropertyAccess(ir::Expression *primary_expr)
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_HASH_MARK);

    lexer::SourcePosition member_start = lexer_->GetToken().Start();
    ValidatePrivateIdentifier();

    auto *private_ident = AllocNode<ir::Identifier>(lexer_->GetToken().Ident(), Allocator());
    private_ident->SetRange({member_start, lexer_->GetToken().End()});
    private_ident->SetPrivate(true);
    private_ident->SetReference();
    lexer_->NextToken();

    auto *member_expr = AllocNode<ir::MemberExpression>(primary_expr, private_ident,
                                                        ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
    member_expr->SetRange({primary_expr->Start(), private_ident->End()});
    return member_expr;
}

ir::MemberExpression *ParserImpl::ParsePropertyAccess(ir::Expression *primary_expr, bool is_optional)
{
    ir::Identifier *ident = ExpectIdentifier(true);

    auto *member_expr = AllocNode<ir::MemberExpression>(primary_expr, ident, ir::MemberExpressionKind::PROPERTY_ACCESS,
                                                        false, is_optional);
    member_expr->SetRange({primary_expr->Start(), ident->End()});

    return member_expr;
}

ir::Expression *ParserImpl::ParsePostPrimaryExpression(ir::Expression *primary_expr, lexer::SourcePosition start_loc,
                                                       bool ignore_call_expression, bool *is_chain_expression)
{
    ir::Expression *return_expression = primary_expr;

    while (true) {
        switch (lexer_->GetToken().Type()) {
            case lexer::TokenType::PUNCTUATOR_QUESTION_DOT: {
                *is_chain_expression = true;
                lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat ?.
                return_expression = ParseOptionalChain(return_expression);
                continue;
            }
            case lexer::TokenType::PUNCTUATOR_PERIOD: {
                lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat period

                if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_HASH_MARK) {
                    return_expression = ParsePrivatePropertyAccess(return_expression);
                    continue;
                }

                return_expression = ParsePropertyAccess(return_expression);
                continue;
            }
            case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET: {
                return_expression = ParseElementAccess(return_expression);
                continue;
            }
            case lexer::TokenType::LITERAL_IDENT: {
                auto *as_expression = ParsePotentialAsExpression(return_expression);

                if (as_expression != nullptr) {
                    return as_expression;
                }
                break;
            }
            case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT:
            case lexer::TokenType::PUNCTUATOR_LESS_THAN: {
                if (ParsePotentialGenericFunctionCall(primary_expr, &return_expression, start_loc,
                                                      ignore_call_expression)) {
                    break;
                }

                continue;
            }
            case lexer::TokenType::PUNCTUATOR_BACK_TICK: {
                ir::TemplateLiteral *property_node = ParseTemplateLiteral();
                lexer::SourcePosition end_loc = property_node->End();

                return_expression = AllocNode<ir::TaggedTemplateExpression>(return_expression, property_node, nullptr);
                return_expression->SetRange({start_loc, end_loc});
                continue;
            }
            case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS: {
                if (ignore_call_expression) {
                    break;
                }
                return_expression = ParseCallExpression(return_expression, false);
                continue;
            }
            case lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK: {
                const bool should_break = ParsePotentialNonNullExpression(&return_expression, start_loc);

                if (should_break) {
                    break;
                }

                continue;
            }
            default: {
                break;
            }
        }

        break;
    }

    return return_expression;
}

void ParserImpl::ValidateUpdateExpression(ir::Expression *return_expression, bool is_chain_expression)
{
    if ((!return_expression->IsMemberExpression() && !return_expression->IsIdentifier() &&
         !return_expression->IsTSNonNullExpression()) ||
        is_chain_expression) {
        ThrowSyntaxError("Invalid left-hand side operator.");
    }

    if (return_expression->IsIdentifier()) {
        const util::StringView &return_expression_str = return_expression->AsIdentifier()->Name();

        if (return_expression_str.Is("eval")) {
            ThrowSyntaxError("Assigning to 'eval' in strict mode is invalid");
        }

        if (return_expression_str.Is("arguments")) {
            ThrowSyntaxError("Assigning to 'arguments' in strict mode is invalid");
        }
    }
}

ir::Expression *ParserImpl::ParseMemberExpression(bool ignore_call_expression, ExpressionParseFlags flags)
{
    bool is_async = lexer_->GetToken().IsAsyncModifier();
    lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    ir::Expression *return_expression = ParsePrimaryExpression(flags);

    if (lexer_->GetToken().NewLine() && return_expression->IsArrowFunctionExpression()) {
        return return_expression;
    }

    if (is_async && !lexer_->GetToken().NewLine()) {
        context_.Status() |= ParserStatus::ASYNC_FUNCTION;
        ir::ArrowFunctionExpression *arrow = ParsePotentialArrowExpression(&return_expression, start_loc);

        if (arrow != nullptr) {
            return arrow;
        }
    }

    bool is_chain_expression = false;
    return_expression =
        ParsePostPrimaryExpression(return_expression, start_loc, ignore_call_expression, &is_chain_expression);

    if (!lexer_->GetToken().NewLine() && lexer::Token::IsUpdateToken(lexer_->GetToken().Type())) {
        lexer::SourcePosition start = return_expression->Start();

        ValidateUpdateExpression(return_expression, is_chain_expression);

        return_expression = AllocNode<ir::UpdateExpression>(return_expression, lexer_->GetToken().Type(), false);

        return_expression->SetRange({start, lexer_->GetToken().End()});
        lexer_->NextToken();
    }

    if (is_chain_expression) {
        lexer::SourcePosition end_loc = return_expression->End();
        return_expression = AllocNode<ir::ChainExpression>(return_expression);
        return_expression->SetRange({start_loc, end_loc});
    }

    return return_expression;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ParserImpl::ParsePatternElement(ExpressionParseFlags flags, bool allow_default)
{
    ir::Expression *return_node = nullptr;

    switch (lexer_->GetToken().Type()) {
        case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET: {
            return_node = ParseArrayExpression(ExpressionParseFlags::MUST_BE_PATTERN);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD: {
            if ((flags & ExpressionParseFlags::IN_REST) != 0) {
                ThrowSyntaxError("Unexpected token");
            }
            return_node = ParseSpreadElement(ExpressionParseFlags::MUST_BE_PATTERN);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_BRACE: {
            return_node =
                ParseObjectExpression(ExpressionParseFlags::MUST_BE_PATTERN | ExpressionParseFlags::OBJECT_PATTERN);
            break;
        }
        case lexer::TokenType::LITERAL_IDENT: {
            return_node = AllocNode<ir::Identifier>(lexer_->GetToken().Ident(), Allocator());
            return_node->AsIdentifier()->SetReference();
            return_node->SetRange(lexer_->GetToken().Loc());
            lexer_->NextToken();
            break;
        }
        default: {
            ThrowSyntaxError("Unexpected token, expected an identifier.");
        }
    }

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        return return_node;
    }

    if ((flags & ExpressionParseFlags::IN_REST) != 0) {
        ThrowSyntaxError("Unexpected token, expected ')'");
    }

    if (!allow_default) {
        ThrowSyntaxError("Invalid destructuring assignment target");
    }

    lexer_->NextToken();

    if (context_.IsGenerator() && lexer_->GetToken().Type() == lexer::TokenType::KEYW_YIELD) {
        ThrowSyntaxError("Yield is not allowed in generator parameters");
    }

    if (context_.IsAsync() && lexer_->GetToken().Type() == lexer::TokenType::KEYW_AWAIT) {
        ThrowSyntaxError("Illegal await-expression in formal parameters of async function");
    }

    ir::Expression *right_node = ParseExpression();

    auto *assignment_expression = AllocNode<ir::AssignmentExpression>(
        ir::AstNodeType::ASSIGNMENT_PATTERN, return_node, right_node, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    assignment_expression->SetRange({return_node->Start(), right_node->End()});

    return assignment_expression;
}

void ParserImpl::CheckPropertyKeyAsyncModifier(ParserStatus *method_status)
{
    const auto async_pos = lexer_->Save();
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

        *method_status |= ParserStatus::ASYNC_FUNCTION;
    } else {
        lexer_->Rewind(async_pos);
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

void ParserImpl::ValidateAccessor(ExpressionParseFlags flags, lexer::TokenFlags current_token_flags)
{
    if ((flags & ExpressionParseFlags::MUST_BE_PATTERN) != 0) {
        ThrowSyntaxError("Unexpected token");
    }

    if ((current_token_flags & lexer::TokenFlags::HAS_ESCAPE) != 0) {
        ThrowSyntaxError("Keyword must not contain escaped characters");
    }
}

ir::Property *ParserImpl::ParseShorthandProperty(const lexer::LexerPosition *start_pos)
{
    char32_t next_cp = lexer_->Lookahead();
    lexer::TokenType keyword_type = lexer_->GetToken().KeywordType();

    /* Rewind the lexer to the beginning of the ident to reparse as common
     * identifier */
    lexer_->Rewind(*start_pos);
    lexer_->NextToken();
    lexer::SourcePosition start = lexer_->GetToken().Start();

    if (lexer_->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Expected an identifier");
    }

    const util::StringView &ident = lexer_->GetToken().Ident();

    auto *key = AllocNode<ir::Identifier>(ident, Allocator());
    key->SetRange(lexer_->GetToken().Loc());

    ir::Expression *value = AllocNode<ir::Identifier>(ident, Allocator());
    value->AsIdentifier()->SetReference();
    value->SetRange(lexer_->GetToken().Loc());

    lexer::SourcePosition end;

    if (next_cp == lexer::LEX_CHAR_EQUALS) {
        CheckRestrictedBinding(keyword_type);

        lexer_->NextToken();  // substitution
        lexer_->NextToken();  // eat substitution

        ir::Expression *right_node = ParseExpression();

        auto *assignment_expression = AllocNode<ir::AssignmentExpression>(
            ir::AstNodeType::ASSIGNMENT_PATTERN, value, right_node, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
        assignment_expression->SetRange({value->Start(), right_node->End()});
        end = right_node->End();
        value = assignment_expression;
    } else {
        end = lexer_->GetToken().End();
        lexer_->NextToken();
    }

    auto *return_property = AllocNode<ir::Property>(key, value);
    return_property->SetRange({start, end});

    return return_property;
}

bool ParserImpl::ParsePropertyModifiers(ExpressionParseFlags flags, ir::PropertyKind *property_kind,
                                        ParserStatus *method_status)
{
    if (lexer_->GetToken().IsAsyncModifier()) {
        CheckPropertyKeyAsyncModifier(method_status);
    }

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY) {
        if ((flags & ExpressionParseFlags::MUST_BE_PATTERN) != 0) {
            ThrowSyntaxError("Unexpected token");
        }

        lexer_->NextToken();
        *method_status |= ParserStatus::GENERATOR_FUNCTION;
    }

    lexer::TokenFlags current_token_flags = lexer_->GetToken().Flags();
    char32_t next_cp = lexer_->Lookahead();
    lexer::TokenType keyword_type = lexer_->GetToken().KeywordType();
    // Parse getter property
    if (keyword_type == lexer::TokenType::KEYW_GET && !IsAccessorDelimiter(next_cp)) {
        ValidateAccessor(flags, current_token_flags);

        *property_kind = ir::PropertyKind::GET;
        lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);

        return false;
    }

    // Parse setter property
    if (keyword_type == lexer::TokenType::KEYW_SET && !IsAccessorDelimiter(next_cp)) {
        ValidateAccessor(flags, current_token_flags);

        *property_kind = ir::PropertyKind::SET;
        lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);

        return false;
    }

    // Parse shorthand property or assignment pattern
    return (IsShorthandDelimiter(next_cp) && (*method_status & ParserStatus::ASYNC_FUNCTION) == 0);
}

void ParserImpl::ParseGeneratorPropertyModifier(ExpressionParseFlags flags, ParserStatus *method_status)
{
    if ((flags & ExpressionParseFlags::MUST_BE_PATTERN) != 0) {
        ThrowSyntaxError("Unexpected token");
    }

    lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
    *method_status |= ParserStatus::GENERATOR_FUNCTION;
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

ir::Expression *ParserImpl::ParsePropertyValue(const ir::PropertyKind *property_kind, const ParserStatus *method_status,
                                               ExpressionParseFlags flags)
{
    bool is_method = (*method_status & ParserStatus::FUNCTION) != 0;
    bool in_pattern = (flags & ExpressionParseFlags::MUST_BE_PATTERN) != 0;

    if (!is_method && !ir::Property::IsAccessorKind(*property_kind)) {
        // If the actual property is not getter/setter nor method, the following
        // token must be ':'
        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
            ThrowSyntaxError("Unexpected token, expected ':'");
        }

        lexer_->NextToken();  // eat colon

        if (!in_pattern) {
            return ParseExpression(flags);
        }

        return ParsePatternElement();
    }

    if (in_pattern) {
        ThrowSyntaxError("Object pattern can't contain methods");
    }

    ParserStatus new_status = *method_status | ParserStatus::FUNCTION | ParserStatus::ALLOW_SUPER;

    if (*property_kind != ir::PropertyKind::SET) {
        new_status |= ParserStatus::NEED_RETURN_TYPE;
    }

    ir::ScriptFunction *method_definiton_node = ParseFunction(new_status);
    method_definiton_node->AddFlag(ir::ScriptFunctionFlags::METHOD);

    size_t params_size = method_definiton_node->Params().size();

    auto *value = AllocNode<ir::FunctionExpression>(method_definiton_node);
    value->SetRange(method_definiton_node->Range());

    if (*property_kind == ir::PropertyKind::SET && params_size != 1) {
        ThrowSyntaxError("Setter must have exactly one formal parameter");
    }

    if (*property_kind == ir::PropertyKind::GET && params_size != 0) {
        ThrowSyntaxError("Getter must not have formal parameters");
    }

    return value;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ParserImpl::ParsePropertyDefinition([[maybe_unused]] ExpressionParseFlags flags)
{
    ir::PropertyKind property_kind = ir::PropertyKind::INIT;
    ParserStatus method_status = ParserStatus::NO_OPTS;

    const auto start_pos = lexer_->Save();
    lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
    lexer::SourcePosition start = lexer_->GetToken().Start();

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD) {
        return ParseSpreadElement(flags);
    }

    if (lexer_->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
        if (ParsePropertyModifiers(flags, &property_kind, &method_status)) {
            return ParseShorthandProperty(&start_pos);
        }
    } else if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY) {
        ParseGeneratorPropertyModifier(flags, &method_status);
    }

    bool is_computed = lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET;
    ir::Expression *key = ParsePropertyKey(flags);

    // Parse method property
    if ((lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS ||
         lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) &&
        !ir::Property::IsAccessorKind(property_kind)) {
        method_status |= ParserStatus::FUNCTION | ParserStatus::ALLOW_SUPER;
        property_kind = ir::PropertyKind::INIT;
    } else if ((method_status & (ParserStatus::GENERATOR_FUNCTION | ParserStatus::ASYNC_FUNCTION)) != 0) {
        ThrowSyntaxError("Unexpected identifier");
    }

    ir::Expression *value = ParsePropertyValue(&property_kind, &method_status, flags);
    lexer::SourcePosition end = value->End();

    ASSERT(key);
    ASSERT(value);

    auto *return_property =
        AllocNode<ir::Property>(property_kind, key, value, method_status != ParserStatus::NO_OPTS, is_computed);
    return_property->SetRange({start, end});

    return return_property;
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
    bool trailing_comma = false;
    bool in_pattern = (flags & ExpressionParseFlags::MUST_BE_PATTERN) != 0;

    if (lexer_->Lookahead() == lexer::LEX_CHAR_RIGHT_BRACE) {
        lexer_->NextToken();
    }

    while (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        ir::Expression *property = ParsePropertyDefinition(flags | ExpressionParseFlags::POTENTIALLY_IN_PATTERN);
        properties.push_back(property);
        trailing_comma = ParsePropertyEnd();
    }

    auto node_type = in_pattern ? ir::AstNodeType::OBJECT_PATTERN : ir::AstNodeType::OBJECT_EXPRESSION;
    auto *object_expression =
        AllocNode<ir::ObjectExpression>(node_type, Allocator(), std::move(properties), trailing_comma);
    object_expression->SetRange({start, lexer_->GetToken().End()});
    lexer_->NextToken();

    if (in_pattern) {
        object_expression->SetDeclaration();
    }

    if ((flags & ExpressionParseFlags::POTENTIALLY_IN_PATTERN) == 0) {
        if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION &&
            !object_expression->ConvertibleToObjectPattern()) {
            ThrowSyntaxError("Invalid left-hand side in array destructuring pattern", object_expression->Start());
        } else if (!in_pattern && lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
            ir::ValidationInfo info = object_expression->ValidateExpression();
            if (info.Fail()) {
                ThrowSyntaxError(info.msg.Utf8(), info.pos);
            }
        }
    }

    return object_expression;
}

ir::SequenceExpression *ParserImpl::ParseSequenceExpression(ir::Expression *start_expr, bool accept_rest)
{
    lexer::SourcePosition start = start_expr->Start();

    ArenaVector<ir::Expression *> sequence(Allocator()->Adapter());
    sequence.push_back(start_expr);

    while (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
        lexer_->NextToken();

        if (accept_rest && lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD) {
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
    auto *sequence_node = AllocNode<ir::SequenceExpression>(std::move(sequence));
    sequence_node->SetRange({start, end});

    return sequence_node;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ParserImpl::ParseUnaryOrPrefixUpdateExpression(ExpressionParseFlags flags)
{
    if (!lexer_->GetToken().IsUnary()) {
        return ParseLeftHandSideExpression(flags);
    }

    lexer::TokenType operator_type = lexer_->GetToken().Type();
    lexer::SourcePosition start = lexer_->GetToken().Start();
    lexer_->NextToken();

    ir::Expression *argument =
        lexer_->GetToken().IsUnary() ? ParseUnaryOrPrefixUpdateExpression() : ParseLeftHandSideExpression();

    if (lexer::Token::IsUpdateToken(operator_type)) {
        if (!argument->IsIdentifier() && !argument->IsMemberExpression() && !argument->IsTSNonNullExpression()) {
            ThrowSyntaxError("Invalid left-hand side in prefix operation");
        }

        if (argument->IsIdentifier()) {
            const util::StringView &argument_str = argument->AsIdentifier()->Name();

            if (argument_str.Is("eval")) {
                ThrowSyntaxError("Assigning to 'eval' in strict mode is invalid");
            } else if (argument_str.Is("arguments")) {
                ThrowSyntaxError("Assigning to 'arguments' in strict mode is invalid");
            }
        }
    }

    if (operator_type == lexer::TokenType::KEYW_DELETE) {
        if (argument->IsIdentifier()) {
            ThrowSyntaxError("Deleting local variable in strict mode");
        }

        if (argument->IsMemberExpression() && argument->AsMemberExpression()->Property()->IsIdentifier() &&
            argument->AsMemberExpression()->Property()->AsIdentifier()->IsPrivateIdent()) {
            ThrowSyntaxError("Private fields can not be deleted");
        }
    }

    lexer::SourcePosition end = argument->End();

    ir::Expression *return_expr = nullptr;

    if (lexer::Token::IsUpdateToken(operator_type)) {
        return_expr = AllocNode<ir::UpdateExpression>(argument, operator_type, true);
    } else if (operator_type == lexer::TokenType::KEYW_AWAIT) {
        return_expr = AllocNode<ir::AwaitExpression>(argument);
    } else {
        return_expr = AllocNode<ir::UnaryExpression>(argument, operator_type);
    }

    return_expr->SetRange({start, end});

    return return_expr;
}

ir::Expression *ParserImpl::ParseImportExpression()
{
    lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    lexer::SourcePosition end_loc = lexer_->GetToken().End();
    lexer_->NextToken();  // eat import

    // parse import.Meta
    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD) {
        if (!context_.IsModule()) {
            ThrowSyntaxError("'import.Meta' may appear only with 'sourceType: module'");
        } else if (Binder()->GetCompilerContext()->IsDirectEval()) {
            ThrowSyntaxError("'import.Meta' is not allowed in direct eval in module code.");
        }

        lexer_->NextToken();  // eat dot

        if (lexer_->GetToken().Type() != lexer::TokenType::LITERAL_IDENT ||
            lexer_->GetToken().KeywordType() != lexer::TokenType::KEYW_META) {
            ThrowSyntaxError("The only valid meta property for import is import.Meta");
        }

        auto *meta_property = AllocNode<ir::MetaProperty>(ir::MetaProperty::MetaPropertyKind::IMPORT_META);
        meta_property->SetRange({start_loc, end_loc});

        lexer_->NextToken();
        return meta_property;
    }

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        ThrowSyntaxError("Unexpected token");
    }

    lexer_->NextToken();  // eat left parentheses

    ir::Expression *source = ParseExpression();

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError("Unexpected token");
    }

    auto *import_expression = AllocNode<ir::ImportExpression>(source);
    import_expression->SetRange({start_loc, lexer_->GetToken().End()});

    lexer_->NextToken();  // eat right paren
    return import_expression;
}

bool ParserImpl::IsNamedFunctionExpression()
{
    return lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS;
}

ir::FunctionExpression *ParserImpl::ParseFunctionExpression(ParserStatus new_status)
{
    lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    ir::Identifier *ident = nullptr;

    if ((new_status & ParserStatus::ARROW_FUNCTION) == 0) {
        ParserStatus saved_status = context_.Status();
        context_.Status() |= static_cast<ParserStatus>(new_status & ParserStatus::ASYNC_FUNCTION);

        lexer_->NextToken();

        if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY) {
            new_status |= ParserStatus::GENERATOR_FUNCTION;
            lexer_->NextToken();
        }

        if (IsNamedFunctionExpression()) {
            CheckRestrictedBinding(lexer_->GetToken().KeywordType());
            ident = ExpectIdentifier();
        }

        context_.Status() = saved_status;
    }

    ir::ScriptFunction *function_node = ParseFunction(new_status);
    function_node->SetStart(start_loc);

    if (ident != nullptr) {
        auto *func_param_scope = function_node->Scope()->ParamScope();
        func_param_scope->BindName(Allocator(), ident->Name());
        function_node->SetIdent(ident);
    }

    auto *func_expr = AllocNode<ir::FunctionExpression>(function_node);
    func_expr->SetRange(function_node->Range());

    return func_expr;
}
}  // namespace panda::es2panda::parser
