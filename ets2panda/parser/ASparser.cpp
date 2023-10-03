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

#include "ASparser.h"

#include "util/helpers.h"
#include "binder/privateBinding.h"
#include "binder/scope.h"
#include "binder/tsBinding.h"
#include "lexer/ASLexer.h"
#include "ir/base/decorator.h"
#include "ir/base/property.h"
#include "ir/base/spreadElement.h"
#include "ir/base/classElement.h"
#include "ir/base/classDefinition.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/module/importDefaultSpecifier.h"
#include "ir/module/exportDefaultDeclaration.h"
#include "ir/module/exportNamedDeclaration.h"
#include "ir/module/importDeclaration.h"
#include "ir/expressions/arrowFunctionExpression.h"
#include "ir/expressions/templateLiteral.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/taggedTemplateExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/sequenceExpression.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/bigIntLiteral.h"
#include "ir/statements/emptyStatement.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/ifStatement.h"
#include "ir/statements/doWhileStatement.h"
#include "ir/statements/whileStatement.h"
#include "ir/statements/tryStatement.h"
#include "ir/statements/breakStatement.h"
#include "ir/statements/continueStatement.h"
#include "ir/statements/throwStatement.h"
#include "ir/statements/switchStatement.h"
#include "ir/statements/returnStatement.h"
#include "ir/statements/debuggerStatement.h"
#include "ir/statements/classDeclaration.h"
#include "ir/statements/labelledStatement.h"
#include "ir/statements/variableDeclarator.h"
#include "ir/statements/functionDeclaration.h"
#include "ir/as/namedType.h"
#include "ir/as/prefixAssertionExpression.h"
#include "ir/ts/tsFunctionType.h"
#include "ir/ts/tsNonNullExpression.h"
#include "ir/ts/tsAsExpression.h"
#include "ir/ts/tsEnumDeclaration.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "ir/ts/tsTypeAliasDeclaration.h"
#include "ir/ts/tsModuleDeclaration.h"
#include "ir/ts/tsInterfaceHeritage.h"
#include "ir/base/tsIndexSignature.h"
#include "ir/base/tsMethodSignature.h"
#include "ir/base/tsPropertySignature.h"
#include "ir/ts/tsClassImplements.h"
#include "ir/ts/tsTypeParameterInstantiation.h"

namespace panda::es2panda::parser {
std::unique_ptr<lexer::Lexer> ASParser::InitLexer(const SourceFile &source_file)
{
    GetProgram()->SetSource(source_file);
    auto lexer = std::make_unique<lexer::ASLexer>(&GetContext());
    SetLexer(lexer.get());
    return lexer;
}

ir::Decorator *ASParser::ParseDecorator()
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_AT);

    lexer::SourcePosition start = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat '@'

    auto *expr = ParseLeftHandSideExpression();
    auto *decorator = AllocNode<ir::Decorator>(expr);
    decorator->SetRange({start, expr->End()});
    return decorator;
}

void ASParser::AddDecorators(ir::AstNode *node, ArenaVector<ir::Decorator *> &decorators)
{
    if (decorators.empty()) {
        return;
    }

    if (!node->CanHaveDecorator(false)) {
        ThrowSyntaxError("Decorators are not valid here", decorators.front()->Start());
    }

    node->AddDecorators(std::move(decorators));
}

ir::TSTypeAliasDeclaration *ASParser::ParseTypeAliasDeclaration()
{
    ASSERT(Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_TYPE);
    lexer::SourcePosition type_start = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat type keyword

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Identifier expected");
    }

    const util::StringView &ident = Lexer()->GetToken().Ident();
    binder::TSBinding ts_binding(Allocator(), ident);
    auto *decl = Binder()->AddTsDecl<binder::TypeAliasDecl>(Lexer()->GetToken().Start(), ts_binding.View());

    auto *id = AllocNode<ir::Identifier>(ident, Allocator());
    id->SetRange(Lexer()->GetToken().Loc());
    Lexer()->NextToken();

    auto type_params_ctx = binder::LexicalScope<binder::LocalScope>(Binder());
    ir::TSTypeParameterDeclaration *type_param_decl = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        auto options = TypeAnnotationParsingOptions::THROW_ERROR;
        type_param_decl = ParseTypeParameterDeclaration(&options);
    }

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        ThrowSyntaxError("'=' expected");
    }

    Lexer()->NextToken();  // eat '='

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_BITWISE_OR) {
        Lexer()->NextToken();  // eat '|'
    }

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
    ir::TypeNode *type_annotation = ParseTypeAnnotation(&options);

    auto *type_alias_decl =
        AllocNode<ir::TSTypeAliasDeclaration>(Allocator(), id, type_param_decl, type_annotation, InAmbientContext());
    type_alias_decl->SetRange({type_start, Lexer()->GetToken().End()});
    decl->BindNode(type_alias_decl);

    return type_alias_decl;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Statement *ASParser::ParseStatement(StatementParsingFlags flags)
{
    return ParseDeclareAndDecorators(flags);
}

void ASParser::ParseOptionalFunctionParameter(ir::AnnotatedExpression *return_node, bool in_rest)
{
    bool is_optional = false;

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_QUESTION_MARK) {
        if (in_rest) {
            ThrowSyntaxError("A rest parameter cannot be optional");
        }

        ASSERT(return_node->IsIdentifier());
        return_node->AsIdentifier()->SetOptional(true);

        is_optional = true;
        Lexer()->NextToken();  // eat '?'
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        return_node->SetTsTypeAnnotation(ParseTypeAnnotation(&options));
    } else if (!is_optional) {
        ThrowSyntaxError("':' expected");
    }

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        return;
    }

    if (in_rest) {
        ThrowSyntaxError("A rest parameter cannot have an initializer");
    }

    if (return_node->IsIdentifier() && is_optional) {
        ThrowSyntaxError("Parameter cannot have question mark and initializer");
    }
}

ParserStatus ASParser::ValidateArrowParameter(ir::Expression *expr, bool *seen_optional)
{
    switch (expr->Type()) {
        case ir::AstNodeType::SPREAD_ELEMENT: {
            if (!expr->AsSpreadElement()->ConvertibleToRest(true)) {
                ThrowSyntaxError("Invalid rest element.");
            }

            [[fallthrough]];
        }
        case ir::AstNodeType::REST_ELEMENT: {
            if (expr->AsRestElement()->IsOptional()) {
                ThrowSyntaxError("A rest parameter cannot be optional.", expr->Start());
            }

            ValidateArrowParameterBindings(expr->AsRestElement()->Argument());
            return ParserStatus::HAS_COMPLEX_PARAM;
        }
        case ir::AstNodeType::IDENTIFIER: {
            const util::StringView &identifier = expr->AsIdentifier()->Name();
            bool is_optional = expr->AsIdentifier()->IsOptional();

            if ((*seen_optional) != is_optional) {
                ThrowSyntaxError("A required parameter cannot follow an optional parameter.", expr->Start());
            }

            (*seen_optional) |= is_optional;

            if (expr->AsIdentifier()->TypeAnnotation() == nullptr) {
                ThrowSyntaxError("':' expected", expr->End());
            }

            if (identifier.Is("arguments")) {
                ThrowSyntaxError("Binding 'arguments' in strict mode is invalid");
            } else if (identifier.Is("eval")) {
                ThrowSyntaxError("Binding 'eval' in strict mode is invalid");
            }

            ValidateArrowParameterBindings(expr);
            return ParserStatus::NO_OPTS;
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

            if (assignment_expr->Left()->IsIdentifier() && assignment_expr->Left()->AsIdentifier()->IsOptional()) {
                ThrowSyntaxError("Parameter cannot have question mark and initializer.", expr->Start());
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

ArrowFunctionDescriptor ASParser::ConvertToArrowParameter(ir::Expression *expr, bool is_async,
                                                          binder::FunctionParamScope *param_scope)
{
    auto arrow_status = is_async ? ParserStatus::ASYNC_FUNCTION : ParserStatus::NO_OPTS;
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());

    if (expr == nullptr) {
        return ArrowFunctionDescriptor {std::move(params), param_scope, Lexer()->GetToken().Start(), arrow_status};
    }

    bool seen_optional = false;

    switch (expr->Type()) {
        case ir::AstNodeType::REST_ELEMENT:
        case ir::AstNodeType::IDENTIFIER:
        case ir::AstNodeType::ASSIGNMENT_EXPRESSION: {
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
                auto &arguments = expr->AsCallExpression()->Arguments();

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

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ASParser::ParsePatternElement(ExpressionParseFlags flags, bool allow_default)
{
    ir::AnnotatedExpression *return_node = nullptr;
    bool is_optional = false;

    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD: {
            if ((flags & ExpressionParseFlags::IN_REST) != 0) {
                ThrowSyntaxError("Unexpected token");
            }

            return_node = ParseSpreadElement(ExpressionParseFlags::MUST_BE_PATTERN);
            break;
        }
        case lexer::TokenType::LITERAL_IDENT: {
            return_node = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
            return_node->AsIdentifier()->SetReference();
            return_node->SetRange(Lexer()->GetToken().Loc());
            Lexer()->NextToken();

            if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_QUESTION_MARK) {
                is_optional = true;

                if ((flags & ExpressionParseFlags::IN_REST) != 0) {
                    ThrowSyntaxError("A rest parameter cannot be optional");
                }

                return_node->AsIdentifier()->SetOptional(true);
                Lexer()->NextToken();
            }

            if (!is_optional && Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
                ThrowSyntaxError("':' expected");
            } else if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
                Lexer()->NextToken();  // eat ':'
                TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
                return_node->SetTsTypeAnnotation(ParseTypeAnnotation(&options));
            }

            break;
        }
        default: {
            ThrowSyntaxError("Identifier expected");
        }
    }

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        return return_node;
    }

    if ((flags & ExpressionParseFlags::IN_REST) != 0) {
        ThrowSyntaxError("A rest parameter cannot have an initializer.");
    }

    if (!allow_default) {
        ThrowSyntaxError("Invalid destructuring assignment target");
    }

    if (is_optional) {
        ThrowSyntaxError("Parameter cannot have question mark and initializer");
    }

    Lexer()->NextToken();

    if (((GetContext().Status() & ParserStatus::GENERATOR_FUNCTION) != 0) &&
        Lexer()->GetToken().Type() == lexer::TokenType::KEYW_YIELD) {
        ThrowSyntaxError("Yield is not allowed in generator parameters");
    }

    ir::Expression *right_node = ParseExpression();

    auto *assignment_expression = AllocNode<ir::AssignmentExpression>(
        ir::AstNodeType::ASSIGNMENT_PATTERN, return_node, right_node, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    assignment_expression->SetRange({return_node->Start(), right_node->End()});

    return assignment_expression;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ASParser::ParsePropertyDefinition([[maybe_unused]] ExpressionParseFlags flags)
{
    Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);

    ir::Expression *key = nullptr;

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_STRING) {
            ThrowSyntaxError("Identifier expected");
        }

        key = AllocNode<ir::StringLiteral>(Lexer()->GetToken().String());
    } else {
        key = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    }

    key->SetRange(Lexer()->GetToken().Loc());

    Lexer()->NextToken();

    ir::Expression *value = nullptr;

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();
        value = ParseExpression();
    } else if (!key->IsStringLiteral()) {
        value = key;
    } else {
        ThrowSyntaxError("':' expected");
    }

    auto *property = AllocNode<ir::Property>(key, value);
    property->SetRange({key->Start(), value->End()});
    return property;
}

bool ASParser::CurrentIsBasicType()
{
    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::LITERAL_STRING:
        case lexer::TokenType::LITERAL_FALSE:
        case lexer::TokenType::LITERAL_TRUE:
        case lexer::TokenType::LITERAL_NULL:
        case lexer::TokenType::KEYW_VOID: {
            return true;
        }
        case lexer::TokenType::LITERAL_IDENT: {
            switch (Lexer()->GetToken().KeywordType()) {
                case lexer::TokenType::KEYW_I8:
                case lexer::TokenType::KEYW_I16:
                case lexer::TokenType::KEYW_I32:
                case lexer::TokenType::KEYW_I64:
                case lexer::TokenType::KEYW_ISIZE:
                case lexer::TokenType::KEYW_U8:
                case lexer::TokenType::KEYW_U16:
                case lexer::TokenType::KEYW_U32:
                case lexer::TokenType::KEYW_U64:
                case lexer::TokenType::KEYW_USIZE:
                case lexer::TokenType::KEYW_F32:
                case lexer::TokenType::KEYW_F64:
                case lexer::TokenType::KEYW_V128:
                case lexer::TokenType::KEYW_FUNCREF:
                case lexer::TokenType::KEYW_EXTERNREF:
                case lexer::TokenType::KEYW_ANYREF:
                case lexer::TokenType::KEYW_EQREF:
                case lexer::TokenType::KEYW_I31REF:
                case lexer::TokenType::KEYW_DATAREF: {
                    return true;
                }
                default: {
                    break;
                }
            }

            break;
        }
        default: {
            break;
        }
    }
    return false;
}

ir::TypeNode *ASParser::ParseFunctionType(lexer::SourcePosition start_loc)
{
    FunctionParameterContext func_param_context(&GetContext(), Binder());
    auto *func_param_scope = func_param_context.LexicalScope().GetScope();
    auto params = ParseFunctionParams();

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_ARROW) {
        ThrowSyntaxError("'=>' expected");
    }

    Lexer()->NextToken();  // eat '=>'

    TypeAnnotationParsingOptions options =
        TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::CAN_BE_TS_TYPE_PREDICATE;
    ir::TypeNode *return_type_annotation = ParseTypeAnnotation(&options);

    auto func_type =
        AllocNode<ir::TSFunctionType>(func_param_scope, std::move(params), nullptr, return_type_annotation);

    func_type->SetRange({start_loc, return_type_annotation->End()});
    func_param_scope->BindNode(func_type);

    return func_type;
}

ir::TypeNode *ASParser::ParseParenthesizedOrFunctionType(bool throw_error)
{
    lexer::SourcePosition type_start = Lexer()->GetToken().Start();
    const auto start_pos = Lexer()->Save();
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
    Lexer()->NextToken();  // eat '('

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::NO_OPTS;
    ir::TypeNode *type = ParseTypeAnnotation(&options);

    if (type == nullptr) {
        Lexer()->Rewind(start_pos);

        if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
            if (throw_error) {
                ThrowSyntaxError("Identifier expected");
            }

            return nullptr;
        }

        return ParseFunctionType(type_start);
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA ||
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_QUESTION_MARK ||
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->Rewind(start_pos);
        return ParseFunctionType(type_start);
    }

    if (throw_error && Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError("')' expected");
    }

    lexer::SourcePosition end_loc = Lexer()->GetToken().End();
    Lexer()->NextToken();  // eat ')'

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_ARROW) {
        Lexer()->Rewind(start_pos);

        return ParseFunctionType(type_start);
    }

    type->SetRange({type_start, end_loc});
    return type;
}

ir::TypeNode *ASParser::ParseTypeAnnotation(TypeAnnotationParsingOptions *options)
{
    ir::TypeNode *type = nullptr;

    bool throw_error = (((*options) & TypeAnnotationParsingOptions::THROW_ERROR) != 0);
    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS: {
            type = ParseParenthesizedOrFunctionType(throw_error);
            if (type == nullptr) {
                return nullptr;
            }

            break;
        }
        case lexer::TokenType::KEYW_VOID: {
            util::StringView name = "void";
            auto *type_name = AllocNode<ir::Identifier>(name, Allocator());
            type_name->SetRange(Lexer()->GetToken().Loc());
            type = AllocNode<ir::NamedType>(type_name);
            type->SetRange(Lexer()->GetToken().Loc());
            Lexer()->NextToken();
            break;
        }
        case lexer::TokenType::KEYW_THIS: {
            util::StringView name = "this";
            auto *type_name = AllocNode<ir::Identifier>(name, Allocator());
            type_name->SetRange(Lexer()->GetToken().Loc());
            type = AllocNode<ir::NamedType>(type_name);
            type->SetRange(Lexer()->GetToken().Loc());
            Lexer()->NextToken();
            break;
        }
        case lexer::TokenType::LITERAL_FALSE:
        case lexer::TokenType::LITERAL_TRUE: {
            util::StringView name = "bool";
            auto *type_name = AllocNode<ir::Identifier>(name, Allocator());
            type_name->SetRange(Lexer()->GetToken().Loc());
            type = AllocNode<ir::NamedType>(type_name);
            type->SetRange(Lexer()->GetToken().Loc());
            Lexer()->NextToken();
            break;
        }
        case lexer::TokenType::LITERAL_NULL: {
            util::StringView name = "null";
            auto *type_name = AllocNode<ir::Identifier>(name, Allocator());
            type_name->SetRange(Lexer()->GetToken().Loc());
            type = AllocNode<ir::NamedType>(type_name);
            type->SetRange(Lexer()->GetToken().Loc());
            Lexer()->NextToken();
            break;
        }
        case lexer::TokenType::LITERAL_STRING: {
            util::StringView name = "string";
            auto *type_name = AllocNode<ir::Identifier>(name, Allocator());
            type_name->SetRange(Lexer()->GetToken().Loc());
            type = AllocNode<ir::NamedType>(type_name);
            type->SetRange(Lexer()->GetToken().Loc());
            Lexer()->NextToken();
            break;
        }
        case lexer::TokenType::LITERAL_IDENT: {
            auto *type_name = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
            type_name->SetRange(Lexer()->GetToken().Loc());
            type = AllocNode<ir::NamedType>(type_name);
            type->SetRange(Lexer()->GetToken().Loc());
            Lexer()->NextToken();

            ir::NamedType *current = type->AsNamedType();
            while (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD) {
                Lexer()->NextToken();

                if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
                    ThrowSyntaxError("Identifier expected");
                }

                type_name = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
                type_name->SetRange(Lexer()->GetToken().Loc());
                auto *next = AllocNode<ir::NamedType>(type_name);
                current->SetRange(Lexer()->GetToken().Loc());
                current->SetNext(next);
                current = next;
                Lexer()->NextToken();
            }

            ir::TSTypeParameterInstantiation *type_params = nullptr;
            if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
                type_params = ParseTypeParameterInstantiation(options);
                if (type_params == nullptr) {
                    return nullptr;
                }

                type->AsNamedType()->SetTypeParams(type_params);
            }

            break;
        }
        default: {
            if (throw_error) {
                ThrowSyntaxError("Type expected");
            }

            return nullptr;
        }
    }

    bool is_nullable = false;

    while (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_BITWISE_OR) {
        Lexer()->NextToken();

        if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_NULL) {
            if (throw_error) {
                ThrowSyntaxError("'null' expected");
            }

            return nullptr;
        }

        if (!is_nullable) {
            is_nullable = true;
            if (type->IsTSFunctionType()) {
                type->AsTSFunctionType()->SetNullable(is_nullable);
            } else {
                ASSERT(type->IsNamedType());
                type->AsNamedType()->SetNullable(is_nullable);
            }
        }

        type->SetEnd(Lexer()->GetToken().End());
        Lexer()->NextToken();
    }

    while (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
        Lexer()->NextToken();

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
            if (throw_error) {
                ThrowSyntaxError("']' expected");
            }

            return nullptr;
        }

        Lexer()->NextToken();

        is_nullable = false;

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_BITWISE_OR) {
            Lexer()->NextToken();

            if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_NULL) {
                if (throw_error) {
                    ThrowSyntaxError("'null' expected");
                }

                return nullptr;
            }

            is_nullable = true;
        }

        const lexer::SourcePosition &start_pos = type->Start();

        util::StringView name = "Array";
        auto *type_name = AllocNode<ir::Identifier>(name, Allocator());
        type_name->SetRange(Lexer()->GetToken().Loc());

        ArenaVector<ir::TypeNode *> params(Allocator()->Adapter());
        params.push_back(type);
        auto *type_param_inst = AllocNode<ir::TSTypeParameterInstantiation>(std::move(params));

        type = AllocNode<ir::NamedType>(type_name);
        type->AsNamedType()->SetTypeParams(type_param_inst);
        type->AsNamedType()->SetNullable(is_nullable);
        type->SetRange({start_pos, Lexer()->GetToken().End()});

        if (is_nullable) {
            Lexer()->NextToken();
            break;
        }
    }

    return type;
}

ir::ArrowFunctionExpression *ASParser::ParsePotentialArrowExpression(
    [[maybe_unused]] ir::Expression **return_expression, [[maybe_unused]] const lexer::SourcePosition &start_loc)
{
    return nullptr;
}

bool ASParser::ParsePotentialNonNullExpression(ir::Expression **return_expression, lexer::SourcePosition start_loc)
{
    if (return_expression == nullptr || Lexer()->GetToken().NewLine()) {
        return true;
    }

    *return_expression = AllocNode<ir::TSNonNullExpression>(*return_expression);
    (*return_expression)->SetRange({start_loc, Lexer()->GetToken().End()});
    Lexer()->NextToken();
    return false;
}

bool ASParser::ParsePotentialGenericFunctionCall(ir::Expression *primary_expr, ir::Expression **return_expression,
                                                 const lexer::SourcePosition &start_loc, bool ignore_call_expression)
{
    if (Lexer()->Lookahead() == lexer::LEX_CHAR_LESS_THAN ||
        (!primary_expr->IsIdentifier() && !primary_expr->IsMemberExpression())) {
        return true;
    }

    const auto saved_pos = Lexer()->Save();

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SHIFT) {
        Lexer()->BackwardToken(lexer::TokenType::PUNCTUATOR_LESS_THAN, 1);
    }

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::NO_OPTS;
    ir::TSTypeParameterInstantiation *type_params = ParseTypeParameterInstantiation(&options);

    if (type_params == nullptr) {
        Lexer()->Rewind(saved_pos);
        return true;
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::EOS) {
        ThrowSyntaxError("'(' or '`' expected");
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        if (!ignore_call_expression) {
            *return_expression = ParseCallExpression(*return_expression, false);
            (*return_expression)->AsCallExpression()->SetTypeParams(type_params);
            return false;
        }

        return true;
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_BACK_TICK) {
        ir::TemplateLiteral *property_node = ParseTemplateLiteral();
        lexer::SourcePosition end_loc = property_node->End();

        *return_expression = AllocNode<ir::TaggedTemplateExpression>(*return_expression, property_node, type_params);
        (*return_expression)->SetRange({start_loc, end_loc});
        return false;
    }

    Lexer()->Rewind(saved_pos);
    return true;
}

bool ASParser::IsNamedFunctionExpression()
{
    return Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS &&
           Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LESS_THAN;
}

ir::Expression *ASParser::ParsePotentialAsExpression(ir::Expression *primary_expression)
{
    if (Lexer()->GetToken().KeywordType() != lexer::TokenType::KEYW_AS) {
        return nullptr;
    }

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
    Lexer()->NextToken();
    ir::TypeNode *type = ParseTypeAnnotation(&options);
    auto *as_expression = AllocNode<ir::TSAsExpression>(primary_expression, type, false);
    return as_expression;
}

ir::Identifier *ASParser::ParsePrimaryExpressionIdent([[maybe_unused]] ExpressionParseFlags flags)
{
    auto *ident_node = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    ident_node->SetReference();
    ident_node->SetRange(Lexer()->GetToken().Loc());

    Lexer()->NextToken();

    ParsePotentialOptionalFunctionParameter(ident_node);

    return ident_node;
}

void ASParser::ValidateArrowFunctionRestParameter([[maybe_unused]] ir::SpreadElement *rest_element)
{
    ParseOptionalFunctionParameter(rest_element, true);

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError("')' expected");
    }
}

ArenaVector<ir::TSInterfaceHeritage *> ASParser::ParseInterfaceExtendsClause()
{
    Lexer()->NextToken();  // eat extends keyword

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Identifier expected");
    }

    const lexer::SourcePosition &heritage_start = Lexer()->GetToken().Start();
    lexer::SourcePosition heritage_end = Lexer()->GetToken().End();
    auto *extends_name = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    extends_name->SetRange(Lexer()->GetToken().Loc());
    auto *extends_clause = AllocNode<ir::NamedType>(extends_name);
    extends_clause->SetRange(Lexer()->GetToken().Loc());
    Lexer()->NextToken();

    ir::NamedType *current = extends_clause->AsNamedType();
    while (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD) {
        Lexer()->NextToken();

        if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
            ThrowSyntaxError("Identifier expected");
        }

        extends_name = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
        extends_name->SetRange(Lexer()->GetToken().Loc());
        auto *next = AllocNode<ir::NamedType>(extends_name);
        current->SetRange(Lexer()->GetToken().Loc());
        current->SetNext(next);
        current = next;
        heritage_end = Lexer()->GetToken().End();
        Lexer()->NextToken();
    }

    if (Lexer()->Lookahead() == lexer::LEX_CHAR_LESS_THAN) {
        Lexer()->ForwardToken(lexer::TokenType::PUNCTUATOR_LESS_THAN, 1);
    } else {
        Lexer()->NextToken();
    }

    ir::TSTypeParameterInstantiation *type_param_inst = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        type_param_inst = ParseTypeParameterInstantiation(&options);
        extends_clause->AsNamedType()->SetTypeParams(type_param_inst);
        heritage_end = Lexer()->GetToken().End();
    }

    extends_clause->SetRange({heritage_start, heritage_end});

    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_IMPLEMENTS) {
        ThrowSyntaxError("Interface declaration cannot have 'implements' clause");
    }

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        ThrowSyntaxError("'{' expected");
    }

    ArenaVector<ir::TSInterfaceHeritage *> extends(Allocator()->Adapter());
    auto *heritage = AllocNode<ir::TSInterfaceHeritage>(extends_clause);
    heritage->SetRange(extends_clause->Range());
    extends.push_back(heritage);
    return extends;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::TSIndexSignature *ASParser::ParseIndexSignature(const lexer::SourcePosition &start_loc, bool is_readonly)
{
    Lexer()->NextToken();  // eat '['

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Identifier expected.");
    }

    if (!Lexer()->GetToken().Ident().Is("key")) {
        ThrowSyntaxError("'key' expected.");
    }

    auto *key = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    key->SetRange(Lexer()->GetToken().Loc());

    Lexer()->NextToken();  // eat key

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
        ThrowSyntaxError("':' expected.");
    }

    Lexer()->NextToken();  // eat ':'

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
    ir::TypeNode *key_type = ParseTypeAnnotation(&options);
    key->SetTsTypeAnnotation(key_type);

    if (!key_type->IsNamedType()) {
        ThrowSyntaxError("Type expected.");
    }

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
        ThrowSyntaxError("']' expected.");
    }

    Lexer()->NextToken();  // eat ']'

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
        ThrowSyntaxError("':' expected.");
    }

    Lexer()->NextToken();  // eat ':'

    ir::TypeNode *type_annotation = ParseTypeAnnotation(&options);

    if (!type_annotation->IsNamedType()) {
        ThrowSyntaxError("Identifier expected.");
    }

    auto *index_signature = AllocNode<ir::TSIndexSignature>(key, type_annotation, is_readonly);
    index_signature->SetRange({start_loc, Lexer()->GetToken().End()});
    return index_signature;
}

std::tuple<ir::Expression *, bool> ASParser::ParseInterfacePropertyKey()
{
    ir::Expression *key = nullptr;

    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::LITERAL_IDENT: {
            const util::StringView &ident = Lexer()->GetToken().Ident();
            key = AllocNode<ir::Identifier>(ident, Allocator());
            key->SetRange(Lexer()->GetToken().Loc());
            break;
        }
        case lexer::TokenType::LITERAL_STRING: {
            const util::StringView &string = Lexer()->GetToken().String();
            key = AllocNode<ir::StringLiteral>(string);
            key->SetRange(Lexer()->GetToken().Loc());
            break;
        }
        case lexer::TokenType::LITERAL_NUMBER: {
            if ((Lexer()->GetToken().Flags() & lexer::TokenFlags::NUMBER_BIGINT) != 0) {
                key = AllocNode<ir::BigIntLiteral>(Lexer()->GetToken().BigInt());
            } else {
                key = AllocNode<ir::NumberLiteral>(Lexer()->GetToken().GetNumber());
            }

            key->SetRange(Lexer()->GetToken().Loc());
            break;
        }
        default: {
            ThrowSyntaxError("Unexpected token in property key");
        }
    }

    Lexer()->NextToken();
    return {key, false};
}

ir::AstNode *ASParser::ParsePropertyOrMethodSignature(const lexer::SourcePosition &start_loc, bool is_readonly)
{
    auto [key, isComputed] = ParseInterfacePropertyKey();

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_QUESTION_MARK) {
        ThrowSyntaxError("Optional properties are not supported.");
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS ||
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        auto type_params_ctx = binder::LexicalScope<binder::LocalScope>(Binder());
        ir::TSTypeParameterDeclaration *type_param_decl = nullptr;

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
            auto options = TypeAnnotationParsingOptions::THROW_ERROR;
            type_param_decl = ParseTypeParameterDeclaration(&options);
        }

        FunctionParameterContext func_param_context(&GetContext(), Binder());
        auto *func_param_scope = func_param_context.LexicalScope().GetScope();
        auto params = ParseFunctionParams();

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
            ThrowSyntaxError("Type expected.");
        }

        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options =
            TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::CAN_BE_TS_TYPE_PREDICATE;
        ir::TypeNode *return_type = ParseTypeAnnotation(&options);

        auto *method_signature = AllocNode<ir::TSMethodSignature>(func_param_scope, key, type_param_decl,
                                                                  std::move(params), return_type, isComputed, false);
        func_param_scope->BindNode(method_signature);
        method_signature->SetRange({start_loc, Lexer()->GetToken().End()});
        return method_signature;
    }

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
        ThrowSyntaxError("Type expected.");
    }

    Lexer()->NextToken();  // eat ':'
    TypeAnnotationParsingOptions options =
        TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::BREAK_AT_NEW_LINE;
    ir::TypeNode *type_annotation = ParseTypeAnnotation(&options);

    auto *property_signature = AllocNode<ir::TSPropertySignature>(key, type_annotation, isComputed, false, is_readonly);
    property_signature->SetRange({start_loc, Lexer()->GetToken().End()});
    return property_signature;
}

ir::AstNode *ASParser::ParseTypeLiteralOrInterfaceMember()
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_AT) {
        ThrowSyntaxError("Decorators are not allowed here");
    }

    char32_t next_cp = Lexer()->Lookahead();
    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();
    bool is_readonly = Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_READONLY &&
                       next_cp != lexer::LEX_CHAR_LEFT_PAREN && next_cp != lexer::LEX_CHAR_COLON;

    if (is_readonly) {
        Lexer()->NextToken();  // eat 'readonly"
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
        return ParseIndexSignature(start_loc, is_readonly);
    }

    return ParsePropertyOrMethodSignature(start_loc, is_readonly);
}

ArenaVector<ir::TSClassImplements *> ASParser::ParseClassImplementClause()
{
    ArenaVector<ir::TSClassImplements *> implements(Allocator()->Adapter());

    while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
            ThrowSyntaxError("Identifier expected");
        }

        const lexer::SourcePosition &implement_start = Lexer()->GetToken().Start();
        lexer::SourcePosition implements_end = Lexer()->GetToken().End();
        auto *implements_name = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
        implements_name->SetRange(Lexer()->GetToken().Loc());
        auto *implements_clause = AllocNode<ir::NamedType>(implements_name);
        implements_clause->SetRange(Lexer()->GetToken().Loc());
        Lexer()->NextToken();

        ir::NamedType *current = implements_clause->AsNamedType();
        while (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD) {
            Lexer()->NextToken();

            if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
                ThrowSyntaxError("Identifier expected");
            }

            implements_name = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
            implements_name->SetRange(Lexer()->GetToken().Loc());
            auto *next = AllocNode<ir::NamedType>(implements_name);
            current->SetRange(Lexer()->GetToken().Loc());
            current->SetNext(next);
            current = next;
            implements_end = Lexer()->GetToken().End();
            Lexer()->NextToken();
        }

        ir::TSTypeParameterInstantiation *impl_type_params = nullptr;
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SHIFT) {
            Lexer()->BackwardToken(lexer::TokenType::PUNCTUATOR_LESS_THAN, 1);
        }

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN ||
            Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SHIFT) {
            TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
            impl_type_params = ParseTypeParameterInstantiation(&options);
        }

        auto *impl = AllocNode<ir::TSClassImplements>(current, impl_type_params);
        impl->SetRange({implement_start, Lexer()->GetToken().End()});
        implements.push_back(impl);

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
            Lexer()->NextToken();
            continue;
        }

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
            ThrowSyntaxError("',' expected");
        }
    }

    if (implements.empty()) {
        ThrowSyntaxError("Implements clause can not be empty");
    }

    return implements;
}

ir::TypeNode *ASParser::ParseClassKeyAnnotation()
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options =
            TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::BREAK_AT_NEW_LINE;
        return ParseTypeAnnotation(&options);
    }

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS &&
        Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        ThrowSyntaxError("Type expected");
    }

    return nullptr;
}

void ASParser::ValidateClassMethodStart(ClassElementDescriptor *desc, ir::TypeNode *type_annotation)
{
    if (type_annotation == nullptr && (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS ||
                                       Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN)) {
        if ((desc->modifiers & ir::ModifierFlags::DECLARE) != 0) {
            ThrowSyntaxError("'declare' modifier cannot appear on class elements of this kind");
        }

        desc->class_method = true;
    } else {
        if (((desc->modifiers & ir::ModifierFlags::ASYNC) != 0) || desc->is_generator) {
            ThrowSyntaxError("Expected '('");
        }
        desc->class_field = true;

        if (desc->invalid_computed_property) {
            ThrowSyntaxError(
                "Computed property name must refer to a symbol or "
                "literal expression whose value is "
                "number or string");
        }
    }

    if ((desc->modifiers & ir::ModifierFlags::ASYNC) != 0) {
        desc->new_status |= ParserStatus::ASYNC_FUNCTION;
    }

    if (desc->is_generator) {
        desc->new_status |= ParserStatus::GENERATOR_FUNCTION;
    }
}

void ASParser::ValidateClassSetter(ClassElementDescriptor *desc, const ArenaVector<ir::AstNode *> &properties,
                                   ir::Expression *prop_name, ir::ScriptFunction *func)
{
    if (func->Params().size() != 1) {
        ThrowSyntaxError("Setter must have exactly one formal parameter");
    }

    if ((desc->modifiers & ir::ModifierFlags::STATIC) == 0) {
        ir::ModifierFlags access = GetAccessability(desc->modifiers);
        CheckAccessorPair(properties, prop_name, ir::MethodDefinitionKind::GET, access);
    }
}

void ASParser::ValidateClassGetter(ClassElementDescriptor *desc, const ArenaVector<ir::AstNode *> &properties,
                                   ir::Expression *prop_name, [[maybe_unused]] ir::ScriptFunction *func)
{
    if ((desc->modifiers & ir::ModifierFlags::STATIC) != 0) {
        ir::ModifierFlags access = GetAccessability(desc->modifiers);

        CheckAccessorPair(properties, prop_name, ir::MethodDefinitionKind::SET, access);
    }
}

ir::ClassElement *ASParser::ParseClassStaticBlock()
{
    ThrowSyntaxError("Unexpected token");
    return nullptr;
}

void ASParser::ParseOptionalClassElement([[maybe_unused]] ClassElementDescriptor *desc)
{
    ThrowSyntaxError("Optional properties are not supported");
}

void ASParser::ValidateIndexSignatureTypeAnnotation(ir::TypeNode *type_annotation)
{
    if (type_annotation == nullptr) {
        ThrowSyntaxError("':' expected");
    }

    if (!type_annotation->IsNamedType()) {
        ThrowSyntaxError("Identifier expected");
    }
}

bool ASParser::IsModifierKind(const lexer::Token &token)
{
    switch (token.KeywordType()) {
        case lexer::TokenType::KEYW_PUBLIC:
        case lexer::TokenType::KEYW_PRIVATE:
        case lexer::TokenType::KEYW_PROTECTED:
        case lexer::TokenType::KEYW_STATIC:
        case lexer::TokenType::KEYW_ASYNC:
        case lexer::TokenType::KEYW_DECLARE:
        case lexer::TokenType::KEYW_READONLY:
            return true;
        default:
            break;
    }

    return false;
}

void ASParser::ConsumeClassPrivateIdentifier([[maybe_unused]] ClassElementDescriptor *desc,
                                             [[maybe_unused]] char32_t *next_cp)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_HASH_MARK) {
        ThrowSyntaxError("Invalid character");
    }
}

std::tuple<bool, bool, bool> ASParser::ParseComputedClassFieldOrIndexSignature(ir::Expression **prop_name)
{
    Lexer()->NextToken();  // eat left square bracket

    if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT &&
        Lexer()->Lookahead() == lexer::LEX_CHAR_COLON) {
        if (!Lexer()->GetToken().Ident().Is("key")) {
            ThrowSyntaxError("'key' expected.");
        }

        auto id = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
        id->SetRange(Lexer()->GetToken().Loc());

        Lexer()->NextToken();  // eat param

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
            ThrowSyntaxError("':' expected");
        }

        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        ir::TypeNode *type_annotation = ParseTypeAnnotation(&options);

        if (!type_annotation->IsNamedType()) {
            ThrowSyntaxError("Type expected");
        }

        id->SetTsTypeAnnotation(type_annotation);
        *prop_name = id;

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
            ThrowSyntaxError("']' expected");
        }

        Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);

        return {false, false, true};
    }

    *prop_name = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA);

    bool invalid_computed_property =
        !(*prop_name)->IsNumberLiteral() && !(*prop_name)->IsStringLiteral() &&
        !((*prop_name)->IsMemberExpression() && (*prop_name)->AsMemberExpression()->Object()->IsIdentifier() &&
          (*prop_name)->AsMemberExpression()->Object()->AsIdentifier()->Name().Is("Symbol"));

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
        ThrowSyntaxError("Unexpected token, expected ']'");
    }

    return {true, invalid_computed_property, false};
}

std::tuple<bool, ir::BlockStatement *, lexer::SourcePosition, bool> ASParser::ParseFunctionBody(
    [[maybe_unused]] const ArenaVector<ir::Expression *> &params, [[maybe_unused]] ParserStatus new_status,
    ParserStatus context_status, binder::FunctionScope *func_scope)
{
    bool is_declare = InAmbientContext();
    bool is_overload = false;
    bool let_declare = true;
    ir::BlockStatement *body = nullptr;
    lexer::SourcePosition end_loc = Lexer()->GetToken().End();

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        if (!is_declare && ((context_status & ParserStatus::IN_METHOD_DEFINITION) == 0)) {
            ThrowSyntaxError("Unexpected token, expected '{'");
        } else {
            let_declare = false;
        }

        is_overload = true;
    } else if (is_declare) {
        ThrowSyntaxError("An implementation cannot be declared in ambient contexts.");
    } else {
        body = ParseBlockStatement(func_scope);
        end_loc = body->End();
    }

    return {let_declare, body, end_loc, is_overload};
}

ir::AstNode *ASParser::ParseImportDefaultSpecifier(ArenaVector<ir::AstNode *> *specifiers)
{
    ir::Identifier *local = ParseNamedImport(Lexer()->GetToken());
    Lexer()->NextToken();  // eat local name

    auto *specifier = AllocNode<ir::ImportDefaultSpecifier>(local);
    specifier->SetRange(specifier->Local()->Range());
    specifiers->push_back(specifier);

    return nullptr;
}

ir::Expression *ASParser::ParseCoverParenthesizedExpressionAndArrowParameterList()
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
    lexer::SourcePosition start = Lexer()->GetToken().Start();
    Lexer()->NextToken();
    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD) {
        ir::SpreadElement *rest_element = ParseSpreadElement(ExpressionParseFlags::MUST_BE_PATTERN);

        rest_element->SetGrouped();
        rest_element->SetStart(start);

        ValidateArrowFunctionRestParameter(rest_element);

        Lexer()->NextToken();

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
            ThrowSyntaxError(":' expected");
        }

        Lexer()->NextToken();  // eat ':'

        ir::TypeNode *return_type_annotation = ParseTypeAnnotation(&options);

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_ARROW) {
            ThrowSyntaxError("'=>' expected");
        }

        return ParseArrowFunctionExpression(rest_element, nullptr, return_type_annotation, false);
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        Lexer()->NextToken();

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
            ThrowSyntaxError(":' expected");
        }

        Lexer()->NextToken();  // eat ':'

        ir::TypeNode *return_type_annotation = ParseTypeAnnotation(&options);

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_ARROW) {
            ThrowSyntaxError("'=>' expected");
        }

        auto *arrow_expr = ParseArrowFunctionExpression(nullptr, nullptr, return_type_annotation, false);
        arrow_expr->SetStart(start);
        arrow_expr->AsArrowFunctionExpression()->Function()->SetStart(start);

        return arrow_expr;
    }

    ir::Expression *expr = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA | ExpressionParseFlags::ACCEPT_REST |
                                           ExpressionParseFlags::POTENTIALLY_IN_PATTERN);

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError("')' expected");
    }

    expr->SetGrouped();
    expr->SetRange({start, Lexer()->GetToken().End()});
    Lexer()->NextToken();

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_ARROW) {
        ThrowSyntaxError("':' expected.");
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        auto saved_pos = Lexer()->Save();
        Lexer()->NextToken();  // eat ':'
        options = TypeAnnotationParsingOptions::NO_OPTS;
        ir::TypeNode *return_type_annotation = ParseTypeAnnotation(&options);

        if (return_type_annotation == nullptr) {
            Lexer()->Rewind(saved_pos);
            return expr;
        }

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_ARROW) {
            Lexer()->Rewind(saved_pos);
            return expr;
        }

        return ParseArrowFunctionExpression(expr, nullptr, return_type_annotation, false);
    }

    return expr;
}

ir::Expression *ASParser::ParsePrefixAssertionExpression()
{
    lexer::SourcePosition start_pos = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat <
    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
    ir::TypeNode *type = ParseTypeAnnotation(&options);

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_GREATER_THAN) {
        ThrowSyntaxError("'>' expected");
    }

    Lexer()->NextToken();  // eat >

    ir::Expression *expr = ParseExpression();

    auto *node = AllocNode<ir::PrefixAssertionExpression>(expr, type);
    node->SetRange({start_pos, Lexer()->GetToken().End()});
    return node;
}

ir::Statement *ASParser::ParseConstStatement(StatementParsingFlags flags)
{
    lexer::SourcePosition const_var_star = Lexer()->GetToken().Start();
    Lexer()->NextToken();

    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_ENUM) {
        return ParseEnumDeclaration(true);
    }

    if ((flags & StatementParsingFlags::ALLOW_LEXICAL) == 0) {
        ThrowSyntaxError("Lexical declaration is not allowed in single statement context");
    }

    auto *variable_decl =
        ParseVariableDeclaration(VariableParsingFlags::CONST | VariableParsingFlags::NO_SKIP_VAR_KIND);
    variable_decl->SetStart(const_var_star);
    ConsumeSemicolon(variable_decl);

    return variable_decl;
}

ir::AnnotatedExpression *ASParser::ParseVariableDeclaratorKey(VariableParsingFlags flags)
{
    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Identifier expected");
    }

    ValidateDeclaratorId();

    const util::StringView &ident_str = Lexer()->GetToken().Ident();
    auto init = AllocNode<ir::Identifier>(ident_str, Allocator());
    init->SetRange(Lexer()->GetToken().Loc());
    Lexer()->NextToken();

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        init->SetTsTypeAnnotation(ParseTypeAnnotation(&options));
    } else if (((flags & VariableParsingFlags::IN_FOR) == 0) &&
               Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        ThrowSyntaxError("Type expected");
    }

    return init;
}

ir::Statement *ASParser::ParsePotentialConstEnum(VariableParsingFlags flags)
{
    if ((flags & VariableParsingFlags::CONST) == 0) {
        ThrowSyntaxError("Variable declaration expected.");
    }

    return ParseEnumDeclaration(true);
}

// NOLINTNEXTLINE(google-default-arguments)
ir::ExportDefaultDeclaration *ASParser::ParseExportDefaultDeclaration(const lexer::SourcePosition &start_loc,
                                                                      bool is_export_equals)
{
    Lexer()->NextToken();  // eat `default` keyword or `=`

    ir::AstNode *decl_node = nullptr;
    bool eat_semicolon = false;

    ExportDeclarationContext export_decl_ctx(Binder());

    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::KEYW_FUNCTION: {
            decl_node = ParseFunctionDeclaration(true);
            break;
        }
        case lexer::TokenType::KEYW_CLASS: {
            decl_node = ParseClassDeclaration(ir::ClassDefinitionModifiers::ID_REQUIRED);
            break;
        }
        case lexer::TokenType::KEYW_INTERFACE: {
            decl_node = ParseInterfaceDeclaration(false);
            break;
        }
        case lexer::TokenType::KEYW_NAMESPACE: {
            Lexer()->NextToken();  // eat 'namespace'
            decl_node = ParseModuleOrNamespaceDeclaration(start_loc);
            break;
        }
        case lexer::TokenType::KEYW_ENUM: {
            decl_node = ParseEnumDeclaration();
            break;
        }
        case lexer::TokenType::KEYW_ASYNC: {
            if ((Lexer()->GetToken().Flags() & lexer::TokenFlags::HAS_ESCAPE) == 0) {
                Lexer()->NextToken();  // eat `async`
                decl_node = ParseFunctionDeclaration(false, ParserStatus::ASYNC_FUNCTION);
                break;
            }

            [[fallthrough]];
        }
        default: {
            decl_node = ParseExpression();
            eat_semicolon = true;
            break;
        }
    }

    lexer::SourcePosition end_loc = decl_node->End();
    auto *export_declaration = AllocNode<ir::ExportDefaultDeclaration>(decl_node, is_export_equals);
    export_declaration->SetRange({start_loc, end_loc});

    if (eat_semicolon) {
        ConsumeSemicolon(export_declaration);
    }

    return export_declaration;
}

ir::ExportNamedDeclaration *ASParser::ParseNamedExportDeclaration(const lexer::SourcePosition &start_loc)
{
    ir::Statement *decl = nullptr;

    ir::ClassDefinitionModifiers class_modifiers = ir::ClassDefinitionModifiers::ID_REQUIRED;
    ir::ModifierFlags flags = ir::ModifierFlags::NONE;

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_DECLARE) {
        CheckDeclare();
    }

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_ABSTRACT) {
        Lexer()->NextToken();  // eat 'abstract'
        flags |= ir::ModifierFlags::ABSTRACT;
    }

    ExportDeclarationContext export_decl_ctx(Binder());

    switch (Lexer()->GetToken().KeywordType()) {
        case lexer::TokenType::KEYW_VAR: {
            decl = ParseVariableDeclaration(VariableParsingFlags::VAR);
            break;
        }
        case lexer::TokenType::KEYW_CONST: {
            decl = ParseVariableDeclaration(VariableParsingFlags::CONST);
            break;
        }
        case lexer::TokenType::KEYW_LET: {
            decl = ParseVariableDeclaration(VariableParsingFlags::LET);
            break;
        }
        case lexer::TokenType::KEYW_FUNCTION: {
            decl = ParseFunctionDeclaration(false, ParserStatus::NO_OPTS);
            break;
        }
        case lexer::TokenType::KEYW_CLASS: {
            decl = ParseClassDeclaration(class_modifiers, flags);
            break;
        }
        case lexer::TokenType::KEYW_ENUM: {
            decl = ParseEnumDeclaration();
            break;
        }
        case lexer::TokenType::KEYW_INTERFACE: {
            decl = ParseInterfaceDeclaration(false);
            break;
        }
        case lexer::TokenType::KEYW_TYPE: {
            decl = ParseTypeAliasDeclaration();
            break;
        }
        case lexer::TokenType::KEYW_GLOBAL:
        case lexer::TokenType::KEYW_MODULE:
        case lexer::TokenType::KEYW_NAMESPACE: {
            decl = ParseModuleDeclaration();
            break;
        }
        default: {
            if (!Lexer()->GetToken().IsAsyncModifier()) {
                ThrowSyntaxError("Unexpected token");
            }

            Lexer()->NextToken();  // eat `async` keyword
            decl = ParseFunctionDeclaration(false, ParserStatus::ASYNC_FUNCTION);
        }
    }

    if (decl->IsVariableDeclaration()) {
        ConsumeSemicolon(decl);
    }

    lexer::SourcePosition end_loc = decl->End();
    ArenaVector<ir::ExportSpecifier *> specifiers(Allocator()->Adapter());
    auto *export_declaration = AllocNode<ir::ExportNamedDeclaration>(Allocator(), decl, std::move(specifiers));
    export_declaration->SetRange({start_loc, end_loc});

    return export_declaration;
}

ir::AstNode *ASParser::ParseImportSpecifiers(ArenaVector<ir::AstNode *> *specifiers)
{
    ASSERT(specifiers->empty());

    if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
        ParseImportDefaultSpecifier(specifiers);
        return nullptr;
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY) {
        ParseNameSpaceImport(specifiers);
    } else if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        ParseNamedImportSpecifiers(specifiers);
    }

    return nullptr;
}

ir::Statement *ASParser::ParseImportDeclaration([[maybe_unused]] StatementParsingFlags flags)
{
    ImportDeclarationContext import_ctx(Binder());

    char32_t next_char = Lexer()->Lookahead();
    if (next_char == lexer::LEX_CHAR_LEFT_PAREN || next_char == lexer::LEX_CHAR_DOT) {
        return ParseExpressionStatement();
    }

    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat import

    ArenaVector<ir::AstNode *> specifiers(Allocator()->Adapter());

    ir::StringLiteral *source = nullptr;

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_STRING) {
        ParseImportSpecifiers(&specifiers);
        source = ParseFromClause(true);
    } else {
        source = ParseFromClause(false);
    }

    lexer::SourcePosition end_loc = source->End();
    auto *import_declaration = AllocNode<ir::ImportDeclaration>(source, std::move(specifiers));
    import_declaration->SetRange({start_loc, end_loc});

    ConsumeSemicolon(import_declaration);

    return import_declaration;
}

void ASParser::ThrowIllegalBreakError()
{
    ThrowSyntaxError("A 'break' statement can only be used within an enclosing iteration or switch statement");
}

void ASParser::ThrowIllegalContinueError()
{
    ThrowSyntaxError("A 'continue' statement can only be used within an enclosing iteration statement");
}

}  // namespace panda::es2panda::parser
