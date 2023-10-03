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

#include "TypedParser.h"

#include "binder/privateBinding.h"
#include "binder/tsBinding.h"
#include "lexer/lexer.h"
#include "ir/base/classDefinition.h"
#include "ir/base/decorator.h"
#include "ir/base/spreadElement.h"
#include "ir/base/tsPropertySignature.h"
#include "ir/base/tsMethodSignature.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/tsIndexSignature.h"
#include "ir/base/scriptFunction.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/yieldExpression.h"
#include "ir/expressions/objectExpression.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/arrowFunctionExpression.h"
#include "ir/expressions/sequenceExpression.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/functionExpression.h"
#include "ir/statement.h"
#include "ir/statements/classDeclaration.h"
#include "ir/statements/variableDeclarator.h"
#include "ir/ts/tsModuleDeclaration.h"
#include "ir/ts/tsModuleBlock.h"
#include "ir/ts/tsInterfaceBody.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "ir/ts/tsEnumMember.h"
#include "ir/ts/tsEnumDeclaration.h"
#include "ir/ts/tsTypeParameterInstantiation.h"
#include "ir/ts/tsTypeParameterDeclaration.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ts/tsQualifiedName.h"
#include "ir/ts/tsTypeReference.h"
#include "ir/ts/tsTypeAliasDeclaration.h"
#include "ir/ts/tsInterfaceHeritage.h"
#include "ir/ts/tsClassImplements.h"
#include "ir/ts/tsTypeAssertion.h"

namespace panda::es2panda::parser {

ir::Expression *TypedParser::ParsePotentialAsExpression([[maybe_unused]] ir::Expression *primary_expression)
{
    return nullptr;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *TypedParser::ParseExpression(ExpressionParseFlags flags)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_YIELD &&
        ((flags & ExpressionParseFlags::DISALLOW_YIELD) == 0)) {
        ir::YieldExpression *yield_expr = ParseYieldExpression();

        return ParsePotentialExpressionSequence(yield_expr, flags);
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        const auto start_pos = Lexer()->Save();

        // TODO(rsipka): ParseTsGenericArrowFunction and ParseTsTypeAssertion might be in a common function
        ir::Expression *expr = ParseGenericArrowFunction();
        // TODO(rsipka): negative cases are not covered, probably this is not a complete solution yet
        if (expr == nullptr) {
            Lexer()->Rewind(start_pos);
            expr = ParseTypeAssertion();
        }

        return expr;
    }

    ir::Expression *unary_expression_node = ParseUnaryOrPrefixUpdateExpression(flags);

    if (unary_expression_node->IsArrowFunctionExpression()) {
        return unary_expression_node;
    }

    ir::Expression *assignment_expression = ParseAssignmentExpression(unary_expression_node, flags);

    if (Lexer()->GetToken().NewLine()) {
        return assignment_expression;
    }

    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::LITERAL_IDENT: {
            if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_AS) {
                return ParsePotentialAsExpression(assignment_expression);
            }
            break;
        }
        case lexer::TokenType::PUNCTUATOR_COMMA: {
            if ((flags & ExpressionParseFlags::ACCEPT_COMMA) != 0) {
                return ParseSequenceExpression(assignment_expression,
                                               ((flags & ExpressionParseFlags::ACCEPT_REST) != 0));
            }
            break;
        }
        default: {
            break;
        }
    }

    return assignment_expression;
}

ir::Statement *TypedParser::ParsePotentialExpressionStatement(StatementParsingFlags flags)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT);

    switch (Lexer()->GetToken().KeywordType()) {
        case lexer::TokenType::KEYW_TYPE: {
            return ParseTypeAliasDeclaration();
        }
        case lexer::TokenType::KEYW_ABSTRACT: {
            Lexer()->NextToken();  // eat abstract keyword

            if (Lexer()->GetToken().Type() != lexer::TokenType::KEYW_CLASS) {
                ThrowSyntaxError(
                    "abstract modifier can only appear on a class, struct, method, or property declaration.");
            }

            return ParseClassStatement(flags, ir::ClassDefinitionModifiers::NONE, ir::ModifierFlags::ABSTRACT);
        }
        case lexer::TokenType::KEYW_GLOBAL:
        case lexer::TokenType::KEYW_MODULE:
        case lexer::TokenType::KEYW_NAMESPACE: {
            return ParseModuleDeclaration();
        }
        default: {
            break;
        }
    }
    return ParseExpressionStatement(flags);
}

ir::TSTypeAssertion *TypedParser::ParseTypeAssertion()
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN);
    lexer::SourcePosition start = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat '<'

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
    ir::TypeNode *type_annotation = ParseTypeAnnotation(&options);

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_GREATER_THAN) {
        return nullptr;
    }

    Lexer()->NextToken();  // eat '>'
    ir::Expression *expression = ParseExpression();
    auto *type_assertion = AllocNode<ir::TSTypeAssertion>(type_annotation, expression);
    type_assertion->SetRange({start, Lexer()->GetToken().End()});

    return type_assertion;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Statement *TypedParser::ParseModuleDeclaration([[maybe_unused]] StatementParsingFlags flags)
{
    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();
    GetContext().Status() |= ParserStatus::MODULE;

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_GLOBAL) {
        return ParseAmbientExternalModuleDeclaration(start_loc);
    }

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_NAMESPACE) {
        Lexer()->NextToken();
    } else {
        ASSERT(Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_MODULE);
        Lexer()->NextToken();
        if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_STRING) {
            return ParseAmbientExternalModuleDeclaration(start_loc);
        }
    }

    return ParseModuleOrNamespaceDeclaration(start_loc);
}

ir::ArrowFunctionExpression *TypedParser::ParseGenericArrowFunction()
{
    ArrowFunctionContext arrow_function_context(this, false);

    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN);
    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();

    auto type_params_ctx = binder::LexicalScope<binder::LocalScope>(Binder());

    auto type_param_decl_options = TypeAnnotationParsingOptions::NO_OPTS;
    ir::TSTypeParameterDeclaration *type_param_decl = ParseTypeParameterDeclaration(&type_param_decl_options);

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        return nullptr;
    }

    FunctionParameterContext func_param_context(&GetContext(), Binder());
    auto params = ParseFunctionParams();

    ParserStatus arrow_status = ParserStatus::NO_OPTS;

    if (std::any_of(params.begin(), params.end(), [](const auto *param) { return !param->IsIdentifier(); })) {
        arrow_status = ParserStatus::HAS_COMPLEX_PARAM;
    }

    ir::TypeNode *return_type_annotation = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        return_type_annotation = ParseTypeAnnotation(&options);
    }

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_ARROW) {
        return nullptr;
    }

    ArrowFunctionDescriptor desc(std::move(params), func_param_context.LexicalScope().GetScope(), start_loc,
                                 arrow_status);

    auto function_ctx = binder::LexicalScope<binder::FunctionScope>(Binder());
    return ParseArrowFunctionExpressionBody(&arrow_function_context, function_ctx.GetScope(), &desc, type_param_decl,
                                            return_type_annotation);
}

ir::TSModuleDeclaration *TypedParser::ParseAmbientExternalModuleDeclaration(const lexer::SourcePosition &start_loc)
{
    bool is_global = false;
    ir::Expression *name = nullptr;

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_GLOBAL) {
        is_global = true;
        name = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    } else {
        ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_STRING);

        if (!InAmbientContext()) {
            ThrowSyntaxError("Only ambient modules can use quoted names");
        }

        name = AllocNode<ir::StringLiteral>(Lexer()->GetToken().String());
    }

    name->SetRange(Lexer()->GetToken().Loc());

    Lexer()->NextToken();

    auto local_ctx = binder::LexicalScope<binder::LocalScope>(Binder());

    ir::Statement *body = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        body = ParseTsModuleBlock();
    } else if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
        Lexer()->NextToken();
    } else {
        ThrowSyntaxError("';' expected");
    }

    auto *module_decl = AllocNode<ir::TSModuleDeclaration>(Allocator(), local_ctx.GetScope(), name, body,
                                                           InAmbientContext(), is_global);
    module_decl->SetRange({start_loc, Lexer()->GetToken().End()});
    local_ctx.GetScope()->BindNode(module_decl);

    return module_decl;
}

ir::TSModuleDeclaration *TypedParser::ParseModuleOrNamespaceDeclaration(const lexer::SourcePosition &start_loc)
{
    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Identifier expected");
    }

    auto *decl = Binder()->AddDecl<binder::VarDecl>(Lexer()->GetToken().Start(), Lexer()->GetToken().Ident());

    auto *ident_node = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    ident_node->SetRange(Lexer()->GetToken().Loc());

    Lexer()->NextToken();

    ir::Statement *body = nullptr;
    auto local_ctx = binder::LexicalScope<binder::LocalScope>(Binder());

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD) {
        Lexer()->NextToken();
        lexer::SourcePosition module_start = Lexer()->GetToken().Start();
        body = ParseModuleOrNamespaceDeclaration(module_start);
    } else {
        body = ParseTsModuleBlock();
    }

    auto *module_decl = AllocNode<ir::TSModuleDeclaration>(Allocator(), local_ctx.GetScope(), ident_node, body,
                                                           InAmbientContext(), false);
    module_decl->SetRange({start_loc, Lexer()->GetToken().End()});
    local_ctx.GetScope()->BindNode(module_decl);
    decl->BindNode(module_decl);

    return module_decl;
}

ir::TSModuleBlock *TypedParser::ParseTsModuleBlock()
{
    auto local_ctx = binder::LexicalScope<binder::LocalScope>(Binder());
    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        ThrowSyntaxError("'{' expected.");
    }

    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();
    Lexer()->NextToken();
    auto statements = ParseStatementList();

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        ThrowSyntaxError("Expected a '}'");
    }

    auto *block_node = AllocNode<ir::TSModuleBlock>(local_ctx.GetScope(), std::move(statements));
    block_node->SetRange({start_loc, Lexer()->GetToken().End()});
    local_ctx.GetScope()->BindNode(block_node);

    Lexer()->NextToken();
    return block_node;
}

void TypedParser::CheckDeclare()
{
    ASSERT(Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_DECLARE);

    if (InAmbientContext()) {
        ThrowSyntaxError("A 'declare' modifier cannot be used in an already ambient context.");
    }

    GetContext().Status() |= ParserStatus::IN_AMBIENT_CONTEXT;

    Lexer()->NextToken();  // eat 'declare'

    switch (Lexer()->GetToken().KeywordType()) {
        case lexer::TokenType::KEYW_VAR:
        case lexer::TokenType::KEYW_LET:
        case lexer::TokenType::KEYW_CONST:
        case lexer::TokenType::KEYW_FUNCTION:
        case lexer::TokenType::KEYW_CLASS:
        case lexer::TokenType::KEYW_TYPE:
        case lexer::TokenType::KEYW_MODULE:
        case lexer::TokenType::KEYW_GLOBAL:
        case lexer::TokenType::KEYW_NAMESPACE:
        case lexer::TokenType::KEYW_ENUM:
        case lexer::TokenType::KEYW_ABSTRACT:
        case lexer::TokenType::KEYW_INTERFACE: {
            return;
        }
        default: {
            ThrowSyntaxError("Unexpected token.");
        }
    }
}

void TypedParser::ParseDecorators(ArenaVector<ir::Decorator *> &decorators)
{
    while (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_AT) {
        decorators.push_back(ParseDecorator());
    }
}

ir::TypeNode *TypedParser::ParseFunctionReturnType(ParserStatus status)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options =
            TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::RETURN_TYPE;
        return ParseTypeAnnotation(&options);
    }

    if ((status & ParserStatus::NEED_RETURN_TYPE) != 0) {
        ThrowSyntaxError("Type expected");
    }

    return nullptr;
}

ir::TypeNode *TypedParser::ParseInterfaceExtendsElement()
{
    const lexer::SourcePosition &heritage_start = Lexer()->GetToken().Start();
    lexer::SourcePosition heritage_end = Lexer()->GetToken().End();
    ir::Expression *expr = ParseQualifiedName();

    if (Lexer()->Lookahead() == lexer::LEX_CHAR_LESS_THAN) {
        Lexer()->ForwardToken(lexer::TokenType::PUNCTUATOR_LESS_THAN, 1);
    }

    ir::TSTypeParameterInstantiation *type_param_inst = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        type_param_inst = ParseTypeParameterInstantiation(&options);
        heritage_end = type_param_inst->End();
    }

    auto *type_reference = AllocNode<ir::TSTypeReference>(expr, type_param_inst);
    type_reference->SetRange({heritage_start, heritage_end});
    return type_reference;
}

ArenaVector<ir::TSInterfaceHeritage *> TypedParser::ParseInterfaceExtendsClause()
{
    Lexer()->NextToken();  // eat extends keyword

    ArenaVector<ir::TSInterfaceHeritage *> extends(Allocator()->Adapter());

    while (true) {
        auto *type_reference = ParseInterfaceExtendsElement();
        auto *heritage = AllocNode<ir::TSInterfaceHeritage>(type_reference);
        heritage->SetRange(type_reference->Range());
        extends.push_back(heritage);

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
            break;
        }

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COMMA) {
            ThrowSyntaxError("',' expected");
        }

        Lexer()->NextToken();
    }

    return extends;
}

ir::TSTypeParameterDeclaration *TypedParser::ParseFunctionTypeParameters()
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        auto options = TypeAnnotationParsingOptions::THROW_ERROR;
        return ParseTypeParameterDeclaration(&options);
    }

    return nullptr;
}

util::StringView TypedParser::FormInterfaceOrEnumDeclarationIdBinding(ir::Identifier *id)
{
    binder::TSBinding ts_binding(Allocator(), id->Name());
    return ts_binding.View();
}

TypedParser::InterfaceId TypedParser::ParseInterfaceDeclarationId()
{
    auto *id = ExpectIdentifier(true);

    util::StringView ident = FormInterfaceOrEnumDeclarationIdBinding(id);

    const auto &bindings = Binder()->GetScope()->Bindings();
    auto res = bindings.find(ident);
    binder::InterfaceDecl *decl {};
    bool already_exists {};

    if (res == bindings.end()) {
        decl = Binder()->AddTsDecl<binder::InterfaceDecl>(Lexer()->GetToken().Start(), Allocator(), ident);
    } else if (!AllowInterfaceRedeclaration()) {
        ThrowSyntaxError("Interface redeclaration is not allowed");
    } else if (!res->second->Declaration()->IsInterfaceDecl()) {
        Binder()->ThrowRedeclaration(Lexer()->GetToken().Start(), id->Name());
    } else {
        decl = res->second->Declaration()->AsInterfaceDecl();
        already_exists = true;
    }

    return {id, decl, already_exists};
}

void TypedParser::BindInterfaceDeclarationId(binder::InterfaceDecl *decl, bool already_exists,
                                             ir::TSInterfaceDeclaration *interface_decl)
{
    if (!already_exists) {
        decl->BindNode(interface_decl);
        decl->AsInterfaceDecl()->Add(interface_decl);
    } else {
        decl->AsInterfaceDecl()->Add(interface_decl);
    }
}

ir::Statement *TypedParser::ParseInterfaceDeclaration(bool is_static)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::KEYW_INTERFACE);
    GetContext().Status() |= ParserStatus::ALLOW_THIS_TYPE;
    lexer::SourcePosition interface_start = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat interface keyword

    auto [id, decl, alreadyExists] = ParseInterfaceDeclarationId();

    auto type_params_ctx = binder::LexicalScope<binder::LocalScope>(Binder());
    ir::TSTypeParameterDeclaration *type_param_decl = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        auto options = TypeAnnotationParsingOptions::THROW_ERROR;
        type_param_decl = ParseTypeParameterDeclaration(&options);
    }

    ArenaVector<ir::TSInterfaceHeritage *> extends(Allocator()->Adapter());
    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_EXTENDS) {
        extends = ParseInterfaceExtendsClause();
    }

    auto local_scope = binder::LexicalScope<binder::LocalScope>(Binder());
    auto *ident_decl = Binder()->AddDecl<binder::ConstDecl>(id->Start(), id->Name());
    lexer::SourcePosition body_start = Lexer()->GetToken().Start();
    auto members = ParseTypeLiteralOrInterface();

    auto *body = AllocNode<ir::TSInterfaceBody>(std::move(members));
    body->SetRange({body_start, Lexer()->GetToken().End()});

    auto *interface_decl = AllocNode<ir::TSInterfaceDeclaration>(Allocator(), local_scope.GetScope(), id,
                                                                 type_param_decl, body, std::move(extends), is_static);
    interface_decl->SetRange({interface_start, Lexer()->GetToken().End()});
    ident_decl->BindNode(interface_decl);

    BindInterfaceDeclarationId(decl, alreadyExists, interface_decl);

    Lexer()->NextToken();
    GetContext().Status() &= ~ParserStatus::ALLOW_THIS_TYPE;

    return interface_decl;
}

static util::StringView GetTSPropertyName(ir::Expression *key)
{
    switch (key->Type()) {
        case ir::AstNodeType::IDENTIFIER: {
            return key->AsIdentifier()->Name();
        }
        case ir::AstNodeType::NUMBER_LITERAL: {
            return key->AsNumberLiteral()->Str();
        }
        case ir::AstNodeType::STRING_LITERAL: {
            return key->AsStringLiteral()->Str();
        }
        default: {
            UNREACHABLE();
        }
    }
}

void TypedParser::CheckObjectTypeForDuplicatedProperties(ir::Expression *key, ArenaVector<ir::AstNode *> &members)
{
    if (!key->IsIdentifier() && !key->IsNumberLiteral() && !key->IsStringLiteral()) {
        return;
    }

    for (auto *it : members) {
        ir::Expression *compare = nullptr;

        switch (it->Type()) {
            case ir::AstNodeType::TS_PROPERTY_SIGNATURE: {
                compare = it->AsTSPropertySignature()->Key();
                break;
            }
            case ir::AstNodeType::TS_METHOD_SIGNATURE: {
                compare = it->AsTSMethodSignature()->Key();
                break;
            }
            default: {
                continue;
            }
        }

        if (!compare->IsIdentifier() && !compare->IsNumberLiteral() && !compare->IsStringLiteral()) {
            continue;
        }

        if (GetTSPropertyName(key) == GetTSPropertyName(compare)) {
            ThrowSyntaxError("Duplicated identifier", key->Start());
        }
    }
}

ArenaVector<ir::AstNode *> TypedParser::ParseTypeLiteralOrInterface()
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE);

    Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat '{'

    ArenaVector<ir::AstNode *> members(Allocator()->Adapter());

    while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        ir::AstNode *member = ParseTypeLiteralOrInterfaceMember();

        if (member->IsMethodDefinition() && member->AsMethodDefinition()->Function()->IsOverload() &&
            member->AsMethodDefinition()->Function()->Body() != nullptr) {
            continue;
        }

        if (member->IsTSPropertySignature()) {
            CheckObjectTypeForDuplicatedProperties(member->AsTSPropertySignature()->Key(), members);
        } else if (member->IsTSMethodSignature()) {
            CheckObjectTypeForDuplicatedProperties(member->AsTSMethodSignature()->Key(), members);
        }

        members.push_back(member);

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
            break;
        }

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COMMA &&
            Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
            if (!Lexer()->GetToken().NewLine()) {
                ThrowSyntaxError("',' expected");
            }

            if (Lexer()->GetToken().IsKeyword() && ((Lexer()->GetToken().Type() != lexer::TokenType::KEYW_STATIC) &&
                                                    (Lexer()->GetToken().Type() != lexer::TokenType::KEYW_PRIVATE))) {
                Lexer()->GetToken().SetTokenType(lexer::TokenType::LITERAL_IDENT);
            }

            continue;
        }

        Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
    }

    return members;
}

ir::TSEnumDeclaration *TypedParser::ParseEnumMembers(ir::Identifier *key, const lexer::SourcePosition &enum_start,
                                                     bool is_const, [[maybe_unused]] bool is_static)
{
    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        ThrowSyntaxError("'{' expected");
    }

    ArenaVector<ir::AstNode *> members(Allocator()->Adapter());
    Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat '{'

    while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        ir::Expression *member_key = nullptr;
        const auto key_start_loc = Lexer()->GetToken().Start();
        binder::EnumDecl *decl {};

        if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
            member_key = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
            decl = Binder()->AddDecl<binder::EnumDecl>(key_start_loc, Lexer()->GetToken().Ident());
            member_key->SetRange(Lexer()->GetToken().Loc());
            Lexer()->NextToken();
        } else if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_STRING) {
            decl = Binder()->AddDecl<binder::EnumDecl>(key_start_loc, Lexer()->GetToken().String());
            member_key = AllocNode<ir::StringLiteral>(Lexer()->GetToken().String());
            member_key->SetRange(Lexer()->GetToken().Loc());
            Lexer()->NextToken();
        } else {
            ThrowSyntaxError("Unexpected token in enum member");
        }

        ir::Expression *member_init = nullptr;
        lexer::SourcePosition init_start = Lexer()->GetToken().Start();

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
            Lexer()->NextToken();  // eat '='
            init_start = Lexer()->GetToken().Start();
            member_init = ParseExpression();
        }

        auto *member = AllocNode<ir::TSEnumMember>(member_key, member_init);
        decl->BindNode(member);
        member->SetRange({init_start, Lexer()->GetToken().End()});
        members.push_back(member);

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
            Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat ','
        }
    }

    auto *enum_declaration = AllocNode<ir::TSEnumDeclaration>(Allocator(), Binder()->GetScope()->AsLocalScope(), key,
                                                              std::move(members), is_const);
    enum_declaration->SetRange({enum_start, Lexer()->GetToken().End()});
    Binder()->GetScope()->BindNode(enum_declaration);
    Lexer()->NextToken();  // eat '}'

    return enum_declaration;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Statement *TypedParser::ParseEnumDeclaration(bool is_const, [[maybe_unused]] bool is_static)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::KEYW_ENUM);
    lexer::SourcePosition enum_start = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat enum keyword

    auto *key = ExpectIdentifier(true);
    util::StringView ident = FormInterfaceOrEnumDeclarationIdBinding(key);

    const auto &bindings = Binder()->GetScope()->Bindings();
    auto res = bindings.find(ident);
    binder::EnumLiteralDecl *decl {};

    if (res == bindings.end()) {
        decl = Binder()->AddTsDecl<binder::EnumLiteralDecl>(Lexer()->GetToken().Start(), ident, is_const);
        binder::LexicalScope enum_ctx = binder::LexicalScope<binder::LocalScope>(Binder());
        decl->BindScope(enum_ctx.GetScope());
        auto *decl_node = ParseEnumMembers(key, enum_start, is_const, false);
        decl->BindNode(decl_node);
        return decl_node;
    }

    if (!res->second->Declaration()->IsEnumLiteralDecl() ||
        (is_const ^ res->second->Declaration()->AsEnumLiteralDecl()->IsConst()) != 0) {
        Binder()->ThrowRedeclaration(Lexer()->GetToken().Start(), key->Name());
    }

    decl = res->second->Declaration()->AsEnumLiteralDecl();

    auto scope_ctx = binder::LexicalScope<binder::LocalScope>::Enter(Binder(), decl->Scope());
    auto *decl_node = ParseEnumMembers(key, enum_start, is_const, false);
    decl->BindNode(decl_node);
    return decl_node;
}

ir::TSTypeParameter *TypedParser::ParseTypeParameter(TypeAnnotationParsingOptions *options)
{
    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();
    bool throw_error = ((*options) & TypeAnnotationParsingOptions::THROW_ERROR) != 0;
    bool add_binding = ((*options) & TypeAnnotationParsingOptions::ADD_TYPE_PARAMETER_BINDING) != 0;

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        if (!throw_error) {
            return nullptr;
        }

        ThrowSyntaxError("Type parameter declaration expected");
    }

    if (throw_error) {
        CheckIfTypeParameterNameIsReserved();
    }

    const auto &ident = Lexer()->GetToken().Ident();
    auto *param_ident = AllocNode<ir::Identifier>(ident, Allocator());
    binder::Decl *decl = nullptr;

    if (add_binding) {
        decl = Binder()->AddDecl<binder::TypeParameterDecl>(Lexer()->GetToken().Start(), param_ident->Name());
    }

    param_ident->SetRange({Lexer()->GetToken().Start(), Lexer()->GetToken().End()});

    Lexer()->NextToken();

    TypeAnnotationParsingOptions new_options = TypeAnnotationParsingOptions::NO_OPTS;

    if (throw_error) {
        new_options |= TypeAnnotationParsingOptions::THROW_ERROR;
    }

    ir::TypeNode *constraint = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_EXTENDS) {
        Lexer()->NextToken();
        constraint = ParseTypeAnnotation(&new_options);
    }

    ir::TypeNode *default_type = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        Lexer()->NextToken();
        default_type = ParseTypeAnnotation(&new_options);
    }

    auto *type_param = AllocNode<ir::TSTypeParameter>(param_ident, constraint, default_type);

    if (decl != nullptr) {
        decl->BindNode(type_param);
    }

    type_param->SetRange({start_loc, Lexer()->GetToken().End()});

    return type_param;
}

ir::TSTypeParameterDeclaration *TypedParser::ParseTypeParameterDeclaration(TypeAnnotationParsingOptions *options)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN);

    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();
    ArenaVector<ir::TSTypeParameter *> params(Allocator()->Adapter());
    bool seen_default = false;
    size_t required_params = 0;
    Lexer()->NextToken();  // eat '<'

    while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_GREATER_THAN) {
        auto new_options = *options | TypeAnnotationParsingOptions::ADD_TYPE_PARAMETER_BINDING;
        ir::TSTypeParameter *current_param = ParseTypeParameter(&new_options);

        if (current_param == nullptr) {
            ASSERT((new_options & TypeAnnotationParsingOptions::THROW_ERROR) == 0);
            return nullptr;
        }

        if (current_param->DefaultType() != nullptr) {
            seen_default = true;
        } else if (seen_default) {
            ThrowSyntaxError("Required type parameters may not follow optional type parameters.");
        } else {
            required_params++;
        }

        params.push_back(current_param);

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
            Lexer()->NextToken();
            continue;
        }

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_GREATER_THAN) {
            if ((new_options & TypeAnnotationParsingOptions::THROW_ERROR) == 0) {
                return nullptr;
            }

            ThrowSyntaxError("'>' expected");
        }
    }

    if (params.empty()) {
        ThrowSyntaxError("Type parameter list cannot be empty.");
    }

    lexer::SourcePosition end_loc = Lexer()->GetToken().End();
    Lexer()->NextToken();  // eat '>'

    auto *type_param_decl = AllocNode<ir::TSTypeParameterDeclaration>(Binder()->GetScope()->AsLocalScope(),
                                                                      std::move(params), required_params);
    type_param_decl->SetRange({start_loc, end_loc});
    Binder()->GetScope()->BindNode(type_param_decl);

    return type_param_decl;
}

ir::Expression *TypedParser::ParseSuperClassReference()
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_EXTENDS) {
        Lexer()->NextToken();

        return ParseLeftHandSideExpression();
    }

    return nullptr;
}

std::tuple<ir::Expression *, ir::TSTypeParameterInstantiation *> TypedParser::ParseSuperClass()
{
    ir::Expression *super_class = ParseSuperClassReference();

    ir::TSTypeParameterInstantiation *super_type_params = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN ||
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SHIFT) {
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SHIFT) {
            Lexer()->BackwardToken(lexer::TokenType::PUNCTUATOR_LESS_THAN, 1);
        }

        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        super_type_params = ParseTypeParameterInstantiation(&options);
    }

    return {super_class, super_type_params};
}

std::tuple<ir::Expression *, ir::TSTypeParameterInstantiation *> TypedParser::ParseClassImplementsElement()
{
    ir::Expression *expr = ParseQualifiedName();

    ir::TSTypeParameterInstantiation *impl_type_params = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN ||
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SHIFT) {
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SHIFT) {
            Lexer()->BackwardToken(lexer::TokenType::PUNCTUATOR_LESS_THAN, 1);
        }

        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        impl_type_params = ParseTypeParameterInstantiation(&options);
    }

    return {expr, impl_type_params};
}

ArenaVector<ir::TSClassImplements *> TypedParser::ParseClassImplementClause()
{
    ArenaVector<ir::TSClassImplements *> implements(Allocator()->Adapter());

    while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        lexer::SourcePosition impl_start = Lexer()->GetToken().Start();
        auto [expr, implTypeParams] = ParseClassImplementsElement();
        auto *impl = AllocNode<ir::TSClassImplements>(expr, implTypeParams);
        impl->SetRange({impl_start, Lexer()->GetToken().End()});
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

bool TypedParser::CheckClassElementInterfaceBody(ir::AstNode *property, ArenaVector<ir::AstNode *> &properties)
{
    for (auto *it : property->AsTSInterfaceBody()->Body()) {
        properties.push_back(it);
    }

    return true;
}

bool TypedParser::CheckClassElement(ir::AstNode *property, ir::MethodDefinition *&ctor,
                                    [[maybe_unused]] ArenaVector<ir::AstNode *> &properties)
{
    if (property->IsTSInterfaceBody()) {
        return CheckClassElementInterfaceBody(property, properties);
    }

    return ParserImpl::CheckClassElement(property, ctor, properties);
}

// NOLINTNEXTLINE(google-default-arguments)
ir::ClassDefinition *TypedParser::ParseClassDefinition(ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags flags)
{
    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();
    Lexer()->NextToken();

    ir::Identifier *ident_node = ParseClassIdent(modifiers);

    auto type_params_ctx = binder::LexicalScope<binder::LocalScope>(Binder());
    ir::TSTypeParameterDeclaration *type_param_decl = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        auto options = TypeAnnotationParsingOptions::THROW_ERROR;
        type_param_decl = ParseTypeParameterDeclaration(&options);
    }
    auto class_ctx = binder::LexicalScope<binder::LocalScope>(Binder());

    auto *ident_decl = BindClassName(ident_node);

    binder::PrivateBinding private_binding(Allocator(), ClassId()++);
    Binder()->AddDecl<binder::ConstDecl>(start_loc, private_binding.View());

    // Parse SuperClass
    auto [superClass, superTypeParams] = ParseSuperClass();

    if (superClass != nullptr) {
        modifiers |= ir::ClassDefinitionModifiers::HAS_SUPER;
    }

    // Parse implements clause
    ArenaVector<ir::TSClassImplements *> implements(Allocator()->Adapter());
    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_IMPLEMENTS) {
        Lexer()->NextToken();
        implements = ParseClassImplementClause();
    }

    ExpectToken(lexer::TokenType::PUNCTUATOR_LEFT_BRACE, false);

    // Parse ClassBody
    auto [ctor, properties, bodyRange] = ParseClassBody(modifiers, flags);

    if (InAmbientContext()) {
        flags |= ir::ModifierFlags::DECLARE;
    }

    CreateCCtor(class_ctx.GetScope(), properties, bodyRange.start);

    auto *class_scope = class_ctx.GetScope();
    auto *class_definition = AllocNode<ir::ClassDefinition>(class_scope, private_binding.View(), ident_node,
                                                            type_param_decl, superTypeParams, std::move(implements),
                                                            ctor, superClass, std::move(properties), modifiers, flags);

    class_definition->SetRange(bodyRange);
    class_scope->BindNode(class_definition);

    if (ident_decl != nullptr) {
        ident_decl->BindNode(class_definition);
    }

    return class_definition;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::AstNode *TypedParser::ParseClassElement(const ArenaVector<ir::AstNode *> &properties,
                                            ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags flags)
{
    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_STATIC &&
        Lexer()->Lookahead() == lexer::LEX_CHAR_LEFT_BRACE) {
        return ParseClassStaticBlock();
    }

    ClassElementDescriptor desc(Allocator());

    desc.method_kind = ir::MethodDefinitionKind::METHOD;
    desc.new_status = ParserStatus::ALLOW_SUPER;
    desc.has_super_class = (modifiers & ir::ClassDefinitionModifiers::HAS_SUPER) != 0;
    desc.prop_start = Lexer()->GetToken().Start();

    ParseDecorators(desc.decorators);

    desc.modifiers = ParseModifiers();

    if (((desc.modifiers & ir::ModifierFlags::ABSTRACT) != 0) && ((flags & ir::ModifierFlags::ABSTRACT) == 0)) {
        ThrowSyntaxError("Abstract methods can only appear within an abstract class.");
    }

    char32_t next_cp = Lexer()->Lookahead();
    CheckClassGeneratorMethod(&desc, &next_cp);
    ParseClassAccessor(&desc, &next_cp);

    if ((desc.modifiers & ir::ModifierFlags::STATIC) == 0) {
        GetContext().Status() |= ParserStatus::ALLOW_THIS_TYPE;
    }

    ir::Expression *prop_name = ParseClassKey(&desc);

    if (desc.method_kind == ir::MethodDefinitionKind::CONSTRUCTOR && !desc.decorators.empty()) {
        ThrowSyntaxError("Decorators are not valid here.", desc.decorators.front()->Start());
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_QUESTION_MARK) {
        ParseOptionalClassElement(&desc);
    } else if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK) {
        if (desc.is_index_signature || Lexer()->Lookahead() != lexer::LEX_CHAR_COLON) {
            ThrowSyntaxError("';' expected");
        }

        desc.modifiers |= ir::ModifierFlags::DEFINITE;
        Lexer()->NextToken();
    }

    ir::TypeNode *type_annotation = ParseClassKeyAnnotation();

    ir::AstNode *property = nullptr;

    if (desc.is_index_signature) {
        if (!desc.decorators.empty()) {
            ThrowSyntaxError("Decorators are not valid here.", desc.decorators.front()->Start());
        }

        ValidateIndexSignatureTypeAnnotation(type_annotation);

        if (type_annotation == nullptr) {
            ThrowSyntaxError("An index signature must have a type annotation");
        }

        if ((desc.modifiers & ir::ModifierFlags::DECLARE) != 0) {
            ThrowSyntaxError("'declare' modifier cannot appear on an index signature.");
        }

        property =
            AllocNode<ir::TSIndexSignature>(prop_name, type_annotation, desc.modifiers & ir::ModifierFlags::READONLY);

        property->SetRange({property->AsTSIndexSignature()->Param()->Start(),
                            property->AsTSIndexSignature()->TypeAnnotation()->End()});
    } else {
        ValidateClassMethodStart(&desc, type_annotation);
        property = ParseClassProperty(&desc, properties, prop_name, type_annotation);

        if (!desc.decorators.empty()) {
            if (desc.is_private_ident) {
                ThrowSyntaxError("Decorators are not valid here");
            }

            property->AddDecorators(std::move(desc.decorators));
        }
    }

    ASSERT(property != nullptr);
    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SEMI_COLON &&
        Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE &&
        ((Lexer()->GetToken().Flags() & lexer::TokenFlags::NEW_LINE) == 0) &&
        !(property->IsMethodDefinition() &&
          property->AsMethodDefinition()->Value()->AsFunctionExpression()->Function()->Body() != nullptr)) {
        ThrowSyntaxError("';' expected.");
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
        Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
    }

    GetContext().Status() &= ~ParserStatus::ALLOW_THIS_TYPE;

    if (desc.is_private_ident) {
        AddPrivateElement(property->AsClassElement());
    }

    return property;
}

void TypedParser::ParseOptionalClassElement(ClassElementDescriptor *desc)
{
    if (desc->is_index_signature) {
        ThrowSyntaxError("';' expected");
    }

    if (desc->method_kind == ir::MethodDefinitionKind::CONSTRUCTOR) {
        ThrowSyntaxError("'(' expected");
    }

    desc->modifiers |= ir::ModifierFlags::OPTIONAL;
    Lexer()->NextToken();
}

ir::ModifierFlags TypedParser::ParseModifiers()
{
    ir::ModifierFlags result_status = ir::ModifierFlags::NONE;
    ir::ModifierFlags prev_status = ir::ModifierFlags::ALL;

    while (IsModifierKind(Lexer()->GetToken())) {
        char32_t next_cp = Lexer()->Lookahead();
        if (!(next_cp != lexer::LEX_CHAR_EQUALS && next_cp != lexer::LEX_CHAR_SEMICOLON &&
              next_cp != lexer::LEX_CHAR_COMMA && next_cp != lexer::LEX_CHAR_LEFT_PAREN)) {
            break;
        }

        lexer::TokenFlags token_flags = Lexer()->GetToken().Flags();
        if ((token_flags & lexer::TokenFlags::HAS_ESCAPE) != 0) {
            ThrowSyntaxError("Keyword must not contain escaped characters");
        }

        ir::ModifierFlags actual_status = ir::ModifierFlags::NONE;
        ir::ModifierFlags next_status = ir::ModifierFlags::NONE;

        switch (Lexer()->GetToken().KeywordType()) {
            case lexer::TokenType::KEYW_PUBLIC: {
                actual_status = ir::ModifierFlags::PUBLIC;
                next_status = ir::ModifierFlags::ASYNC | ir::ModifierFlags::STATIC | ir::ModifierFlags::READONLY |
                              ir::ModifierFlags::DECLARE | ir::ModifierFlags::ABSTRACT;
                break;
            }
            case lexer::TokenType::KEYW_PRIVATE: {
                actual_status = ir::ModifierFlags::PRIVATE;
                next_status = ir::ModifierFlags::ASYNC | ir::ModifierFlags::STATIC | ir::ModifierFlags::READONLY |
                              ir::ModifierFlags::DECLARE | ir::ModifierFlags::ABSTRACT;
                break;
            }
            case lexer::TokenType::KEYW_PROTECTED: {
                actual_status = ir::ModifierFlags::PROTECTED;
                next_status = ir::ModifierFlags::ASYNC | ir::ModifierFlags::STATIC | ir::ModifierFlags::READONLY |
                              ir::ModifierFlags::DECLARE | ir::ModifierFlags::ABSTRACT;
                break;
            }
            case lexer::TokenType::KEYW_INTERNAL: {
                actual_status = ir::ModifierFlags::INTERNAL;
                next_status = ir::ModifierFlags::ASYNC | ir::ModifierFlags::STATIC | ir::ModifierFlags::READONLY |
                              ir::ModifierFlags::DECLARE | ir::ModifierFlags::ABSTRACT | ir::ModifierFlags::PROTECTED;
                break;
            }
            case lexer::TokenType::KEYW_STATIC: {
                actual_status = ir::ModifierFlags::STATIC;
                next_status = ir::ModifierFlags::ASYNC | ir::ModifierFlags::READONLY | ir::ModifierFlags::DECLARE |
                              ir::ModifierFlags::ABSTRACT;
                break;
            }
            case lexer::TokenType::KEYW_ASYNC: {
                actual_status = ir::ModifierFlags::ASYNC;
                next_status = ir::ModifierFlags::READONLY | ir::ModifierFlags::DECLARE | ir::ModifierFlags::ABSTRACT;
                break;
            }
            case lexer::TokenType::KEYW_ABSTRACT: {
                actual_status = ir::ModifierFlags::ABSTRACT;
                next_status = ir::ModifierFlags::ACCESS | ir::ModifierFlags::ASYNC | ir::ModifierFlags::STATIC |
                              ir::ModifierFlags::READONLY | ir::ModifierFlags::DECLARE;
                break;
            }
            case lexer::TokenType::KEYW_DECLARE: {
                actual_status = ir::ModifierFlags::DECLARE;
                next_status = ir::ModifierFlags::ACCESS | ir::ModifierFlags::ASYNC | ir::ModifierFlags::STATIC |
                              ir::ModifierFlags::READONLY;
                break;
            }
            case lexer::TokenType::KEYW_READONLY: {
                actual_status = ir::ModifierFlags::READONLY;
                next_status = ir::ModifierFlags::ASYNC | ir::ModifierFlags::DECLARE | ir::ModifierFlags::ABSTRACT;
                break;
            }
            default: {
                UNREACHABLE();
            }
        }

        next_cp = Lexer()->Lookahead();
        if (next_cp == lexer::LEX_CHAR_COLON || next_cp == lexer::LEX_CHAR_COMMA ||
            next_cp == lexer::LEX_CHAR_RIGHT_PAREN || next_cp == lexer::LEX_CHAR_QUESTION ||
            next_cp == lexer::LEX_CHAR_RIGHT_BRACE || next_cp == lexer::LEX_CHAR_LESS_THAN) {
            break;
        }

        auto pos = Lexer()->Save();
        Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);

        if ((prev_status & actual_status) == 0) {
            Lexer()->Rewind(pos);
            ThrowSyntaxError("Unexpected modifier");
        }

        if ((result_status & actual_status) != 0) {
            Lexer()->Rewind(pos);
            ThrowSyntaxError("Duplicated modifier is not allowed");
        }

        if ((GetContext().Status() & ParserStatus::CONSTRUCTOR_FUNCTION) != 0 &&
            (actual_status & ~ir::ModifierFlags::ALLOWED_IN_CTOR_PARAMETER) != 0) {
            Lexer()->Rewind(pos);
            ThrowParameterModifierError(actual_status);
        }

        result_status |= actual_status;
        prev_status = next_status;
    }

    return result_status;
}

ir::Expression *TypedParser::ParseQualifiedName(ExpressionParseFlags flags)
{
    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Identifier expected");
    }

    ir::Expression *expr = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    expr->AsIdentifier()->SetReference();
    expr->SetRange(Lexer()->GetToken().Loc());

    Lexer()->NextToken();

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD) {
        expr = ParseQualifiedReference(expr, flags);
    }

    return expr;
}

ir::Expression *TypedParser::ParseQualifiedReference(ir::Expression *type_name, ExpressionParseFlags flags)
{
    lexer::SourcePosition start_loc = type_name->Start();

    do {
        Lexer()->NextToken();  // eat '.'

        ir::Identifier *prop_name {};
        if ((flags & ExpressionParseFlags::IMPORT) != 0 &&
            Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY) {
            Lexer()->NextToken();  // eat '*'
            prop_name = AllocNode<ir::Identifier>(binder::Binder::STAR_IMPORT, Allocator());
        } else if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
            if ((flags & ExpressionParseFlags::POTENTIAL_CLASS_LITERAL) != 0) {
                if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_CLASS) {
                    type_name->SetRange({start_loc, Lexer()->GetToken().End()});
                    return type_name;
                }
                if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_THIS) {
                    return nullptr;
                }
            }

            ThrowSyntaxError("Identifier expected");
        } else {
            prop_name = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
        }

        prop_name->SetRange(Lexer()->GetToken().Loc());

        type_name = AllocNode<ir::TSQualifiedName>(type_name, prop_name);
        type_name->SetRange({type_name->AsTSQualifiedName()->Left()->Start(), Lexer()->GetToken().End()});

        if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
            Lexer()->NextToken();
        }

    } while (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD);

    type_name->SetRange({start_loc, Lexer()->GetToken().End()});

    return type_name;
}

ir::TSTypeParameterInstantiation *TypedParser::ParseTypeParameterInstantiation(TypeAnnotationParsingOptions *options)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN);
    bool throw_error = ((*options) & TypeAnnotationParsingOptions::THROW_ERROR) != 0;
    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();
    ArenaVector<ir::TypeNode *> params(Allocator()->Adapter());
    Lexer()->NextToken();  // eat '<'

    while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_GREATER_THAN) {
        ir::TypeNode *current_param = ParseTypeAnnotation(options);

        if (current_param == nullptr) {
            return nullptr;
        }

        params.push_back(current_param);

        switch (Lexer()->GetToken().Type()) {
            case lexer::TokenType::PUNCTUATOR_COMMA: {
                Lexer()->NextToken();
                continue;
            }
            case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT: {
                Lexer()->BackwardToken(lexer::TokenType::PUNCTUATOR_GREATER_THAN, 1);
                break;
            }
            case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT: {
                Lexer()->BackwardToken(lexer::TokenType::PUNCTUATOR_GREATER_THAN, 2);
                break;
            }
            case lexer::TokenType::PUNCTUATOR_GREATER_THAN: {
                break;
            }
            default: {
                if (throw_error) {
                    ThrowSyntaxError("'>' expected");
                }

                return nullptr;
            }
        }
    }

    lexer::SourcePosition end_loc = Lexer()->GetToken().End();
    Lexer()->NextToken();

    auto *type_param_inst = AllocNode<ir::TSTypeParameterInstantiation>(std::move(params));

    type_param_inst->SetRange({start_loc, end_loc});

    return type_param_inst;
}

ir::Statement *TypedParser::ParseDeclareAndDecorators(StatementParsingFlags flags)
{
    ArenaVector<ir::Decorator *> decorators(Allocator()->Adapter());

    ParseDecorators(decorators);

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_DECLARE) {
        CheckDeclare();
    }

    ir::Statement *stmt = TypedParser::ParseStatement(flags);

    GetContext().Status() &= ~ParserStatus::IN_AMBIENT_CONTEXT;
    AddDecorators(stmt, decorators);

    return stmt;
}

void TypedParser::ConvertThisKeywordToIdentIfNecessary()
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_THIS) {
        Lexer()->GetToken().SetTokenType(lexer::TokenType::LITERAL_IDENT);
    }
}

ir::VariableDeclarator *TypedParser::ParseVariableDeclarator(ir::Expression *init, lexer::SourcePosition start_loc,
                                                             VariableParsingFlags flags)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        return ParseVariableDeclaratorInitializer(init, flags, start_loc);
    }

    if (((flags & VariableParsingFlags::CONST) != 0) && ((flags & VariableParsingFlags::ACCEPT_CONST_NO_INIT) == 0) &&
        !InAmbientContext()) {
        ThrowSyntaxError("Missing initializer in const declaration");
    }

    if (((flags & VariableParsingFlags::IN_FOR) == 0) && (init->IsArrayPattern() || init->IsObjectPattern())) {
        ThrowSyntaxError("Missing initializer in destructuring declaration");
    }

    lexer::SourcePosition end_loc = init->End();
    auto declarator = AllocNode<ir::VariableDeclarator>(init);
    declarator->SetRange({start_loc, end_loc});

    return declarator;
}

void TypedParser::ParsePotentialOptionalFunctionParameter(ir::AnnotatedExpression *return_node)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_QUESTION_MARK) {
        ASSERT(return_node->IsIdentifier() || return_node->IsObjectPattern() || return_node->IsArrayPattern() ||
               return_node->IsRestElement());

        switch (return_node->Type()) {
            case ir::AstNodeType::IDENTIFIER: {
                return_node->AsIdentifier()->SetOptional(true);
                break;
            }
            case ir::AstNodeType::OBJECT_PATTERN: {
                return_node->AsObjectPattern()->SetOptional(true);
                break;
            }
            case ir::AstNodeType::ARRAY_PATTERN: {
                return_node->AsArrayPattern()->SetOptional(true);
                break;
            }
            case ir::AstNodeType::REST_ELEMENT: {
                return_node->AsRestElement()->SetOptional(true);
                break;
            }
            default: {
                UNREACHABLE();
            }
        }

        Lexer()->NextToken();  // eat '?'
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        return_node->SetTsTypeAnnotation(ParseTypeAnnotation(&options));
    }
}

ParserStatus TypedParser::ValidateArrowParameter(ir::Expression *expr, bool *seen_optional)
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

            if ((*seen_optional) && !is_optional) {
                ThrowSyntaxError("A required parameter cannot follow an optional parameter.", expr->Start());
            }

            (*seen_optional) |= is_optional;

            if (identifier.Is("arguments")) {
                ThrowSyntaxError("Binding 'arguments' in strict mode is invalid");
            } else if (identifier.Is("eval")) {
                ThrowSyntaxError("Binding 'eval' in strict mode is invalid");
            }

            ValidateArrowParameterBindings(expr);
            return ParserStatus::NO_OPTS;
        }
        case ir::AstNodeType::OBJECT_EXPRESSION: {
            ir::ObjectExpression *object_pattern = expr->AsObjectExpression();

            if (!object_pattern->ConvertibleToObjectPattern()) {
                ThrowSyntaxError("Invalid destructuring assignment target");
            }

            if (!InAmbientContext() && ((GetContext().Status() & ParserStatus::FUNCTION) != 0) &&
                object_pattern->IsOptional()) {
                ThrowSyntaxError("A binding pattern parameter cannot be optional in an implementation signature.",
                                 expr->Start());
            }

            ValidateArrowParameterBindings(expr);
            return ParserStatus::HAS_COMPLEX_PARAM;
        }
        case ir::AstNodeType::ARRAY_EXPRESSION: {
            ir::ArrayExpression *array_pattern = expr->AsArrayExpression();

            if (!array_pattern->ConvertibleToArrayPattern()) {
                ThrowSyntaxError("Invalid destructuring assignment target");
            }

            if (!InAmbientContext() && ((GetContext().Status() & ParserStatus::FUNCTION) != 0) &&
                array_pattern->IsOptional()) {
                ThrowSyntaxError("A binding pattern parameter cannot be optional in an implementation signature.",
                                 expr->Start());
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

}  // namespace panda::es2panda::parser
