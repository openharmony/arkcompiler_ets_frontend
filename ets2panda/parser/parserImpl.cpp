/**
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#include "parserImpl.h"

#include "binder/privateBinding.h"
#include "binder/scope.h"
#include "binder/tsBinding.h"
#include "ir/astDump.h"
#include "ir/astNode.h"
#include "ir/base/classDefinition.h"
#include "ir/base/classProperty.h"
#include "ir/base/classStaticBlock.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/property.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/spreadElement.h"
#include "ir/expression.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/literals/bigIntLiteral.h"
#include "ir/expressions/literals/booleanLiteral.h"
#include "ir/expressions/literals/nullLiteral.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/objectExpression.h"
#include "ir/expressions/superExpression.h"
#include "ir/module/exportDefaultDeclaration.h"
#include "ir/module/exportNamedDeclaration.h"
#include "ir/module/exportSpecifier.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/emptyStatement.h"
#include "ir/statements/expressionStatement.h"
#include "ir/statements/functionDeclaration.h"
#include "ir/statements/classDeclaration.h"
#include "lexer/lexer.h"
#include "lexer/token/letters.h"
#include "lexer/token/sourceLocation.h"

using namespace std::literals::string_literals;

namespace panda::es2panda::parser {
ParserImpl::ParserImpl(Program *program, const CompilerOptions &options, ParserStatus status)
    : program_(program), context_(program_, status), options_(options)
{
}

std::unique_ptr<lexer::Lexer> ParserImpl::InitLexer(const SourceFile &source_file)
{
    program_->SetSource(source_file);
    std::unique_ptr<lexer::Lexer> lexer = std::make_unique<lexer::Lexer>(&context_);
    lexer_ = lexer.get();
    return lexer;
}

void ParserImpl::ParseScript(const SourceFile &source_file, bool gen_std_lib)
{
    auto lexer = InitLexer(source_file);

    if (source_file.is_module) {
        context_.Status() |= (ParserStatus::MODULE);
        ParseProgram(ScriptKind::MODULE);

        if (!Binder()->TopScope()->AsModuleScope()->ExportAnalysis()) {
            ThrowSyntaxError("Invalid exported binding");
        }
    } else if (gen_std_lib) {
        ParseProgram(ScriptKind::STDLIB);
    } else {
        ParseProgram(ScriptKind::SCRIPT);
    }
}

void ParserImpl::ParseProgram(ScriptKind kind)
{
    lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    lexer_->NextToken();
    program_->SetKind(kind);

    auto statements = ParseStatementList(StatementParsingFlags::STMT_GLOBAL_LEXICAL);

    auto *block_stmt = AllocNode<ir::BlockStatement>(Allocator(), Binder()->GetScope(), std::move(statements));
    Binder()->GetScope()->BindNode(block_stmt);
    block_stmt->SetRange({start_loc, lexer_->GetToken().End()});

    program_->SetAst(block_stmt);
}

bool ParserImpl::InAmbientContext()
{
    return (context_.Status() & ParserStatus::IN_AMBIENT_CONTEXT) != 0;
}

ExpressionParseFlags ParserImpl::CarryExpressionParserFlag(ExpressionParseFlags origin, ExpressionParseFlags carry)
{
    return static_cast<ExpressionParseFlags>(origin & carry);
}

ExpressionParseFlags ParserImpl::CarryPatternFlags(ExpressionParseFlags flags)
{
    return CarryExpressionParserFlag(flags, ExpressionParseFlags::POTENTIALLY_IN_PATTERN |
                                                ExpressionParseFlags::OBJECT_PATTERN);
}

ir::ModifierFlags ParserImpl::GetAccessability(ir::ModifierFlags modifiers)
{
    if ((modifiers & ir::ModifierFlags::PUBLIC) != 0) {
        return ir::ModifierFlags::PUBLIC;
    }

    if ((modifiers & ir::ModifierFlags::PRIVATE) != 0) {
        return ir::ModifierFlags::PRIVATE;
    }

    if ((modifiers & ir::ModifierFlags::PROTECTED) != 0) {
        return ir::ModifierFlags::PROTECTED;
    }

    if ((modifiers & ir::ModifierFlags::INTERNAL) != 0) {
        return ir::ModifierFlags::INTERNAL;
    }

    return ir::ModifierFlags::NONE;
}

bool ParserImpl::IsModifierKind(const lexer::Token &token)
{
    switch (token.KeywordType()) {
        case lexer::TokenType::KEYW_STATIC:
        case lexer::TokenType::KEYW_ASYNC:
            return true;
        default:
            break;
    }

    return false;
}

ir::ModifierFlags ParserImpl::ParseModifiers()
{
    ir::ModifierFlags result_status = ir::ModifierFlags::NONE;
    ir::ModifierFlags prev_status = ir::ModifierFlags::ALL;

    while (IsModifierKind(lexer_->GetToken())) {
        char32_t next_cp = lexer_->Lookahead();
        if (next_cp == lexer::LEX_CHAR_LEFT_PAREN) {
            return result_status;
        }

        lexer::TokenFlags token_flags = lexer_->GetToken().Flags();
        if ((token_flags & lexer::TokenFlags::HAS_ESCAPE) != 0) {
            ThrowSyntaxError("Keyword must not contain escaped characters");
        }

        ir::ModifierFlags actual_status = ir::ModifierFlags::NONE;
        ir::ModifierFlags next_status = ir::ModifierFlags::NONE;

        switch (lexer_->GetToken().KeywordType()) {
            case lexer::TokenType::KEYW_STATIC: {
                actual_status = ir::ModifierFlags::STATIC;
                next_status = ir::ModifierFlags::ASYNC;
                break;
            }
            case lexer::TokenType::KEYW_ASYNC: {
                actual_status = ir::ModifierFlags::ASYNC;
                next_status = ir::ModifierFlags::NONE;
                break;
            }
            default: {
                break;
            }
        }

        if (lexer_->Lookahead() == lexer::LEX_CHAR_COLON || lexer_->Lookahead() == lexer::LEX_CHAR_COMMA ||
            lexer_->Lookahead() == lexer::LEX_CHAR_RIGHT_PAREN || lexer_->Lookahead() == lexer::LEX_CHAR_QUESTION ||
            lexer_->Lookahead() == lexer::LEX_CHAR_RIGHT_BRACE || lexer_->Lookahead() == lexer::LEX_CHAR_LESS_THAN) {
            break;
        }

        auto pos = lexer_->Save();
        lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);

        if ((prev_status & actual_status) == 0) {
            lexer_->Rewind(pos);
            ThrowSyntaxError("Unexpected modifier");
        }

        if ((result_status & actual_status) != 0) {
            lexer_->Rewind(pos);
            ThrowSyntaxError("Duplicated modifier is not allowed");
        }

        result_status |= actual_status;
        prev_status = next_status;
    }

    return result_status;
}

void ParserImpl::CheckAccessorPair(const ArenaVector<ir::AstNode *> &properties, const ir::Expression *prop_name,
                                   ir::MethodDefinitionKind method_kind, ir::ModifierFlags access)
{
    for (const auto &it : properties) {
        if (!it->IsMethodDefinition() || it->AsMethodDefinition()->Kind() != method_kind) {
            continue;
        }

        const ir::Expression *key = it->AsMethodDefinition()->Key();

        if (key->Type() != prop_name->Type()) {
            continue;
        }

        bool key_is_same = false;

        if (key->IsIdentifier()) {
            const util::StringView &str_name = prop_name->AsIdentifier()->Name();
            const util::StringView &compare_name = (key->AsIdentifier()->Name());

            key_is_same = str_name == compare_name;
        } else if (key->IsNumberLiteral()) {
            key_is_same =
                key->AsNumberLiteral()->Number().GetDouble() == prop_name->AsNumberLiteral()->Number().GetDouble();
        } else if (key->IsStringLiteral()) {
            key_is_same = *key->AsStringLiteral() == *prop_name->AsStringLiteral();
        }

        if (!key_is_same) {
            continue;
        }

        ir::ModifierFlags get_access = ir::ModifierFlags::NONE;
        ir::ModifierFlags set_access = ir::ModifierFlags::NONE;

        if (method_kind == ir::MethodDefinitionKind::GET) {
            set_access = access;
            get_access = GetAccessability(it->Modifiers());
        } else {
            get_access = access;
            set_access = GetAccessability(it->Modifiers());
        }

        if ((set_access == ir::ModifierFlags::NONE && get_access > ir::ModifierFlags::PUBLIC) ||
            (set_access != ir::ModifierFlags::NONE && get_access > set_access)) {
            ThrowSyntaxError("A get accessor must be at least as accessible as the setter", key->Start());
        }
    }
}

void ParserImpl::ParseClassAccessor(ClassElementDescriptor *desc, char32_t *next_cp)
{
    ConsumeClassPrivateIdentifier(desc, next_cp);

    if (lexer_->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        return;
    }

    auto keyword_type = lexer_->GetToken().KeywordType();
    if ((keyword_type != lexer::TokenType::KEYW_GET && keyword_type != lexer::TokenType::KEYW_SET) ||
        (*next_cp == lexer::LEX_CHAR_EQUALS || *next_cp == lexer::LEX_CHAR_SEMICOLON ||
         *next_cp == lexer::LEX_CHAR_LEFT_PAREN || *next_cp == lexer::LEX_CHAR_COLON ||
         *next_cp == lexer::LEX_CHAR_LESS_THAN)) {
        return;
    }

    ThrowIfPrivateIdent(desc, "Unexpected identifier");

    if ((lexer_->GetToken().Flags() & lexer::TokenFlags::HAS_ESCAPE) != 0) {
        ThrowSyntaxError("Keyword must not contain escaped characters");
    }

    desc->method_kind =
        keyword_type == lexer::TokenType::KEYW_GET ? ir::MethodDefinitionKind::GET : ir::MethodDefinitionKind::SET;
    desc->method_start = lexer_->GetToken().Start();

    lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
    ConsumeClassPrivateIdentifier(desc, next_cp);
}

void ParserImpl::ThrowIfPrivateIdent(ClassElementDescriptor *desc, const char *msg)
{
    if (desc->is_private_ident) {
        ThrowSyntaxError(msg);
    }
}

void ParserImpl::ThrowErrorIfStaticConstructor([[maybe_unused]] ir::ModifierFlags flags) {}

void ParserImpl::ValidateClassKey(ClassElementDescriptor *desc)
{
    if (((desc->modifiers & ir::ModifierFlags::ASYNC) != 0 || desc->is_generator) &&
        (desc->method_kind == ir::MethodDefinitionKind::GET || desc->method_kind == ir::MethodDefinitionKind::SET)) {
        ThrowSyntaxError("Invalid accessor");
    }

    const util::StringView &prop_name_str = lexer_->GetToken().Ident();

    if (prop_name_str.Is("constructor")) {
        if (lexer_->Lookahead() != lexer::LEX_CHAR_LEFT_PAREN) {
            ThrowSyntaxError("Classes may not have a field named 'constructor'");
        }

        ThrowIfPrivateIdent(desc, "Private identifier can not be constructor");

        if ((desc->modifiers & ir::ModifierFlags::STATIC) == 0) {
            if ((desc->modifiers & ir::ModifierFlags::ASYNC) != 0 ||
                desc->method_kind == ir::MethodDefinitionKind::GET ||
                desc->method_kind == ir::MethodDefinitionKind::SET || desc->is_generator) {
                ThrowSyntaxError("Constructor can not be special method");
            }

            desc->method_kind = ir::MethodDefinitionKind::CONSTRUCTOR;
            desc->method_start = lexer_->GetToken().Start();
            desc->new_status |= ParserStatus::CONSTRUCTOR_FUNCTION;

            if (desc->has_super_class) {
                desc->new_status |= ParserStatus::ALLOW_SUPER_CALL;
            }
        }

        ThrowErrorIfStaticConstructor(desc->modifiers);
    } else if (prop_name_str.Is("prototype") && (desc->modifiers & ir::ModifierFlags::STATIC) != 0) {
        ThrowSyntaxError("Classes may not have static property named prototype");
    }
}

std::tuple<bool, bool, bool> ParserImpl::ParseComputedClassFieldOrIndexSignature(ir::Expression **prop_name)
{
    lexer_->NextToken();  // eat left square bracket

    *prop_name = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA);

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
        ThrowSyntaxError("Unexpected token, expected ']'");
    }

    return {true, false, false};
}

ir::Expression *ParserImpl::ParseClassKey(ClassElementDescriptor *desc)
{
    ir::Expression *prop_name = nullptr;
    if (lexer_->GetToken().IsKeyword()) {
        lexer_->GetToken().SetTokenType(lexer::TokenType::LITERAL_IDENT);
    }

    switch (lexer_->GetToken().Type()) {
        case lexer::TokenType::LITERAL_IDENT: {
            ValidateClassKey(desc);

            prop_name = AllocNode<ir::Identifier>(lexer_->GetToken().Ident(), Allocator());
            prop_name->SetRange(lexer_->GetToken().Loc());
            prop_name->AsIdentifier()->SetPrivate(desc->is_private_ident);
            break;
        }
        case lexer::TokenType::LITERAL_STRING: {
            ThrowIfPrivateIdent(desc, "Private identifier name can not be string");

            if (lexer_->GetToken().Ident().Is("constructor")) {
                ThrowSyntaxError("Classes may not have a field named 'constructor'");
            }

            if (lexer_->GetToken().Ident().Is("prototype") && (desc->modifiers & ir::ModifierFlags::STATIC) != 0) {
                ThrowSyntaxError("Classes may not have a static property named 'prototype'");
            }

            prop_name = AllocNode<ir::StringLiteral>(lexer_->GetToken().String());
            prop_name->SetRange(lexer_->GetToken().Loc());
            break;
        }
        case lexer::TokenType::LITERAL_NUMBER: {
            ThrowIfPrivateIdent(desc, "Private identifier name can not be number");

            if ((lexer_->GetToken().Flags() & lexer::TokenFlags::NUMBER_BIGINT) != 0) {
                prop_name = AllocNode<ir::BigIntLiteral>(lexer_->GetToken().BigInt());
            } else {
                prop_name = AllocNode<ir::NumberLiteral>(lexer_->GetToken().GetNumber());
            }

            prop_name->SetRange(lexer_->GetToken().Loc());
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET: {
            ThrowIfPrivateIdent(desc, "Unexpected character in private identifier");
            auto [isComputed, invalidComputedProperty, isIndexSignature] =
                ParseComputedClassFieldOrIndexSignature(&prop_name);
            desc->is_computed = isComputed;
            desc->invalid_computed_property = invalidComputedProperty;
            desc->is_index_signature = isIndexSignature;
            break;
        }
        default: {
            ThrowSyntaxError("Unexpected token in class property");
        }
    }

    lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);

    return prop_name;
}

void ParserImpl::ValidateClassMethodStart(ClassElementDescriptor *desc, [[maybe_unused]] ir::TypeNode *type_annotation)
{
    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        return;
    }
    desc->class_method = true;

    if ((desc->modifiers & ir::ModifierFlags::ASYNC) != 0) {
        desc->new_status |= ParserStatus::ASYNC_FUNCTION;
    }

    if (desc->is_generator) {
        desc->new_status |= ParserStatus::GENERATOR_FUNCTION;
    }
}

void ParserImpl::ValidateClassSetter([[maybe_unused]] ClassElementDescriptor *desc,
                                     [[maybe_unused]] const ArenaVector<ir::AstNode *> &properties,
                                     [[maybe_unused]] ir::Expression *prop_name, ir::ScriptFunction *func)
{
    if (func->Params().size() != 1) {
        ThrowSyntaxError("Setter must have exactly one formal parameter");
    }
}

void ParserImpl::ValidateClassGetter([[maybe_unused]] ClassElementDescriptor *desc,
                                     [[maybe_unused]] const ArenaVector<ir::AstNode *> &properties,
                                     [[maybe_unused]] ir::Expression *prop_name, ir::ScriptFunction *func)
{
    if (!func->Params().empty()) {
        ThrowSyntaxError("Getter must not have formal parameters");
    }
}

ir::MethodDefinition *ParserImpl::ParseClassMethod(ClassElementDescriptor *desc,
                                                   const ArenaVector<ir::AstNode *> &properties,
                                                   ir::Expression *prop_name, lexer::SourcePosition *prop_end)
{
    if (desc->method_kind != ir::MethodDefinitionKind::SET &&
        (desc->new_status & ParserStatus::CONSTRUCTOR_FUNCTION) == 0) {
        desc->new_status |= ParserStatus::NEED_RETURN_TYPE;
    }

    ir::ScriptFunction *func = ParseFunction(desc->new_status);

    auto *func_expr = AllocNode<ir::FunctionExpression>(func);
    func_expr->SetRange(func->Range());

    if (desc->method_kind == ir::MethodDefinitionKind::SET) {
        ValidateClassSetter(desc, properties, prop_name, func);
    } else if (desc->method_kind == ir::MethodDefinitionKind::GET) {
        ValidateClassGetter(desc, properties, prop_name, func);
    }

    *prop_end = func->End();
    func->AddFlag(ir::ScriptFunctionFlags::METHOD);
    auto *method = AllocNode<ir::MethodDefinition>(desc->method_kind, prop_name, func_expr, desc->modifiers,
                                                   Allocator(), desc->is_computed);
    method->SetRange(func_expr->Range());

    return method;
}

ir::ClassElement *ParserImpl::ParseClassProperty(ClassElementDescriptor *desc,
                                                 const ArenaVector<ir::AstNode *> &properties,
                                                 ir::Expression *prop_name, ir::TypeNode *type_annotation)
{
    lexer::SourcePosition prop_end = prop_name->End();
    ir::ClassElement *property = nullptr;

    if (desc->class_method) {
        if ((desc->modifiers & ir::ModifierFlags::DECLARE) != 0) {
            ThrowSyntaxError("'declare modifier cannot appear on class elements of this kind.");
        }

        property = ParseClassMethod(desc, properties, prop_name, &prop_end);
        property->SetRange({desc->prop_start, prop_end});
        return property;
    }

    ir::Expression *value = nullptr;

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        lexer_->NextToken();  // eat equals

        if (InAmbientContext() || (desc->modifiers & ir::ModifierFlags::DECLARE) != 0) {
            ThrowSyntaxError("Initializers are not allowed in ambient contexts.");
        }

        value = ParseExpression();
        prop_end = value->End();
    }

    property = AllocNode<ir::ClassProperty>(prop_name, value, type_annotation, desc->modifiers, Allocator(),
                                            desc->is_computed);

    property->SetRange({desc->prop_start, prop_end});

    return property;
}

void ParserImpl::CheckClassGeneratorMethod(ClassElementDescriptor *desc, char32_t *next_cp)
{
    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_MULTIPLY) {
        return;
    }

    desc->is_generator = true;
    lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
    *next_cp = lexer_->Lookahead();
}

void ParserImpl::ValidatePrivateIdentifier()
{
    size_t iter_idx = lexer_->GetToken().Start().index;
    lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);

    if (lexer_->GetToken().Type() != lexer::TokenType::LITERAL_IDENT ||
        (lexer_->GetToken().Start().index - iter_idx > 1)) {
        ThrowSyntaxError("Unexpected token in private field");
    }
}

void ParserImpl::ConsumeClassPrivateIdentifier(ClassElementDescriptor *desc, char32_t *next_cp)
{
    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_HASH_MARK) {
        return;
    }

    desc->is_private_ident = true;
    ValidatePrivateIdentifier();
    *next_cp = lexer_->Lookahead();
}

void ParserImpl::AddPrivateElement(const ir::ClassElement *elem)
{
    if (!class_private_context_.AddElement(elem)) {
        ThrowSyntaxError("Private field has already been declared");
    }
}

ir::ClassElement *ParserImpl::ParseClassStaticBlock()
{
    const lexer::SourcePosition &start_pos = lexer_->GetToken().Start();

    lexer_->NextToken();  // eat 'static'

    SavedParserContext context(this, ParserStatus::ALLOW_SUPER);
    context_.Status() &= ~(ParserStatus::ASYNC_FUNCTION | ParserStatus::GENERATOR_FUNCTION);

    lexer_->NextToken();  // eat '{'

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());

    auto func_param_ctx = binder::LexicalScope<binder::FunctionParamScope>(Binder());
    auto *func_param_scope = func_param_ctx.GetScope();
    auto func_ctx = binder::LexicalScope<binder::FunctionScope>(Binder());
    auto *func_scope = func_ctx.GetScope();

    func_scope->BindParamScope(func_param_scope);
    func_param_scope->BindFunctionScope(func_scope);

    ArenaVector<ir::Statement *> statements = ParseStatementList();

    auto *body = AllocNode<ir::BlockStatement>(Allocator(), func_scope, std::move(statements));
    auto *func =
        AllocNode<ir::ScriptFunction>(func_scope, std::move(params), nullptr, body, nullptr,
                                      ir::ScriptFunctionFlags::EXPRESSION | ir::ScriptFunctionFlags::STATIC_BLOCK,
                                      ir::ModifierFlags::STATIC, false, context_.GetLanguge());
    func_scope->BindNode(func);
    func_param_scope->BindNode(func);

    auto *func_expr = AllocNode<ir::FunctionExpression>(func);
    auto *static_block = AllocNode<ir::ClassStaticBlock>(func_expr, Allocator());
    static_block->SetRange({start_pos, lexer_->GetToken().End()});

    lexer_->NextToken();  // eat '}'

    return static_block;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::AstNode *ParserImpl::ParseClassElement(const ArenaVector<ir::AstNode *> &properties,
                                           [[maybe_unused]] ir::ClassDefinitionModifiers modifiers,
                                           [[maybe_unused]] ir::ModifierFlags flags,
                                           [[maybe_unused]] ir::Identifier *ident_node)
{
    if (lexer_->GetToken().KeywordType() == lexer::TokenType::KEYW_STATIC &&
        lexer_->Lookahead() == lexer::LEX_CHAR_LEFT_BRACE) {
        return ParseClassStaticBlock();
    }

    ClassElementDescriptor desc(Allocator());

    desc.method_kind = ir::MethodDefinitionKind::METHOD;
    desc.new_status = ParserStatus::ALLOW_SUPER;
    desc.has_super_class = (modifiers & ir::ClassDefinitionModifiers::HAS_SUPER) != 0U;
    desc.prop_start = lexer_->GetToken().Start();
    desc.modifiers = ParseModifiers();

    char32_t next_cp = lexer_->Lookahead();
    CheckClassGeneratorMethod(&desc, &next_cp);
    ParseClassAccessor(&desc, &next_cp);

    if ((desc.modifiers & ir::ModifierFlags::STATIC) == 0) {
        context_.Status() |= ParserStatus::ALLOW_THIS_TYPE;
    }

    ir::Expression *prop_name = ParseClassKey(&desc);
    ValidateClassMethodStart(&desc, nullptr);
    ir::ClassElement *property = ParseClassProperty(&desc, properties, prop_name, nullptr);

    if (property != nullptr && lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SEMI_COLON &&
        lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE &&
        (lexer_->GetToken().Flags() & lexer::TokenFlags::NEW_LINE) == 0 &&
        !(property->IsMethodDefinition() &&
          property->AsMethodDefinition()->Value()->AsFunctionExpression()->Function()->Body() != nullptr)) {
        ThrowSyntaxError("';' expected.");
    }

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
        lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
    }

    context_.Status() &= ~ParserStatus::ALLOW_THIS_TYPE;

    if (desc.is_private_ident) {
        AddPrivateElement(property);
    }

    return property;
}

ir::MethodDefinition *ParserImpl::BuildImplicitConstructor(ir::ClassDefinitionModifiers modifiers,
                                                           const lexer::SourcePosition &start_loc)
{
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());

    auto *param_scope = Binder()->Allocator()->New<binder::FunctionParamScope>(Allocator(), Binder()->GetScope());
    auto *scope = Binder()->Allocator()->New<binder::FunctionScope>(Allocator(), param_scope);

    if ((modifiers & ir::ClassDefinitionModifiers::HAS_SUPER) != 0U) {
        util::StringView args_str = "args";
        params.push_back(AllocNode<ir::SpreadElement>(ir::AstNodeType::REST_ELEMENT, Allocator(),
                                                      AllocNode<ir::Identifier>(args_str, Allocator())));
        param_scope->AddParamDecl(Allocator(), params.back());

        ArenaVector<ir::Expression *> call_args(Allocator()->Adapter());
        auto *super_expr = AllocNode<ir::SuperExpression>();
        call_args.push_back(AllocNode<ir::SpreadElement>(ir::AstNodeType::SPREAD_ELEMENT, Allocator(),
                                                         AllocNode<ir::Identifier>(args_str, Allocator())));

        auto *call_expr = AllocNode<ir::CallExpression>(super_expr, std::move(call_args), nullptr, false);
        statements.push_back(AllocNode<ir::ExpressionStatement>(call_expr));
    }

    auto *body = AllocNode<ir::BlockStatement>(Allocator(), scope, std::move(statements));
    auto *func = AllocNode<ir::ScriptFunction>(scope, std::move(params), nullptr, body, nullptr,
                                               ir::ScriptFunctionFlags::CONSTRUCTOR |
                                                   ir::ScriptFunctionFlags::IMPLICIT_SUPER_CALL_NEEDED,
                                               false, context_.GetLanguge());

    scope->BindNode(func);
    param_scope->BindNode(func);
    scope->BindParamScope(param_scope);
    param_scope->BindFunctionScope(scope);

    auto *func_expr = AllocNode<ir::FunctionExpression>(func);
    auto *key = AllocNode<ir::Identifier>("constructor", Allocator());

    if ((modifiers & ir::ClassDefinitionModifiers::SET_CTOR_ID) != 0U) {
        func->SetIdent(key);
    }

    auto *ctor = AllocNode<ir::MethodDefinition>(ir::MethodDefinitionKind::CONSTRUCTOR, key, func_expr,
                                                 ir::ModifierFlags::NONE, Allocator(), false);

    ctor->SetRange({start_loc, lexer_->GetToken().End()});

    return ctor;
}

void ParserImpl::CreateImplicitConstructor(ir::MethodDefinition *&ctor,
                                           [[maybe_unused]] ArenaVector<ir::AstNode *> &properties,
                                           ir::ClassDefinitionModifiers modifiers,
                                           const lexer::SourcePosition &start_loc)
{
    if (ctor != nullptr) {
        return;
    }

    ctor = BuildImplicitConstructor(modifiers, start_loc);
}

ir::Identifier *ParserImpl::ParseClassIdent(ir::ClassDefinitionModifiers modifiers)
{
    if (lexer_->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
        return ExpectIdentifier();
    }

    auto id_required =
        static_cast<ir::ClassDefinitionModifiers>(modifiers & ir::ClassDefinitionModifiers::DECLARATION_ID_REQUIRED);

    if (id_required == ir::ClassDefinitionModifiers::DECLARATION_ID_REQUIRED) {
        ThrowSyntaxError("Unexpected token, expected an identifier.");
    }

    return nullptr;
}

bool ParserImpl::CheckClassElement(ir::AstNode *property, ir::MethodDefinition *&ctor,
                                   [[maybe_unused]] ArenaVector<ir::AstNode *> &properties)
{
    if (!property->IsMethodDefinition()) {
        return false;
    }

    ir::MethodDefinition *def = property->AsMethodDefinition();
    if (!def->IsConstructor()) {
        return false;
    }

    if (ctor != nullptr) {
        ThrowSyntaxError("Multiple constructor implementations are not allowed.", property->Start());
    }
    ctor = def;

    return true;
}

ir::Expression *ParserImpl::ParseSuperClassReference()
{
    if (lexer_->GetToken().Type() == lexer::TokenType::KEYW_EXTENDS) {
        lexer_->NextToken();
        return ParseLeftHandSideExpression();
    }

    return nullptr;
}

std::tuple<ir::Expression *, ir::TSTypeParameterInstantiation *> ParserImpl::ParseSuperClass()
{
    return {ParseSuperClassReference(), nullptr};
}

binder::Decl *ParserImpl::BindClassName(ir::Identifier *ident_node)
{
    if (ident_node == nullptr) {
        return nullptr;
    }

    return Binder()->AddDecl<binder::ConstDecl>(lexer_->GetToken().Start(), ident_node->Name());
}

// NOLINTNEXTLINE(google-default-arguments)
ir::ClassDefinition *ParserImpl::ParseClassDefinition(ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags flags)
{
    lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    lexer_->NextToken();

    auto class_ctx = binder::LexicalScope<binder::LocalScope>(Binder());
    ir::Identifier *ident_node = ParseClassIdent(modifiers);

    if (ident_node == nullptr && (modifiers & ir::ClassDefinitionModifiers::DECLARATION) != 0U) {
        ThrowSyntaxError("Unexpected token, expected an identifier.");
    }

    binder::Decl *ident_decl = BindClassName(ident_node);

    binder::PrivateBinding private_binding(Allocator(), class_id_++);
    Binder()->AddDecl<binder::ConstDecl>(start_loc, private_binding.View());

    // Parse SuperClass
    auto [superClass, superTypeParams] = ParseSuperClass();

    if (superClass != nullptr) {
        modifiers |= ir::ClassDefinitionModifiers::HAS_SUPER;
    }

    ExpectToken(lexer::TokenType::PUNCTUATOR_LEFT_BRACE, false);

    auto [ctor, properties, bodyRange] = ParseClassBody(modifiers, flags);

    ArenaVector<ir::TSClassImplements *> implements(Allocator()->Adapter());
    auto *class_scope = class_ctx.GetScope();
    auto *class_definition = AllocNode<ir::ClassDefinition>(
        class_scope, private_binding.View(), ident_node, nullptr, superTypeParams, std::move(implements), ctor,
        superClass, std::move(properties), modifiers, flags, GetContext().GetLanguge());

    class_definition->SetRange(bodyRange);
    class_scope->BindNode(class_definition);

    if (ident_decl != nullptr) {
        ident_decl->BindNode(class_definition);
    }

    return class_definition;
}

ParserImpl::ClassBody ParserImpl::ParseClassBody(ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags flags,
                                                 ir::Identifier *ident_node)
{
    auto saved_ctx = SavedStatusContext<ParserStatus::IN_CLASS_BODY>(&context_);

    lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);

    ir::MethodDefinition *ctor = nullptr;
    ArenaVector<ir::AstNode *> properties(Allocator()->Adapter());

    SavedClassPrivateContext class_context(this);

    while (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
            lexer_->NextToken();
            continue;
        }

        ir::AstNode *property = ParseClassElement(properties, modifiers, flags, ident_node);

        if (CheckClassElement(property, ctor, properties)) {
            continue;
        }

        properties.push_back(property);
    }

    lexer::SourcePosition end_loc = lexer_->GetToken().End();
    CreateImplicitConstructor(ctor, properties, modifiers, end_loc);
    lexer_->NextToken();

    return {ctor, std::move(properties), lexer::SourceRange {start_loc, end_loc}};
}

void ParserImpl::ValidateRestParameter(ir::Expression *param)
{
    if (!param->IsIdentifier()) {
        context_.Status() |= ParserStatus::HAS_COMPLEX_PARAM;
        if (!param->IsRestElement()) {
            return;
        }

        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
            ThrowSyntaxError("Rest parameter must be last formal parameter.");
        }
    }
}

ArenaVector<ir::Expression *> ParserImpl::ParseFunctionParams()
{
    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        lexer_->NextToken();  // eat '('
    }

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());

    while (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ir::Expression *parameter = ParseFunctionParameter();
        ValidateRestParameter(parameter);

        params.push_back(parameter);

        if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
            lexer_->NextToken();
        } else if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
            ThrowSyntaxError("Invalid token: comma or right parenthesis expected.");
        }
    }

    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS);
    lexer_->NextToken();
    return params;
}

ir::Expression *ParserImpl::CreateParameterThis([[maybe_unused]] util::StringView class_name)
{
    ThrowSyntaxError({"Unexpected token: ", class_name.Utf8()});
}

std::tuple<bool, ir::BlockStatement *, lexer::SourcePosition, bool> ParserImpl::ParseFunctionBody(
    [[maybe_unused]] const ArenaVector<ir::Expression *> &params, [[maybe_unused]] ParserStatus new_status,
    [[maybe_unused]] ParserStatus context_status, binder::FunctionScope *func_scope)
{
    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        ThrowSyntaxError("Unexpected token, expected '{'");
    }

    ir::BlockStatement *body = ParseBlockStatement(func_scope);

    return {true, body, body->End(), false};
}

FunctionSignature ParserImpl::ParseFunctionSignature(ParserStatus status, ir::Identifier *class_name)
{
    auto type_params_ctx = binder::LexicalScope<binder::LocalScope>(Binder());

    ir::TSTypeParameterDeclaration *type_param_decl = ParseFunctionTypeParameters();

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        ThrowSyntaxError("Unexpected token, expected '('");
    }

    FunctionParameterContext func_param_context(&context_, Binder());

    ir::Expression *parameter_this = nullptr;
    if (class_name != nullptr) {
        const auto saved_pos = Lexer()->Save();
        lexer_->NextToken();  // eat '('
        parameter_this = CreateParameterThis(class_name->Name());
        Lexer()->Rewind(saved_pos);
    }

    auto params = ParseFunctionParams();

    if (class_name != nullptr) {
        params.emplace(params.begin(), parameter_this);
    }

    ir::TypeNode *return_type_annotation = ParseFunctionReturnType(status);
    ir::ScriptFunctionFlags throw_marker = ParseFunctionThrowMarker(true);

    return {type_param_decl, std::move(params), return_type_annotation, func_param_context.LexicalScope().GetScope(),
            throw_marker};
}

ir::ScriptFunction *ParserImpl::ParseFunction(ParserStatus new_status)
{
    FunctionContext function_context(this, new_status | ParserStatus::FUNCTION | ParserStatus::ALLOW_NEW_TARGET);

    bool is_declare = InAmbientContext();

    lexer::SourcePosition start_loc = lexer_->GetToken().Start();

    auto [typeParamDecl, params, returnTypeAnnotation, funcParamScope, throw_marker] =
        ParseFunctionSignature(new_status);

    auto param_ctx = binder::LexicalScope<binder::FunctionParamScope>::Enter(Binder(), funcParamScope, false);
    auto function_ctx = binder::LexicalScope<binder::FunctionScope>(Binder());
    auto *function_scope = function_ctx.GetScope();
    function_scope->BindParamScope(funcParamScope);
    funcParamScope->BindFunctionScope(function_scope);

    auto [letDeclare, body, endLoc, isOverload] =
        ParseFunctionBody(params, new_status, context_.Status(), function_scope);

    if (isOverload) {
        function_context.AddFlag(ir::ScriptFunctionFlags::OVERLOAD);
    }

    function_context.AddFlag(throw_marker);

    auto *func_node =
        AllocNode<ir::ScriptFunction>(function_scope, std::move(params), typeParamDecl, body, returnTypeAnnotation,
                                      function_context.Flags(), is_declare && letDeclare, context_.GetLanguge());
    function_scope->BindNode(func_node);
    funcParamScope->BindNode(func_node);
    func_node->SetRange({start_loc, endLoc});

    return func_node;
}

ir::SpreadElement *ParserImpl::ParseSpreadElement(ExpressionParseFlags flags)
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD);
    lexer::SourcePosition start_location = lexer_->GetToken().Start();
    bool in_pattern = (flags & ExpressionParseFlags::MUST_BE_PATTERN) != 0;
    lexer_->NextToken();

    ir::Expression *argument {};
    if (in_pattern) {
        argument = ParsePatternElement(ExpressionParseFlags::IN_REST);
        if ((flags & ExpressionParseFlags::OBJECT_PATTERN) != 0 && !argument->IsIdentifier()) {
            ThrowSyntaxError("RestParameter must be followed by an identifier in declaration contexts");
        }
    } else {
        argument = ParseExpression(flags);
    }

    if (in_pattern && argument->IsAssignmentExpression()) {
        ThrowSyntaxError("RestParameter does not support an initializer");
    }

    auto node_type = in_pattern ? ir::AstNodeType::REST_ELEMENT : ir::AstNodeType::SPREAD_ELEMENT;
    auto *spread_element_node = AllocNode<ir::SpreadElement>(node_type, Allocator(), argument);
    spread_element_node->SetRange({start_location, argument->End()});
    return spread_element_node;
}

void ParserImpl::CheckRestrictedBinding()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::LITERAL_IDENT);
    CheckRestrictedBinding(lexer_->GetToken().KeywordType());
}

void ParserImpl::CheckRestrictedBinding(lexer::TokenType keyword_type)
{
    if (keyword_type == lexer::TokenType::KEYW_ARGUMENTS || keyword_type == lexer::TokenType::KEYW_EVAL) {
        ThrowSyntaxError(
            "'eval' or 'arguments' can't be defined or assigned to "
            "in strict mode code",
            lexer_->GetToken().Start());
    }
}

void ParserImpl::CheckRestrictedBinding(const util::StringView &ident, const lexer::SourcePosition &pos)
{
    if (ident.Is("eval") || ident.Is("arguments")) {
        ThrowSyntaxError(
            "'eval' or 'arguments' can't be defined or assigned to "
            "in strict mode code",
            pos);
    }
}

ir::Expression *ParserImpl::ParseFunctionParameter()
{
    ConvertThisKeywordToIdentIfNecessary();

    if (lexer_->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
        CheckRestrictedBinding();
    }

    ir::Expression *function_parameter = ParsePatternElement(ExpressionParseFlags::NO_OPTS, true);
    Binder()->AddParamDecl(function_parameter);

    return function_parameter;
}

void ParserImpl::ValidateLvalueAssignmentTarget(ir::Expression *node)
{
    switch (node->Type()) {
        case ir::AstNodeType::IDENTIFIER: {
            CheckRestrictedBinding(node->AsIdentifier()->Name(), node->Start());
            break;
        }
        case ir::AstNodeType::MEMBER_EXPRESSION: {
            break;
        }
        default: {
            ThrowSyntaxError("Invalid left-hand side in assignment expression");
        }
    }
}

void ParserImpl::ValidateAssignmentTarget(ExpressionParseFlags flags, ir::Expression *node)
{
    switch (node->Type()) {
        case ir::AstNodeType::ARRAY_PATTERN:
        case ir::AstNodeType::OBJECT_PATTERN: {
            break;
        }
        case ir::AstNodeType::ARRAY_EXPRESSION:
        case ir::AstNodeType::OBJECT_EXPRESSION: {
            if ((flags & ExpressionParseFlags::POTENTIALLY_IN_PATTERN) != 0) {
                return;
            }

            [[fallthrough]];
        }
        default: {
            return ValidateLvalueAssignmentTarget(node);
        }
    }
}

void ParserImpl::ValidateArrowParameterBindings(const ir::Expression *node)
{
    switch (node->Type()) {
        case ir::AstNodeType::IDENTIFIER: {
            CheckRestrictedBinding(node->AsIdentifier()->Name(), node->Start());
            break;
        }
        case ir::AstNodeType::OMITTED_EXPRESSION: {
            break;
        }
        case ir::AstNodeType::REST_ELEMENT: {
            ValidateArrowParameterBindings(node->AsRestElement()->Argument());
            break;
        }
        case ir::AstNodeType::PROPERTY: {
            break;
        }
        case ir::AstNodeType::OBJECT_PATTERN: {
            const auto &props = node->AsObjectPattern()->Properties();

            for (auto *it : props) {
                ValidateArrowParameterBindings(it);
            }
            break;
        }
        case ir::AstNodeType::ARRAY_PATTERN: {
            const auto &elements = node->AsArrayPattern()->Elements();

            for (auto *it : elements) {
                ValidateArrowParameterBindings(it);
            }
            break;
        }
        case ir::AstNodeType::ASSIGNMENT_PATTERN: {
            ValidateArrowParameterBindings(node->AsAssignmentPattern()->Left());
            break;
        }
        default: {
            ThrowSyntaxError("Unexpected ArrowParameter element");
        }
    }
}

void ParserImpl::ThrowParameterModifierError(ir::ModifierFlags status) const
{
    ThrowSyntaxError({"'",
                      (status & ir::ModifierFlags::STATIC) != 0  ? "static"
                      : (status & ir::ModifierFlags::ASYNC) != 0 ? "async"
                                                                 : "declare",
                      "' modifier cannot appear on a parameter."},
                     lexer_->GetToken().Start());
}

ir::Identifier *ParserImpl::ExpectIdentifier(bool is_reference)
{
    if (lexer_->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Identifier expected.");
    }

    auto *ident = AllocNode<ir::Identifier>(lexer_->GetToken().Ident(), Allocator());
    ident->SetReference(is_reference);
    ident->SetRange(lexer_->GetToken().Loc());

    lexer_->NextToken();

    return ident;
}

void ParserImpl::ExpectToken(lexer::TokenType token_type, bool consume_token)
{
    if (lexer_->GetToken().Type() == token_type) {
        if (consume_token) {
            lexer_->NextToken();
        }
        return;
    }
    ThrowExpectedToken(token_type);
}

void ParserImpl::ThrowUnexpectedToken(lexer::TokenType const token_type) const
{
    ThrowSyntaxError("Unexpected token: '"s + TokenToString(token_type) + "'."s);
}

void ParserImpl::ThrowExpectedToken(lexer::TokenType const token_type) const
{
    ThrowSyntaxError("Unexpected token, expected: '"s + TokenToString(token_type) + "'."s);
}

void ParserImpl::ThrowSyntaxError(std::string_view const error_message) const
{
    ThrowSyntaxError(error_message, lexer_->GetToken().Start());
}

void ParserImpl::ThrowSyntaxError(std::initializer_list<std::string_view> list) const
{
    ThrowSyntaxError(list, lexer_->GetToken().Start());
}

void ParserImpl::ThrowSyntaxError(std::initializer_list<std::string_view> list, const lexer::SourcePosition &pos) const
{
    std::stringstream ss;

    for (const auto &it : list) {
        ss << it;
    }

    std::string err = ss.str();

    ThrowSyntaxError(std::string_view {err}, pos);
}

void ParserImpl::ThrowSyntaxError(std::string_view error_message, const lexer::SourcePosition &pos) const
{
    lexer::LineIndex index(program_->SourceCode());
    lexer::SourceLocation loc = index.GetLocation(pos);

    throw Error {ErrorType::SYNTAX, program_->SourceFile().Utf8(), error_message, loc.line, loc.col};
}

ScriptExtension ParserImpl::Extension() const
{
    return program_->Extension();
}

bool ParserImpl::CheckModuleAsModifier()
{
    if (lexer_->GetToken().KeywordType() != lexer::TokenType::KEYW_AS) {
        return false;
    }

    if ((lexer_->GetToken().Flags() & lexer::TokenFlags::HAS_ESCAPE) != 0U) {
        ThrowSyntaxError("Escape sequences are not allowed in 'as' keyword");
    }

    return true;
}

void ExportDeclarationContext::BindExportDecl(ir::AstNode *export_decl)
{
    if (Binder() == nullptr) {
        return;
    }

    binder::ModuleScope::ExportDeclList decl_list(Allocator()->Adapter());

    if (export_decl->IsExportDefaultDeclaration()) {
        auto *decl = export_decl->AsExportDefaultDeclaration();
        auto *rhs = decl->Decl();

        if (Binder()->GetScope()->Bindings().size() == SavedBindings().size()) {
            if (rhs->IsFunctionDeclaration()) {
                Binder()->AddDecl<binder::FunctionDecl>(rhs->Start(), Binder()->Allocator(),
                                                        util::StringView(DEFAULT_EXPORT),
                                                        rhs->AsFunctionDeclaration()->Function());
            } else {
                Binder()->AddDecl<binder::ConstDecl>(rhs->Start(), util::StringView(DEFAULT_EXPORT));
            }
        }
    }

    for (const auto &[name, variable] : Binder()->GetScope()->Bindings()) {
        if (SavedBindings().find(name) != SavedBindings().end()) {
            continue;
        }

        util::StringView export_name(export_decl->IsExportDefaultDeclaration() ? "default" : name);

        variable->AddFlag(binder::VariableFlags::LOCAL_EXPORT);
        auto *decl = Binder()->AddDecl<binder::ExportDecl>(variable->Declaration()->Node()->Start(), export_name, name);
        decl_list.push_back(decl);
    }

    auto *module_scope = Binder()->GetScope()->AsModuleScope();
    module_scope->AddExportDecl(export_decl, std::move(decl_list));
}

void ImportDeclarationContext::BindImportDecl(ir::ImportDeclaration *import_decl)
{
    binder::ModuleScope::ImportDeclList decl_list(Allocator()->Adapter());

    for (const auto &[name, variable] : Binder()->GetScope()->Bindings()) {
        if (SavedBindings().find(name) != SavedBindings().end()) {
            continue;
        }

        decl_list.push_back(variable->Declaration()->AsImportDecl());
    }

    Binder()->GetScope()->AsModuleScope()->AddImportDecl(import_decl, std::move(decl_list));
}
}  // namespace panda::es2panda::parser
