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

#include "plugins/ecmascript/es2panda/parser/parserFlags.h"
#include "plugins/ecmascript/es2panda/util/helpers.h"
#include "plugins/ecmascript/es2panda/binder/tsBinding.h"
#include "plugins/ecmascript/es2panda/ir/astNode.h"
#include "plugins/ecmascript/es2panda/ir/base/catchClause.h"
#include "plugins/ecmascript/es2panda/ir/base/classDefinition.h"
#include "plugins/ecmascript/es2panda/ir/base/scriptFunction.h"
#include "plugins/ecmascript/es2panda/ir/expression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/arrayExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/assignmentExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/binaryExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/conditionalExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/stringLiteral.h"
#include "plugins/ecmascript/es2panda/ir/expressions/objectExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/sequenceExpression.h"
#include "plugins/ecmascript/es2panda/ir/module/exportAllDeclaration.h"
#include "plugins/ecmascript/es2panda/ir/module/exportDefaultDeclaration.h"
#include "plugins/ecmascript/es2panda/ir/module/exportNamedDeclaration.h"
#include "plugins/ecmascript/es2panda/ir/module/exportSpecifier.h"
#include "plugins/ecmascript/es2panda/ir/module/importDeclaration.h"
#include "plugins/ecmascript/es2panda/ir/module/importDefaultSpecifier.h"
#include "plugins/ecmascript/es2panda/ir/module/importNamespaceSpecifier.h"
#include "plugins/ecmascript/es2panda/ir/module/importSpecifier.h"
#include "plugins/ecmascript/es2panda/ir/statements/assertStatement.h"
#include "plugins/ecmascript/es2panda/ir/statements/blockStatement.h"
#include "plugins/ecmascript/es2panda/ir/statements/breakStatement.h"
#include "plugins/ecmascript/es2panda/ir/statements/classDeclaration.h"
#include "plugins/ecmascript/es2panda/ir/statements/continueStatement.h"
#include "plugins/ecmascript/es2panda/ir/statements/debuggerStatement.h"
#include "plugins/ecmascript/es2panda/ir/statements/doWhileStatement.h"
#include "plugins/ecmascript/es2panda/ir/statements/emptyStatement.h"
#include "plugins/ecmascript/es2panda/ir/statements/expressionStatement.h"
#include "plugins/ecmascript/es2panda/ir/statements/forInStatement.h"
#include "plugins/ecmascript/es2panda/ir/statements/forOfStatement.h"
#include "plugins/ecmascript/es2panda/ir/statements/forUpdateStatement.h"
#include "plugins/ecmascript/es2panda/ir/statements/functionDeclaration.h"
#include "plugins/ecmascript/es2panda/ir/statements/ifStatement.h"
#include "plugins/ecmascript/es2panda/ir/statements/labelledStatement.h"
#include "plugins/ecmascript/es2panda/ir/statements/returnStatement.h"
#include "plugins/ecmascript/es2panda/ir/statements/switchCaseStatement.h"
#include "plugins/ecmascript/es2panda/ir/statements/switchStatement.h"
#include "plugins/ecmascript/es2panda/ir/statements/throwStatement.h"
#include "plugins/ecmascript/es2panda/ir/statements/tryStatement.h"
#include "plugins/ecmascript/es2panda/ir/statements/variableDeclaration.h"
#include "plugins/ecmascript/es2panda/ir/statements/variableDeclarator.h"
#include "plugins/ecmascript/es2panda/ir/statements/whileStatement.h"
#include "plugins/ecmascript/es2panda/ir/ets/etsStructDeclaration.h"
#include "plugins/ecmascript/es2panda/lexer/keywordsBase.h"
#include "plugins/ecmascript/es2panda/lexer/lexer.h"
#include "plugins/ecmascript/es2panda/lexer/token/letters.h"
#include "plugins/ecmascript/es2panda/lexer/token/sourceLocation.h"
#include "plugins/ecmascript/es2panda/util/ustring.h"

#include <tuple>

#include "parserImpl.h"

namespace panda::es2panda::parser {

using namespace std::literals::string_literals;

// NOLINTNEXTLINE(google-default-arguments)
ir::Statement *ParserImpl::ParseStatement(StatementParsingFlags flags)
{
    switch (lexer_->GetToken().Type()) {
        case lexer::TokenType::PUNCTUATOR_LEFT_BRACE: {
            return ParseBlockStatement();
        }
        case lexer::TokenType::PUNCTUATOR_SEMI_COLON: {
            return ParseEmptyStatement();
        }
        case lexer::TokenType::KEYW_ASSERT: {
            return ParseAssertStatement();
        }
        case lexer::TokenType::KEYW_EXPORT: {
            return ParseExportDeclaration(flags);
        }
        case lexer::TokenType::KEYW_IMPORT: {
            return ParseImportDeclaration(flags);
        }
        case lexer::TokenType::KEYW_FUNCTION: {
            return ParseFunctionStatement(flags);
        }
        case lexer::TokenType::KEYW_CLASS: {
            return ParseClassStatement(flags, ir::ClassDefinitionModifiers::NONE);
        }
        case lexer::TokenType::KEYW_VAR: {
            return ParseVarStatement();
        }
        case lexer::TokenType::KEYW_LET: {
            return ParseLetStatement(flags);
        }
        case lexer::TokenType::KEYW_CONST: {
            return ParseConstStatement(flags);
        }
        case lexer::TokenType::KEYW_IF: {
            return ParseIfStatement();
        }
        case lexer::TokenType::KEYW_DO: {
            return ParseDoWhileStatement();
        }
        case lexer::TokenType::KEYW_FOR: {
            return ParseForStatement();
        }
        case lexer::TokenType::KEYW_TRY: {
            return ParseTryStatement();
        }
        case lexer::TokenType::KEYW_WHILE: {
            return ParseWhileStatement();
        }
        case lexer::TokenType::KEYW_BREAK: {
            return ParseBreakStatement();
        }
        case lexer::TokenType::KEYW_CONTINUE: {
            return ParseContinueStatement();
        }
        case lexer::TokenType::KEYW_THROW: {
            return ParseThrowStatement();
        }
        case lexer::TokenType::KEYW_RETURN: {
            return ParseReturnStatement();
        }
        case lexer::TokenType::KEYW_SWITCH: {
            return ParseSwitchStatement();
        }
        case lexer::TokenType::KEYW_DEBUGGER: {
            return ParseDebuggerStatement();
        }
        case lexer::TokenType::LITERAL_IDENT: {
            if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_STRUCT) {
                return ParseStructStatement(flags, ir::ClassDefinitionModifiers::NONE);
            }

            if (lexer_->Lookahead() == lexer::LEX_CHAR_COLON) {
                const auto pos = lexer_->Save();
                lexer_->NextToken();
                return ParseLabelledStatement(pos);
            }

            return ParsePotentialExpressionStatement(flags);
        }
        case lexer::TokenType::KEYW_WITH: {
            ThrowSyntaxError("'With' is deprecated and not supported any more.");
        }
        case lexer::TokenType::KEYW_ENUM: {
            return ParseEnumDeclaration();
        }
        case lexer::TokenType::KEYW_INTERFACE: {
            return ParseInterfaceDeclaration(false);
        }
        default: {
            return ParseExpressionStatement(flags);
        }
    }
}

ir::Statement *ParserImpl::ParseVarStatement()
{
    auto *variable_decl = ParseVariableDeclaration(VariableParsingFlags::VAR);
    ConsumeSemicolon(variable_decl);
    return variable_decl;
}

ir::Statement *ParserImpl::ParseLetStatement(StatementParsingFlags flags)
{
    if ((flags & StatementParsingFlags::ALLOW_LEXICAL) == 0) {
        ThrowSyntaxError("Lexical declaration is not allowed in single statement context");
    }

    auto *variable_decl = ParseVariableDeclaration(VariableParsingFlags::LET);
    ConsumeSemicolon(variable_decl);
    return variable_decl;
}

ir::Statement *ParserImpl::ParseConstStatement(StatementParsingFlags flags)
{
    if ((flags & StatementParsingFlags::ALLOW_LEXICAL) == 0) {
        ThrowSyntaxError("Lexical declaration is not allowed in single statement context");
    }

    lexer::SourcePosition const_var_star = lexer_->GetToken().Start();
    lexer_->NextToken();

    auto *variable_decl =
        ParseVariableDeclaration(VariableParsingFlags::CONST | VariableParsingFlags::NO_SKIP_VAR_KIND);
    variable_decl->SetStart(const_var_star);
    ConsumeSemicolon(variable_decl);

    return variable_decl;
}

ir::EmptyStatement *ParserImpl::ParseEmptyStatement()
{
    auto *empty = AllocNode<ir::EmptyStatement>();
    empty->SetRange(lexer_->GetToken().Loc());
    lexer_->NextToken();
    return empty;
}

ir::DebuggerStatement *ParserImpl::ParseDebuggerStatement()
{
    auto *debugger_node = AllocNode<ir::DebuggerStatement>();
    debugger_node->SetRange(lexer_->GetToken().Loc());
    lexer_->NextToken();
    ConsumeSemicolon(debugger_node);
    return debugger_node;
}

ir::Statement *ParserImpl::ParseFunctionStatement(StatementParsingFlags flags)
{
    CheckFunctionDeclaration(flags);

    if ((flags & StatementParsingFlags::STMT_LEXICAL_SCOPE_NEEDED) == 0) {
        return ParseFunctionDeclaration(false, ParserStatus::NO_OPTS);
    }

    auto local_ctx = binder::LexicalScope<binder::LocalScope>(Binder());
    ArenaVector<ir::Statement *> stmts(Allocator()->Adapter());
    auto *func_decl = ParseFunctionDeclaration(false, ParserStatus::NO_OPTS);
    stmts.push_back(func_decl);

    auto *local_block_stmt = AllocNode<ir::BlockStatement>(Allocator(), local_ctx.GetScope(), std::move(stmts));
    local_block_stmt->SetRange(func_decl->Range());
    local_ctx.GetScope()->BindNode(local_block_stmt);

    return func_decl;
}

ir::Statement *ParserImpl::ParsePotentialExpressionStatement(StatementParsingFlags flags)
{
    return ParseExpressionStatement(flags);
}

// NOLINTNEXTLINE(google-default-arguments)
ir::ETSStructDeclaration *ParserImpl::ParseStructStatement([[maybe_unused]] StatementParsingFlags flags,
                                                           [[maybe_unused]] ir::ClassDefinitionModifiers modifiers,
                                                           [[maybe_unused]] ir::ModifierFlags mod_flags)
{
    ThrowSyntaxError("Illegal start of expression", Lexer()->GetToken().Start());
}

// NOLINTNEXTLINE(google-default-arguments)
ir::ClassDeclaration *ParserImpl::ParseClassStatement(StatementParsingFlags flags,
                                                      ir::ClassDefinitionModifiers modifiers,
                                                      ir::ModifierFlags mod_flags)
{
    if ((flags & StatementParsingFlags::ALLOW_LEXICAL) == 0) {
        ThrowSyntaxError("Lexical declaration is not allowed in single statement context");
    }

    return ParseClassDeclaration(modifiers, mod_flags);
}

ir::ETSStructDeclaration *ParserImpl::ParseStructDeclaration(ir::ClassDefinitionModifiers modifiers,
                                                             ir::ModifierFlags flags)
{
    const lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    modifiers |= ir::ClassDefinitionModifiers::DECLARATION;

    if ((flags & ir::ModifierFlags::ABSTRACT) != 0U) {
        ThrowSyntaxError("struct declaration is not allowed to use 'abstract' modifiers.");
    }

    ir::ClassDefinition *class_definition = GetAndBindClassDefinition(modifiers, flags);

    if ((class_definition->Modifiers() & ir::ClassDefinitionModifiers::HAS_SUPER) != 0U) {
        ThrowSyntaxError("struct declaration cannot extends form other class");
    }

    lexer::SourcePosition end_loc = class_definition->End();
    auto *struct_decl = AllocNode<ir::ETSStructDeclaration>(class_definition, Allocator());
    struct_decl->SetRange({start_loc, end_loc});
    return struct_decl;
}

ir::ClassDeclaration *ParserImpl::ParseClassDeclaration(ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags flags)
{
    const lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    modifiers |= ir::ClassDefinitionModifiers::DECLARATION;
    ir::ClassDefinition *class_definition = GetAndBindClassDefinition(modifiers, flags);

    lexer::SourcePosition end_loc = class_definition->End();
    auto *class_decl = AllocNode<ir::ClassDeclaration>(class_definition, Allocator());
    class_decl->SetRange({start_loc, end_loc});
    return class_decl;
}

ir::ClassDefinition *ParserImpl::GetAndBindClassDefinition(ir::ClassDefinitionModifiers modifiers,
                                                           ir::ModifierFlags flags)
{
    ir::ClassDefinition *class_definition = ParseClassDefinition(modifiers, flags);

    auto *ident = class_definition->Ident();
    util::StringView class_name = ident->Name();

    if ((modifiers & ir::ClassDefinitionModifiers::CLASS_DECL) != 0U) {
        Binder()->AddDecl<binder::ClassDecl>(ident->Start(), class_name, class_definition);
    } else {
        Binder()->AddDecl<binder::LetDecl>(ident->Start(), class_name, class_definition);
    }

    return class_definition;
}

void ParserImpl::CheckFunctionDeclaration(StatementParsingFlags flags)
{
    if ((flags & StatementParsingFlags::LABELLED) != 0) {
        ThrowSyntaxError(
            "In strict mode code, functions can only be "
            "declared at top level, inside a block, "
            "or "
            "as the body of an if statement");
    }

    if ((flags & StatementParsingFlags::ALLOW_LEXICAL) == 0) {
        if ((flags & (StatementParsingFlags::IF_ELSE | StatementParsingFlags::LABELLED)) == 0) {
            ThrowSyntaxError("Lexical declaration is not allowed in single statement context");
        }

        if (lexer_->Lookahead() == lexer::LEX_CHAR_ASTERISK) {
            ThrowSyntaxError("Generators can only be declared at the top level or inside a block");
        }
    }
}

void ParserImpl::ConsumeSemicolon(ir::Statement *statement)
{
    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
        statement->SetEnd(lexer_->GetToken().End());
        lexer_->NextToken();
        return;
    }

    if (!lexer_->GetToken().NewLine()) {
        if (lexer_->GetToken().Type() != lexer::TokenType::EOS &&
            lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
            ThrowSyntaxError("Unexpected token");
        }
    }
}

ArenaVector<ir::Statement *> ParserImpl::ParseStatementList(StatementParsingFlags flags)
{
    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());
    ParseDirectivePrologue(&statements);

    auto end_type =
        (flags & StatementParsingFlags::GLOBAL) != 0 ? lexer::TokenType::EOS : lexer::TokenType::PUNCTUATOR_RIGHT_BRACE;

    while (lexer_->GetToken().Type() != end_type) {
        statements.push_back(ParseStatement(flags));
    }

    return statements;
}

bool ParserImpl::ParseDirective(ArenaVector<ir::Statement *> *statements)
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::LITERAL_STRING);

    const util::StringView &str = lexer_->GetToken().String();

    const auto status = static_cast<ParserStatus>(
        context_.Status() & (ParserStatus::CONSTRUCTOR_FUNCTION | ParserStatus::HAS_COMPLEX_PARAM));
    if (status == ParserStatus::HAS_COMPLEX_PARAM && str.Is("use strict")) {
        ThrowSyntaxError(
            "Illegal 'use strict' directive in function with "
            "non-simple parameter list");
    }

    ir::Expression *expr_node = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA);
    bool is_directive = expr_node->IsStringLiteral();

    auto *expr_statement = AllocNode<ir::ExpressionStatement>(expr_node);
    expr_statement->SetRange(expr_node->Range());

    ConsumeSemicolon(expr_statement);
    statements->push_back(expr_statement);

    return is_directive;
}

void ParserImpl::ParseDirectivePrologue(ArenaVector<ir::Statement *> *statements)
{
    while (true) {
        if (lexer_->GetToken().Type() != lexer::TokenType::LITERAL_STRING || !ParseDirective(statements)) {
            break;
        }
    }
}

ir::Statement *ParserImpl::ParseAssertStatement()
{
    return nullptr;
}

void ParserImpl::ValidateLabeledStatement([[maybe_unused]] lexer::TokenType type) {}

ir::BlockStatement *ParserImpl::ParseBlockStatement(binder::Scope *scope)
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE);

    lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    lexer_->NextToken();
    auto statements = ParseStatementList();

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        ThrowSyntaxError("Expected a '}'");
    }

    auto *block_node = AllocNode<ir::BlockStatement>(Allocator(), scope, std::move(statements));
    block_node->SetRange({start_loc, lexer_->GetToken().End()});
    scope->BindNode(block_node);

    lexer_->NextToken();
    return block_node;
}

ir::BlockStatement *ParserImpl::ParseBlockStatement()
{
    auto local_ctx = binder::LexicalScope<binder::LocalScope>(Binder());
    return ParseBlockStatement(local_ctx.GetScope());
}

void ParserImpl::ThrowPossibleOutOfBoundaryJumpError([[maybe_unused]] bool allow_break) {}

void ParserImpl::ThrowIllegalBreakError()
{
    ThrowSyntaxError("Illegal break statement");
}

ir::BreakStatement *ParserImpl::ParseBreakStatement()
{
    bool allow_break = (context_.Status() & (ParserStatus::IN_ITERATION | ParserStatus::IN_SWITCH)) != 0;

    ThrowPossibleOutOfBoundaryJumpError(allow_break);

    lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    lexer_->NextToken();

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON ||
        lexer_->GetToken().Type() == lexer::TokenType::EOS || lexer_->GetToken().NewLine() ||
        lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        if (!allow_break) {
            ThrowIllegalBreakError();
        }

        auto *break_statement = AllocNode<ir::BreakStatement>();
        break_statement->SetRange({start_loc, lexer_->GetToken().End()});

        if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
            lexer_->NextToken();
        }

        return break_statement;
    }

    if (lexer_->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Unexpected token.");
    }

    const auto &label = lexer_->GetToken().Ident();

    if (context_.FindLabel(label) == nullptr) {
        ThrowSyntaxError("Undefined label");
    }

    auto *ident_node = AllocNode<ir::Identifier>(label, Allocator());
    ident_node->SetRange(lexer_->GetToken().Loc());

    auto *break_statement = AllocNode<ir::BreakStatement>(ident_node);
    break_statement->SetRange({start_loc, lexer_->GetToken().End()});

    lexer_->NextToken();
    ConsumeSemicolon(break_statement);

    return break_statement;
}

void ParserImpl::ThrowIllegalContinueError()
{
    ThrowSyntaxError("Illegal continue statement");
}

ir::ContinueStatement *ParserImpl::ParseContinueStatement()
{
    ThrowPossibleOutOfBoundaryJumpError((context_.Status() & (ParserStatus::IN_ITERATION | ParserStatus::IN_SWITCH)) !=
                                        0U);

    if ((context_.Status() & ParserStatus::IN_ITERATION) == 0) {
        ThrowIllegalContinueError();
    }

    lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    lexer::SourcePosition end_loc = lexer_->GetToken().End();
    lexer_->NextToken();

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
        auto *continue_statement = AllocNode<ir::ContinueStatement>();
        continue_statement->SetRange({start_loc, lexer_->GetToken().End()});
        lexer_->NextToken();
        return continue_statement;
    }

    if (lexer_->GetToken().NewLine() || lexer_->GetToken().Type() == lexer::TokenType::EOS ||
        lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        auto *continue_statement = AllocNode<ir::ContinueStatement>();
        continue_statement->SetRange({start_loc, end_loc});
        return continue_statement;
    }

    if (lexer_->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Unexpected token.");
    }

    const auto &label = lexer_->GetToken().Ident();
    const ParserContext *label_ctx = context_.FindLabel(label);

    if (label_ctx == nullptr || (label_ctx->Status() & ParserStatus::IN_ITERATION) == 0) {
        ThrowSyntaxError("Undefined label");
    }

    auto *ident_node = AllocNode<ir::Identifier>(label, Allocator());
    ident_node->SetRange(lexer_->GetToken().Loc());

    auto *continue_statement = AllocNode<ir::ContinueStatement>(ident_node);
    continue_statement->SetRange({start_loc, lexer_->GetToken().End()});

    lexer_->NextToken();
    ConsumeSemicolon(continue_statement);

    return continue_statement;
}

ir::DoWhileStatement *ParserImpl::ParseDoWhileStatement()
{
    IterationContext<binder::LoopScope> iter_ctx(&context_, Binder());

    lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    lexer_->NextToken();
    ir::Statement *body = ParseStatement();

    if (lexer_->GetToken().Type() != lexer::TokenType::KEYW_WHILE) {
        ThrowSyntaxError("Missing 'while' keyword in a 'DoWhileStatement'");
    }

    lexer_->NextToken();
    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        ThrowSyntaxError("Missing left parenthesis in a 'DoWhileStatement'");
    }

    lexer_->NextToken();

    ir::Expression *test = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA);

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError("Missing right parenthesis in a 'DoWhileStatement'");
    }

    auto *do_while_statement = AllocNode<ir::DoWhileStatement>(iter_ctx.LexicalScope().GetScope(), body, test);
    do_while_statement->SetRange({start_loc, lexer_->GetToken().End()});
    iter_ctx.LexicalScope().GetScope()->BindNode(do_while_statement);

    lexer_->NextToken();

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
        do_while_statement->SetEnd(lexer_->GetToken().End());
        lexer_->NextToken();
    }

    return do_while_statement;
}

void ParserImpl::CreateFunctionDeclaration(ir::Identifier *ident_node, util::StringView &name, ir::ScriptFunction *func,
                                           [[maybe_unused]] const lexer::SourcePosition &start_loc)
{
    Binder()->AddDecl<binder::FunctionDecl>(ident_node->Start(), Allocator(), name, func);
}

ir::FunctionDeclaration *ParserImpl::ParseFunctionDeclaration(bool can_be_anonymous, ParserStatus new_status)
{
    lexer::SourcePosition start_loc = lexer_->GetToken().Start();

    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::KEYW_FUNCTION);
    ParserStatus saved_status = context_.Status();

    lexer_->NextToken();

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY) {
        new_status |= ParserStatus::GENERATOR_FUNCTION;
        lexer_->NextToken();
    }

    context_.Status() = saved_status;

    if (lexer_->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        if (can_be_anonymous) {
            ir::ScriptFunction *func = ParseFunction(new_status | ParserStatus::NEED_RETURN_TYPE);
            func->SetStart(start_loc);

            auto *func_decl = AllocNode<ir::FunctionDeclaration>(Allocator(), func);
            func_decl->SetRange(func->Range());
            return func_decl;
        }

        ThrowSyntaxError("Unexpected token, expected identifier after 'function' keyword");
    }

    util::StringView ident = lexer_->GetToken().Ident();

    CheckRestrictedBinding();
    auto *ident_node = ExpectIdentifier();

    new_status |= ParserStatus::FUNCTION_DECLARATION;
    ir::ScriptFunction *func = ParseFunction(new_status | ParserStatus::NEED_RETURN_TYPE);

    func->SetIdent(ident_node);
    func->SetStart(start_loc);
    auto *func_decl = AllocNode<ir::FunctionDeclaration>(Allocator(), func);
    func_decl->SetRange(func->Range());

    CreateFunctionDeclaration(ident_node, ident, func, start_loc);

    if (func->IsOverload() && lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
        lexer_->NextToken();
    }

    return func_decl;
}

ir::Statement *ParserImpl::ParseExpressionStatement(StatementParsingFlags flags)
{
    const auto start_pos = lexer_->Save();
    ParserStatus saved_status = context_.Status();

    if (lexer_->GetToken().IsAsyncModifier()) {
        lexer_->NextToken();

        if (lexer_->GetToken().Type() == lexer::TokenType::KEYW_FUNCTION && !lexer_->GetToken().NewLine()) {
            if ((flags & StatementParsingFlags::ALLOW_LEXICAL) == 0) {
                ThrowSyntaxError("Lexical declaration is not allowed in single statement context");
            }

            ir::FunctionDeclaration *function_decl = ParseFunctionDeclaration(false, ParserStatus::ASYNC_FUNCTION);
            function_decl->SetStart(start_pos.GetToken().Start());

            return function_decl;
        }

        lexer_->Rewind(start_pos);
    }

    ir::Expression *expr_node = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA);
    context_.Status() = saved_status;
    lexer::SourcePosition end_pos = expr_node->End();

    auto *expr_statement_node = AllocNode<ir::ExpressionStatement>(expr_node);
    expr_statement_node->SetRange({start_pos.GetToken().Start(), end_pos});
    ConsumeSemicolon(expr_statement_node);

    return expr_statement_node;
}

// NOLINTBEGIN(cert-err58-cpp)
static std::string const INVALID_LEFT_HAND_IN_FOR_OF =
    "Invalid left-hand side in 'for' statement: must have a single binding."s;
static std::string const UNEXPECTED_TOKEN = "Unexpected token"s;
static std::string const MISSING_LEFT_IN_FOR = "Missing left parenthesis in 'for' statement."s;
static std::string const MISSING_RIGHT_IN_FOR = "Missing right parenthesis in 'for' statement."s;
static std::string const INVALID_TYPE_ANNOTATION_IN_FOR =
    "Type annotation is not allowed when existing variable is used as loop iterator in 'for' statement."s;
// NOLINTEND(cert-err58-cpp)

std::tuple<ForStatementKind, ir::Expression *, ir::Expression *> ParserImpl::ParseForInOf(
    ir::AstNode *init_node, ExpressionParseFlags expr_flags, bool is_await)
{
    ForStatementKind for_kind = ForStatementKind::UPDATE;
    ir::Expression *update_node = nullptr;
    ir::Expression *right_node = nullptr;

    if (lexer_->GetToken().IsForInOf()) {
        const ir::VariableDeclarator *var_decl = init_node->AsVariableDeclaration()->Declarators().front();

        if (lexer_->GetToken().Type() == lexer::TokenType::KEYW_IN) {
            if (var_decl->Init() != nullptr) {
                ThrowSyntaxError("for-in loop variable declaration may not have an initializer");
            }
            for_kind = ForStatementKind::IN;
            expr_flags = ExpressionParseFlags::ACCEPT_COMMA;
            ValidateForInStatement();
        } else {
            if (var_decl->Init() != nullptr) {
                ThrowSyntaxError("for-of loop variable declaration may not have an initializer");
            }

            for_kind = ForStatementKind::OF;
        }

        lexer_->NextToken();
        right_node = ParseExpression(expr_flags);
    } else {
        if (is_await) {
            ThrowSyntaxError("Unexpected token");
        }

        if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
            ThrowSyntaxError("Invalid left-hand side in 'For[In/Of]Statement'");
        } else if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
            lexer_->NextToken();
        } else {
            right_node = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA | ExpressionParseFlags::IN_FOR);
            if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
                ThrowSyntaxError("Unexpected token, expected ';' in 'ForStatement'.");
            }
            lexer_->NextToken();
        }

        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
            update_node = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA | ExpressionParseFlags::IN_FOR);
        }
    }

    return {for_kind, right_node, update_node};
}

std::tuple<ForStatementKind, ir::AstNode *, ir::Expression *, ir::Expression *> ParserImpl::ParseForInOf(
    ir::Expression *left_node, ExpressionParseFlags expr_flags, bool is_await)
{
    ForStatementKind for_kind = ForStatementKind::UPDATE;
    ir::AstNode *init_node = nullptr;
    ir::Expression *update_node = nullptr;
    ir::Expression *right_node = nullptr;

    if (lexer_->GetToken().IsForInOf()) {
        if (lexer_->GetToken().Type() == lexer::TokenType::KEYW_IN) {
            for_kind = ForStatementKind::IN;
            expr_flags = ExpressionParseFlags::ACCEPT_COMMA;
            ValidateForInStatement();
        } else {
            for_kind = ForStatementKind::OF;
        }

        bool is_valid = true;
        switch (left_node->Type()) {
            case ir::AstNodeType::IDENTIFIER:
            case ir::AstNodeType::MEMBER_EXPRESSION: {
                break;
            }
            case ir::AstNodeType::ARRAY_EXPRESSION: {
                is_valid = left_node->AsArrayExpression()->ConvertibleToArrayPattern();
                break;
            }
            case ir::AstNodeType::OBJECT_EXPRESSION: {
                is_valid = left_node->AsObjectExpression()->ConvertibleToObjectPattern();
                break;
            }
            default: {
                is_valid = false;
            }
        }

        if (!is_valid) {
            ValidateLvalueAssignmentTarget(left_node);
        }

        init_node = left_node;
        lexer_->NextToken();
        right_node = ParseExpression(expr_flags);

        return {for_kind, init_node, right_node, update_node};
    }

    if (is_await) {
        ThrowSyntaxError("Unexpected token");
    }

    ir::Expression *expr = ParseAssignmentExpression(left_node);

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
        init_node = ParseSequenceExpression(expr);
    } else {
        init_node = expr;
    }

    if (init_node->IsConditionalExpression()) {
        ir::ConditionalExpression *cond_expr = init_node->AsConditionalExpression();
        if (cond_expr->Alternate()->IsBinaryExpression()) {
            const auto *binary_expr = cond_expr->Alternate()->AsBinaryExpression();
            if (binary_expr->OperatorType() == lexer::TokenType::KEYW_IN) {
                ThrowSyntaxError("Invalid left-hand side in for-in statement");
            }
        }
    }

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError("Invalid left-hand side in 'For[In/Of]Statement'");
    }

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
        ThrowSyntaxError("Unexpected token, expected ';' in 'ForStatement'.");
    }

    lexer_->NextToken();

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
        lexer_->NextToken();
    } else {
        right_node = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA | ExpressionParseFlags::IN_FOR);

        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
            ThrowSyntaxError("Unexpected token, expected ';' in 'ForStatement'.");
        }
        lexer_->NextToken();
    }

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        update_node = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA | ExpressionParseFlags::IN_FOR);
    }

    return {for_kind, init_node, right_node, update_node};
}

std::tuple<ir::Expression *, ir::Expression *> ParserImpl::ParseForUpdate(bool is_await)
{
    if (is_await) {
        ThrowSyntaxError("Unexpected token");
    }

    ir::Expression *update_node = nullptr;
    ir::Expression *right_node = nullptr;

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
        lexer_->NextToken();
    } else {
        right_node = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA | ExpressionParseFlags::IN_FOR);
        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
            ThrowSyntaxError("Unexpected token, expected ';' in 'ForStatement'.");
        }
        lexer_->NextToken();
    }

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        update_node = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA | ExpressionParseFlags::IN_FOR);
    }

    return {right_node, update_node};
}

ir::Statement *ParserImpl::ParseForStatement()
{
    lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    ForStatementKind for_kind = ForStatementKind::UPDATE;
    ir::AstNode *init_node = nullptr;
    ir::Expression *update_node = nullptr;
    ir::Expression *left_node = nullptr;
    ir::Expression *right_node = nullptr;
    bool can_be_for_in_of = true;
    bool is_await = false;
    lexer_->NextToken();
    VariableParsingFlags var_flags = VariableParsingFlags::IN_FOR;
    ExpressionParseFlags expr_flags = ExpressionParseFlags::NO_OPTS;

    if (lexer_->GetToken().Type() == lexer::TokenType::KEYW_AWAIT) {
        is_await = true;
        var_flags |= VariableParsingFlags::DISALLOW_INIT;
        lexer_->NextToken();
    }

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        ThrowSyntaxError(MISSING_LEFT_IN_FOR, lexer_->GetToken().Start());
    }
    lexer_->NextToken();

    lexer::TokenType token_type;
    auto const current_position = lexer_->Save();
    do {
        token_type = lexer_->GetToken().Type();
        if (lexer_->GetToken().KeywordType() == lexer::TokenType::KEYW_OF) {
            var_flags |= VariableParsingFlags::FOR_OF;
            break;
        }
        if (token_type == lexer::TokenType::KEYW_IN) {
            var_flags |= VariableParsingFlags::STOP_AT_IN;
            break;
        }
        lexer_->NextToken();
    } while (token_type != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS &&
             token_type != lexer::TokenType::PUNCTUATOR_LEFT_BRACE &&
             token_type != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS && token_type != lexer::TokenType::EOS);
    lexer_->Rewind(current_position);

    auto decl_ctx = binder::LexicalScope<binder::LoopDeclarationScope>(Binder());

    switch (lexer_->GetToken().Type()) {
        case lexer::TokenType::KEYW_VAR: {
            init_node = ParseVariableDeclaration(var_flags | VariableParsingFlags::VAR);
            break;
        }
        case lexer::TokenType::KEYW_LET: {
            init_node = ParseVariableDeclaration(var_flags | VariableParsingFlags::LET);
            break;
        }
        case lexer::TokenType::KEYW_CONST: {
            init_node = ParseVariableDeclaration(var_flags | VariableParsingFlags::CONST |
                                                 VariableParsingFlags::ACCEPT_CONST_NO_INIT);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_SEMI_COLON: {
            if (is_await) {
                ThrowSyntaxError(UNEXPECTED_TOKEN, lexer_->GetToken().Start());
            }

            can_be_for_in_of = false;
            lexer_->NextToken();
            break;
        }
        default: {
            left_node = ParseUnaryOrPrefixUpdateExpression(ExpressionParseFlags::POTENTIALLY_IN_PATTERN);
            break;
        }
    }

    IterationContext<binder::LoopScope> iter_ctx(&context_, Binder());
    iter_ctx.LexicalScope().GetScope()->BindDecls(decl_ctx.GetScope());

    if (init_node != nullptr) {
        if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
            lexer_->NextToken();
            can_be_for_in_of = false;
        } else if (init_node->AsVariableDeclaration()->Declarators().size() > 1 && lexer_->GetToken().IsForInOf()) {
            ThrowSyntaxError(INVALID_LEFT_HAND_IN_FOR_OF,
                             init_node->AsVariableDeclaration()->Declarators()[1]->Start());
        }
    }

    // VariableDeclaration->DeclarationSize > 1 or seen semi_colon
    if (!can_be_for_in_of) {
        std::tie(right_node, update_node) = ParseForUpdate(is_await);
    } else if (left_node != nullptr) {
        // initNode was parsed as LHS
        if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
            ThrowSyntaxError(INVALID_TYPE_ANNOTATION_IN_FOR, lexer_->GetToken().Start());
        }
        std::tie(for_kind, init_node, right_node, update_node) = ParseForInOf(left_node, expr_flags, is_await);
    } else if (init_node != nullptr) {
        // initNode was parsed as VariableDeclaration and declaration size = 1
        std::tie(for_kind, right_node, update_node) = ParseForInOf(init_node, expr_flags, is_await);
    }

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK) {
        lexer_->NextToken();
    }
    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError(MISSING_RIGHT_IN_FOR, lexer_->GetToken().Start());
    }
    lexer_->NextToken();

    ir::Statement *body_node = ParseStatement();
    lexer::SourcePosition end_loc = body_node->End();

    ir::Statement *for_statement = nullptr;
    auto *loop_scope = iter_ctx.LexicalScope().GetScope();

    if (for_kind == ForStatementKind::UPDATE) {
        for_statement = AllocNode<ir::ForUpdateStatement>(loop_scope, init_node, right_node, update_node, body_node);
    } else if (for_kind == ForStatementKind::IN) {
        for_statement = AllocNode<ir::ForInStatement>(loop_scope, init_node, right_node, body_node);
    } else {
        for_statement = AllocNode<ir::ForOfStatement>(loop_scope, init_node, right_node, body_node, is_await);
    }

    for_statement->SetRange({start_loc, end_loc});
    loop_scope->BindNode(for_statement);
    loop_scope->DeclScope()->BindNode(for_statement);

    return for_statement;
}

void ParserImpl::ThrowIfBodyEmptyError([[maybe_unused]] ir::Statement *consequent) {}

ir::IfStatement *ParserImpl::ParseIfStatement()
{
    lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    lexer::SourcePosition end_loc = lexer_->GetToken().End();
    lexer_->NextToken();

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        ThrowSyntaxError("Missing left parenthesis in an 'IfStatement'");
    }

    lexer_->NextToken();
    ir::Expression *test = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA);

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError("Missing right parenthesis in an 'IfStatement'");
    }

    lexer_->NextToken();
    ir::Statement *consequent = ParseStatement(StatementParsingFlags::IF_ELSE | StatementParsingFlags::ALLOW_LEXICAL);

    ThrowIfBodyEmptyError(consequent);

    end_loc = consequent->End();
    ir::Statement *alternate = nullptr;

    if (lexer_->GetToken().Type() == lexer::TokenType::KEYW_ELSE) {
        lexer_->NextToken();  // eat ELSE keyword
        alternate = ParseStatement(StatementParsingFlags::IF_ELSE | StatementParsingFlags::ALLOW_LEXICAL);
        end_loc = alternate->End();
    }

    auto *if_statement = AllocNode<ir::IfStatement>(test, consequent, alternate);
    if_statement->SetRange({start_loc, end_loc});
    return if_statement;
}

ir::LabelledStatement *ParserImpl::ParseLabelledStatement(const lexer::LexerPosition &pos)
{
    const util::StringView &actual_label = pos.GetToken().Ident();

    if (lexer_->GetToken().KeywordType() == lexer::TokenType::KEYW_AWAIT && context_.IsModule()) {
        ThrowSyntaxError("'await' is a reserved identifier in module code", pos.GetToken().Start());
    }

    if (context_.FindLabel(actual_label) != nullptr) {
        ThrowSyntaxError("Label already declared", pos.GetToken().Start());
    }

    SavedParserContext new_ctx(this, ParserStatus::IN_LABELED, actual_label);

    auto *ident_node = AllocNode<ir::Identifier>(actual_label, Allocator());
    ident_node->SetRange(pos.GetToken().Loc());

    lexer_->NextToken();

    ValidateLabeledStatement(Lexer()->GetToken().Type());

    ir::Statement *body = ParseStatement(StatementParsingFlags::LABELLED);

    auto *labeled_statement = AllocNode<ir::LabelledStatement>(ident_node, body);
    labeled_statement->SetRange({pos.GetToken().Start(), body->End()});

    return labeled_statement;
}

ir::ReturnStatement *ParserImpl::ParseReturnStatement()
{
    if ((context_.Status() & ParserStatus::FUNCTION) == 0) {
        ThrowSyntaxError("return keyword should be used in function body");
    }

    lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    lexer::SourcePosition end_loc = lexer_->GetToken().End();
    lexer_->NextToken();

    bool has_argument = (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SEMI_COLON &&
                         lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE &&
                         lexer_->GetToken().Type() != lexer::TokenType::EOS && !lexer_->GetToken().NewLine());

    ir::ReturnStatement *return_statement = nullptr;

    if (has_argument) {
        ir::Expression *expression = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA);
        end_loc = expression->End();
        return_statement = AllocNode<ir::ReturnStatement>(expression);
    } else {
        return_statement = AllocNode<ir::ReturnStatement>();
    }

    return_statement->SetRange({start_loc, end_loc});
    ConsumeSemicolon(return_statement);

    return return_statement;
}

void ParserImpl::ThrowMultipleDefaultError()
{
    ThrowSyntaxError("Multiple default clauses.");
}

ir::SwitchCaseStatement *ParserImpl::ParseSwitchCaseStatement(bool *seen_default)
{
    lexer::SourcePosition case_start_loc = lexer_->GetToken().Start();
    ir::Expression *test_expr = nullptr;

    switch (lexer_->GetToken().KeywordType()) {
        case lexer::TokenType::KEYW_CASE: {
            lexer_->NextToken();
            test_expr = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA);
            break;
        }
        case lexer::TokenType::KEYW_DEFAULT: {
            if (*seen_default) {
                ThrowMultipleDefaultError();
            }
            *seen_default = true;
            lexer_->NextToken();
            break;
        }
        default: {
            ThrowSyntaxError("Unexpected token, expected 'case' or 'default'.");
        }
    }

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
        ThrowSyntaxError("Unexpected token, expected ':'");
    }

    ArenaVector<ir::Statement *> consequents(Allocator()->Adapter());
    lexer::SourcePosition case_end_loc = lexer_->GetToken().End();

    lexer_->NextToken();

    while (lexer_->GetToken().Type() != lexer::TokenType::KEYW_CASE &&
           lexer_->GetToken().KeywordType() != lexer::TokenType::KEYW_DEFAULT &&
           lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        ir::Statement *consequent = ParseStatement(StatementParsingFlags::ALLOW_LEXICAL);
        case_end_loc = consequent->End();
        consequents.push_back(consequent);
    }

    auto *case_node = AllocNode<ir::SwitchCaseStatement>(test_expr, std::move(consequents));
    case_node->SetRange({case_start_loc, case_end_loc});
    return case_node;
}

ir::SwitchStatement *ParserImpl::ParseSwitchStatement()
{
    lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    lexer_->NextToken();
    if (!(lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS)) {
        ThrowSyntaxError("Unexpected token, expected '('");
    }

    lexer_->NextToken();
    ir::Expression *discriminant = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA);

    if (!(lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS)) {
        ThrowSyntaxError("Unexpected token, expected ')'");
    }

    lexer_->NextToken();
    SwitchContext switch_context(&context_);

    if (!(lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE)) {
        ThrowSyntaxError("Unexpected token, expected '{'");
    }

    lexer_->NextToken();
    bool seen_default = false;
    auto local_ctx = binder::LexicalScope<binder::LocalScope>(Binder());
    ArenaVector<ir::SwitchCaseStatement *> cases(Allocator()->Adapter());

    while (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        cases.push_back(ParseSwitchCaseStatement(&seen_default));
    }

    auto *switch_statement = AllocNode<ir::SwitchStatement>(local_ctx.GetScope(), discriminant, std::move(cases));
    switch_statement->SetRange({start_loc, lexer_->GetToken().End()});
    local_ctx.GetScope()->BindNode(switch_statement);

    lexer_->NextToken();

    return switch_statement;
}

void ParserImpl::ThrowIllegalNewLineErrorAfterThrow()
{
    ThrowSyntaxError("Illegal newline after throw");
}

ir::ThrowStatement *ParserImpl::ParseThrowStatement()
{
    lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    lexer_->NextToken();

    if (lexer_->GetToken().NewLine()) {
        ThrowIllegalNewLineErrorAfterThrow();
    }

    ir::Expression *expression = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA);
    lexer::SourcePosition end_loc = expression->End();

    auto *throw_statement = AllocNode<ir::ThrowStatement>(expression);
    throw_statement->SetRange({start_loc, end_loc});
    ConsumeSemicolon(throw_statement);

    return throw_statement;
}

void ParserImpl::ParseCatchParamTypeAnnotation([[maybe_unused]] ir::AnnotatedExpression *param) {}

ir::Expression *ParserImpl::ParseCatchParam()
{
    ir::AnnotatedExpression *param = nullptr;

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        return param;
    }

    lexer_->NextToken();  // eat left paren

    if (lexer_->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
        CheckRestrictedBinding();
        param = ExpectIdentifier();
    } else if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
        param = ParseArrayExpression(ExpressionParseFlags::MUST_BE_PATTERN);
    } else if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        param = ParseObjectExpression(ExpressionParseFlags::MUST_BE_PATTERN);
    } else {
        ThrowSyntaxError("Unexpected token in catch parameter");
    }

    auto param_decl = Binder()->AddParamDecl(param);

    if (param->IsIdentifier()) {
        param->AsIdentifier()->SetVariable(std::get<1>(param_decl));
    }

    ParseCatchParamTypeAnnotation(param);

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError("Unexpected token, expected ')'");
    }

    lexer_->NextToken();

    return param;
}

ir::CatchClause *ParserImpl::ParseCatchClause()
{
    lexer::SourcePosition catch_start_loc = lexer_->GetToken().Start();
    lexer_->NextToken();  // eat 'catch' keyword

    auto catch_param_ctx = binder::LexicalScope<binder::CatchParamScope>(Binder());
    auto *catch_param_scope = catch_param_ctx.GetScope();

    ir::Expression *param = ParseCatchParam();
    if (param != nullptr && param->IsIdentifier()) {
        param->AsIdentifier()->Variable()->SetScope(catch_param_scope);
    }
    catch_param_scope->BindNode(param);

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        ThrowSyntaxError("Unexpected token, expected '{'");
    }

    auto catch_ctx = binder::LexicalScope<binder::CatchScope>(Binder());
    auto *catch_scope = catch_ctx.GetScope();
    catch_scope->AssignParamScope(catch_param_scope);

    ir::BlockStatement *catch_block = ParseBlockStatement(catch_scope);
    lexer::SourcePosition end_loc = catch_block->End();

    auto *catch_clause = AllocNode<ir::CatchClause>(catch_scope, param, catch_block);
    catch_clause->SetRange({catch_start_loc, end_loc});
    catch_scope->BindNode(catch_clause);

    return catch_clause;
}

ir::Statement *ParserImpl::ParseTryStatement()
{
    lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    lexer::SourcePosition end_loc = lexer_->GetToken().End();

    lexer_->NextToken();

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        ThrowSyntaxError("Unexpected token, expected '{'");
    }

    ir::BlockStatement *body = ParseBlockStatement();

    if (lexer_->GetToken().Type() != lexer::TokenType::KEYW_CATCH &&
        lexer_->GetToken().Type() != lexer::TokenType::KEYW_FINALLY) {
        ThrowSyntaxError("Missing catch or finally clause");
    }

    ir::CatchClause *catch_clause = nullptr;
    ir::BlockStatement *finally_clause = nullptr;
    ArenaVector<ir::CatchClause *> catch_clauses(Allocator()->Adapter());

    if (lexer_->GetToken().Type() == lexer::TokenType::KEYW_CATCH) {
        catch_clause = ParseCatchClause();
        end_loc = catch_clause->End();
        catch_clauses.push_back(catch_clause);
    }

    if (lexer_->GetToken().Type() == lexer::TokenType::KEYW_FINALLY) {
        lexer_->NextToken();  // eat 'finally' keyword

        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
            ThrowSyntaxError("Unexpected token, expected '{'");
        }

        finally_clause = ParseBlockStatement();
        end_loc = finally_clause->End();
    }

    ArenaVector<std::pair<compiler::LabelPair, const ir::Statement *>> finalizer_insertions(Allocator()->Adapter());

    auto *try_statement =
        AllocNode<ir::TryStatement>(body, std::move(catch_clauses), finally_clause, finalizer_insertions);
    try_statement->SetRange({start_loc, end_loc});
    return try_statement;
}

void ParserImpl::ValidateDeclaratorId()
{
    if (InAmbientContext()) {
        return;
    }

    CheckRestrictedBinding();
}

ir::VariableDeclarator *ParserImpl::ParseVariableDeclaratorInitializer(ir::Expression *init, VariableParsingFlags flags,
                                                                       const lexer::SourcePosition &start_loc)
{
    if ((flags & VariableParsingFlags::DISALLOW_INIT) != 0) {
        ThrowSyntaxError("for-await-of loop variable declaration may not have an initializer");
    }

    lexer_->NextToken();

    if (InAmbientContext() && (flags & VariableParsingFlags::CONST) == 0) {
        ThrowSyntaxError("Initializers are not allowed in ambient contexts.");
    }

    auto expr_flags = ((flags & VariableParsingFlags::STOP_AT_IN) != 0 ? ExpressionParseFlags::STOP_AT_IN
                                                                       : ExpressionParseFlags::NO_OPTS);

    ir::Expression *initializer = ParseExpression(expr_flags);
    lexer::SourcePosition end_loc = initializer->End();

    auto *declarator = AllocNode<ir::VariableDeclarator>(init, initializer);
    declarator->SetRange({start_loc, end_loc});

    return declarator;
}

void ParserImpl::AddVariableDeclarationBindings(ir::Expression *init, lexer::SourcePosition start_loc,
                                                VariableParsingFlags flags)
{
    std::vector<ir::Identifier *> bindings = util::Helpers::CollectBindingNames(init);

    for (const auto *binding : bindings) {
        binder::Decl *decl = nullptr;

        if ((flags & VariableParsingFlags::VAR) != 0U) {
            decl = Binder()->AddDecl<binder::VarDecl>(start_loc, binding->Name());
        } else if ((flags & VariableParsingFlags::LET) != 0U) {
            decl = Binder()->AddDecl<binder::LetDecl>(start_loc, binding->Name());
        } else {
            decl = Binder()->AddDecl<binder::ConstDecl>(start_loc, binding->Name());
        }

        decl->BindNode(init);
    }
}

ir::AnnotatedExpression *ParserImpl::ParseVariableDeclaratorKey([[maybe_unused]] VariableParsingFlags flags)
{
    switch (lexer_->GetToken().Type()) {
        case lexer::TokenType::LITERAL_IDENT: {
            ValidateDeclaratorId();
            return ExpectIdentifier(true);
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET: {
            return ParseArrayExpression(ExpressionParseFlags::MUST_BE_PATTERN);
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_BRACE: {
            return ParseObjectExpression(ExpressionParseFlags::MUST_BE_PATTERN);
        }
        default: {
            break;
        }
    }

    ThrowSyntaxError("Unexpected token in variable declaration");
    return nullptr;
}

ir::VariableDeclarator *ParserImpl::ParseVariableDeclarator(ir::Expression *init, lexer::SourcePosition start_loc,
                                                            VariableParsingFlags flags)
{
    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        return ParseVariableDeclaratorInitializer(init, flags, start_loc);
    }

    if ((flags & VariableParsingFlags::CONST) != 0U && (flags & VariableParsingFlags::ACCEPT_CONST_NO_INIT) == 0U) {
        ThrowSyntaxError("Missing initializer in const declaration");
    }

    if ((flags & VariableParsingFlags::IN_FOR) == 0U && (init->IsArrayPattern() || init->IsObjectPattern())) {
        ThrowSyntaxError("Missing initializer in destructuring declaration");
    }

    lexer::SourcePosition end_loc = init->End();
    auto declarator = AllocNode<ir::VariableDeclarator>(init);
    declarator->SetRange({start_loc, end_loc});

    return declarator;
}

ir::VariableDeclarator *ParserImpl::ParseVariableDeclarator(VariableParsingFlags flags)
{
    lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    ir::Expression *init = ParseVariableDeclaratorKey(flags);
    ir::VariableDeclarator *declarator = ParseVariableDeclarator(init, start_loc, flags);
    AddVariableDeclarationBindings(init, start_loc, flags);

    return declarator;
}

ir::Statement *ParserImpl::ParsePotentialConstEnum([[maybe_unused]] VariableParsingFlags flags)
{
    ThrowSyntaxError("Variable declaration expected.");
}

void ParserImpl::ThrowIfVarDeclaration([[maybe_unused]] VariableParsingFlags flags) {}

ir::Statement *ParserImpl::ParseVariableDeclaration(VariableParsingFlags flags)
{
    lexer::SourcePosition start_loc = lexer_->GetToken().Start();

    if ((flags & VariableParsingFlags::NO_SKIP_VAR_KIND) == 0) {
        lexer_->NextToken();
    }

    ThrowIfVarDeclaration(flags);

    if (lexer_->GetToken().Type() == lexer::TokenType::KEYW_ENUM) {
        return ParsePotentialConstEnum(flags);
    }

    ArenaVector<ir::VariableDeclarator *> declarators(Allocator()->Adapter());

    while (true) {
        ir::VariableDeclarator *declarator = ParseVariableDeclarator(flags);

        declarators.push_back(declarator);

        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COMMA) {
            break;
        }
        lexer_->NextToken();
    }

    auto var_kind = ir::VariableDeclaration::VariableDeclarationKind::VAR;

    if ((flags & VariableParsingFlags::LET) != 0) {
        var_kind = ir::VariableDeclaration::VariableDeclarationKind::LET;
    } else if ((flags & VariableParsingFlags::CONST) != 0) {
        var_kind = ir::VariableDeclaration::VariableDeclarationKind::CONST;
    }

    lexer::SourcePosition end_loc = declarators.back()->End();
    auto *declaration =
        AllocNode<ir::VariableDeclaration>(var_kind, Allocator(), std::move(declarators), InAmbientContext());
    declaration->SetRange({start_loc, end_loc});

    return declaration;
}

ir::WhileStatement *ParserImpl::ParseWhileStatement()
{
    lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    lexer_->NextToken();
    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        ThrowSyntaxError("Unexpected token, expected '('");
    }

    lexer_->NextToken();
    ir::Expression *test = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA);

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError("Unexpected token, expected ')'");
    }

    lexer_->NextToken();
    IterationContext<binder::LoopScope> iter_ctx(&context_, Binder());
    ir::Statement *body = ParseStatement();

    lexer::SourcePosition end_loc = body->End();
    auto *while_statement = AllocNode<ir::WhileStatement>(iter_ctx.LexicalScope().GetScope(), test, body);
    while_statement->SetRange({start_loc, end_loc});
    iter_ctx.LexicalScope().GetScope()->BindNode(while_statement);

    return while_statement;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::ExportDefaultDeclaration *ParserImpl::ParseExportDefaultDeclaration(const lexer::SourcePosition &start_loc,
                                                                        bool is_export_equals)
{
    lexer_->NextToken();  // eat `default` keyword or `=`

    ir::AstNode *decl_node = nullptr;
    bool eat_semicolon = false;

    ExportDeclarationContext export_decl_ctx(Binder());

    switch (lexer_->GetToken().Type()) {
        case lexer::TokenType::KEYW_FUNCTION: {
            decl_node = ParseFunctionDeclaration(true);
            break;
        }
        case lexer::TokenType::KEYW_CLASS: {
            decl_node = ParseClassDeclaration(ir::ClassDefinitionModifiers::NONE);
            break;
        }
        case lexer::TokenType::LITERAL_IDENT: {
            switch (lexer_->GetToken().KeywordType()) {
                case lexer::TokenType::KEYW_STRUCT: {
                    decl_node = ParseStructDeclaration(ir::ClassDefinitionModifiers::NONE);
                    break;
                }
                case lexer::TokenType::KEYW_ASYNC: {
                    if ((lexer_->GetToken().Flags() & lexer::TokenFlags::HAS_ESCAPE) == 0) {
                        lexer_->NextToken();  // eat `async`
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

            break;
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
    export_decl_ctx.BindExportDecl(export_declaration);

    if (eat_semicolon) {
        ConsumeSemicolon(export_declaration);
    }

    return export_declaration;
}

ir::Identifier *ParserImpl::ParseNamedExport(const lexer::Token &exported_token)
{
    if (exported_token.Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Unexpected token, expected an identifier.");
    }

    CheckRestrictedBinding(exported_token.KeywordType());

    const util::StringView &exported_string = exported_token.Ident();

    auto *exported = AllocNode<ir::Identifier>(exported_string, Allocator());
    exported->SetRange(exported_token.Loc());

    return exported;
}

ir::ExportAllDeclaration *ParserImpl::ParseExportAllDeclaration(const lexer::SourcePosition &start_loc)
{
    lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat `*` character

    ir::Identifier *exported = nullptr;

    if (CheckModuleAsModifier()) {
        lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
        exported = ParseNamedExport(lexer_->GetToken());
        lexer_->NextToken();  // eat exported name
    }

    ir::StringLiteral *source = ParseFromClause();
    lexer::SourcePosition end_loc = source->End();

    auto *export_declaration = AllocNode<ir::ExportAllDeclaration>(source, exported);
    export_declaration->SetRange({start_loc, end_loc});
    auto *decl = Binder()->AddDecl<binder::ExportDecl>(start_loc, exported != nullptr ? exported->Name() : "*", "*");
    Binder()->GetScope()->AsModuleScope()->AddExportDecl(export_declaration, decl);

    ConsumeSemicolon(export_declaration);

    return export_declaration;
}

ir::ExportNamedDeclaration *ParserImpl::ParseExportNamedSpecifiers(const lexer::SourcePosition &start_loc)
{
    lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat `{` character

    ArenaVector<ir::ExportSpecifier *> specifiers(Allocator()->Adapter());
    binder::ModuleScope::ExportDeclList export_decls(Allocator()->Adapter());

    while (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        if (lexer_->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
            ThrowSyntaxError("Unexpected token");
        }

        lexer::Token local_token = lexer_->GetToken();
        auto *local = AllocNode<ir::Identifier>(lexer_->GetToken().Ident(), Allocator());
        local->SetRange(lexer_->GetToken().Loc());

        lexer_->NextToken();  // eat local name

        ir::Identifier *exported = nullptr;

        if (CheckModuleAsModifier()) {
            lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat `as` literal
            exported = ParseNamedExport(lexer_->GetToken());
            lexer_->NextToken();  // eat exported name
        } else {
            exported = ParseNamedExport(local_token);
        }

        auto *specifier = AllocNode<ir::ExportSpecifier>(local, exported);
        specifier->SetRange({local->Start(), exported->End()});

        specifiers.push_back(specifier);
        auto *decl = Binder()->AddDecl<binder::ExportDecl>(start_loc, exported->Name(), local->Name(), specifier);
        export_decls.push_back(decl);

        if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
            lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat comma
        }
    }

    lexer::SourcePosition end_pos = lexer_->GetToken().End();
    lexer_->NextToken();  // eat right brace

    ir::StringLiteral *source = nullptr;

    if (lexer_->GetToken().KeywordType() == lexer::TokenType::KEYW_FROM) {
        source = ParseFromClause();
    }

    auto *export_declaration = AllocNode<ir::ExportNamedDeclaration>(Allocator(), source, std::move(specifiers));
    export_declaration->SetRange({start_loc, end_pos});
    Binder()->GetScope()->AsModuleScope()->AddExportDecl(export_declaration, std::move(export_decls));
    ConsumeSemicolon(export_declaration);

    return export_declaration;
}

ir::ExportNamedDeclaration *ParserImpl::ParseNamedExportDeclaration(const lexer::SourcePosition &start_loc)
{
    ir::Statement *decl = nullptr;
    ExportDeclarationContext export_decl_ctx(Binder());

    switch (lexer_->GetToken().Type()) {
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
            decl = ParseClassDeclaration(ir::ClassDefinitionModifiers::ID_REQUIRED);
            break;
        }
        case lexer::TokenType::LITERAL_IDENT: {
            if (lexer_->GetToken().KeywordType() == lexer::TokenType::KEYW_STRUCT) {
                decl = ParseStructDeclaration(ir::ClassDefinitionModifiers::NONE);
                break;
            }
            [[fallthrough]];
        }
        default: {
            if (!lexer_->GetToken().IsAsyncModifier()) {
                ThrowSyntaxError("Unexpected token");
            }

            lexer_->NextToken();  // eat `async` keyword
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
    export_decl_ctx.BindExportDecl(export_declaration);

    return export_declaration;
}

ir::Statement *ParserImpl::ParseExportDeclaration(StatementParsingFlags flags)
{
    if ((flags & StatementParsingFlags::GLOBAL) == 0) {
        ThrowSyntaxError("'import' and 'export' may only appear at the top level");
    }

    if (!context_.IsModule()) {
        ThrowSyntaxError("'import' and 'export' may appear only with 'sourceType: module'");
    }

    lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    lexer_->NextToken();  // eat `export` keyword

    switch (lexer_->GetToken().Type()) {
        case lexer::TokenType::PUNCTUATOR_MULTIPLY: {
            return ParseExportAllDeclaration(start_loc);
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_BRACE: {
            return ParseExportNamedSpecifiers(start_loc);
        }
        default: {
            if (lexer_->GetToken().KeywordType() == lexer::TokenType::KEYW_DEFAULT) {
                return ParseExportDefaultDeclaration(start_loc);
            }
            return ParseNamedExportDeclaration(start_loc);
        }
    }
}

void ParserImpl::ParseNameSpaceImport(ArenaVector<ir::AstNode *> *specifiers)
{
    lexer::SourcePosition namespace_start = lexer_->GetToken().Start();
    lexer_->NextToken();  // eat `*` character

    if (!CheckModuleAsModifier()) {
        ThrowSyntaxError("Unexpected token.");
    }

    lexer_->NextToken();  // eat `as` literal

    ir::Identifier *local = ParseNamedImport(lexer_->GetToken());

    auto *specifier = AllocNode<ir::ImportNamespaceSpecifier>(local);
    specifier->SetRange({namespace_start, lexer_->GetToken().End()});
    specifiers->push_back(specifier);

    Binder()->AddDecl<binder::ImportDecl>(namespace_start, "*", local->Name(), specifier);

    lexer_->NextToken();  // eat local name
}

ir::Identifier *ParserImpl::ParseNamedImport(const lexer::Token &imported_token)
{
    if (imported_token.Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Unexpected token");
    }

    CheckRestrictedBinding(imported_token.KeywordType());

    auto *local = AllocNode<ir::Identifier>(imported_token.Ident(), Allocator());
    local->SetRange(imported_token.Loc());

    return local;
}

void ParserImpl::ParseNamedImportSpecifiers(ArenaVector<ir::AstNode *> *specifiers)
{
    lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat `{` character

    while (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        if (lexer_->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
            ThrowSyntaxError("Unexpected token");
        }

        lexer::Token imported_token = lexer_->GetToken();
        auto *imported = AllocNode<ir::Identifier>(imported_token.Ident(), Allocator());
        ir::Identifier *local = nullptr;
        imported->SetRange(lexer_->GetToken().Loc());

        lexer_->NextToken();  // eat import name

        if (CheckModuleAsModifier()) {
            lexer_->NextToken();  // eat `as` literal
            local = ParseNamedImport(lexer_->GetToken());
            lexer_->NextToken();  // eat local name
        } else {
            local = ParseNamedImport(imported_token);
        }

        auto *specifier = AllocNode<ir::ImportSpecifier>(imported, local);
        specifier->SetRange({imported->Start(), local->End()});
        specifiers->push_back(specifier);

        Binder()->AddDecl<binder::ImportDecl>(imported->Start(), imported->Name(), local->Name(), specifier);

        if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
            lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat comma
        }
    }

    lexer_->NextToken();  // eat right brace
}

ir::AstNode *ParserImpl::ParseImportDefaultSpecifier(ArenaVector<ir::AstNode *> *specifiers)
{
    ir::Identifier *local = ParseNamedImport(lexer_->GetToken());
    lexer_->NextToken();  // eat local name

    auto *specifier = AllocNode<ir::ImportDefaultSpecifier>(local);
    specifier->SetRange(specifier->Local()->Range());
    specifiers->push_back(specifier);

    Binder()->AddDecl<binder::ImportDecl>(local->Start(), "default", local->Name(), specifier);

    lexer_->NextToken();  // eat specifier name

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
        lexer_->NextToken();  // eat comma
    }

    return nullptr;
}

ir::StringLiteral *ParserImpl::ParseFromClause(bool require_from)
{
    if (lexer_->GetToken().KeywordType() != lexer::TokenType::KEYW_FROM) {
        if (require_from) {
            ThrowSyntaxError("Unexpected token.");
        }
    } else {
        lexer_->NextToken();  // eat `from` literal
    }

    if (lexer_->GetToken().Type() != lexer::TokenType::LITERAL_STRING) {
        ThrowSyntaxError("Unexpected token.");
    }

    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::LITERAL_STRING);

    auto *source = AllocNode<ir::StringLiteral>(lexer_->GetToken().String());
    source->SetRange(lexer_->GetToken().Loc());

    lexer_->NextToken();

    return source;
}

ir::AstNode *ParserImpl::ParseImportSpecifiers(ArenaVector<ir::AstNode *> *specifiers)
{
    ASSERT(specifiers->empty());

    if (lexer_->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
        ir::AstNode *ast_node = ParseImportDefaultSpecifier(specifiers);

        if (ast_node != nullptr) {
            return ast_node;
        }
    }

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY) {
        ParseNameSpaceImport(specifiers);
    } else if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        ParseNamedImportSpecifiers(specifiers);
    }
    return nullptr;
}

ir::Statement *ParserImpl::ParseImportDeclaration(StatementParsingFlags flags)
{
    ImportDeclarationContext import_ctx(Binder());

    if ((flags & StatementParsingFlags::GLOBAL) == 0) {
        ThrowSyntaxError("'import' and 'export' may only appear at the top level");
    }

    if (!context_.IsModule()) {
        ThrowSyntaxError("'import' and 'export' may appear only with 'sourceType: module'");
    }

    char32_t next_char = lexer_->Lookahead();
    if (next_char == lexer::LEX_CHAR_LEFT_PAREN || next_char == lexer::LEX_CHAR_DOT) {
        return ParseExpressionStatement();
    }

    lexer::SourcePosition start_loc = lexer_->GetToken().Start();
    lexer_->NextToken();  // eat import

    ArenaVector<ir::AstNode *> specifiers(Allocator()->Adapter());

    ir::StringLiteral *source = nullptr;

    if (lexer_->GetToken().Type() != lexer::TokenType::LITERAL_STRING) {
        ParseImportSpecifiers(&specifiers);
        source = ParseFromClause(true);
    } else {
        source = ParseFromClause(false);
    }

    lexer::SourcePosition end_loc = source->End();
    auto *import_declaration = AllocNode<ir::ImportDeclaration>(source, std::move(specifiers));
    import_declaration->SetRange({start_loc, end_loc});
    import_ctx.BindImportDecl(import_declaration);

    ConsumeSemicolon(import_declaration);

    return import_declaration;
}
}  // namespace panda::es2panda::parser
