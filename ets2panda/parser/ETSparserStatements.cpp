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

ArenaVector<ir::Statement *> ETSParser::ParseTopLevelStatements()
{
    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());
    while (Lexer()->GetToken().Type() != lexer::TokenType::EOS) {
        if (Lexer()->TryEatTokenType(lexer::TokenType::PUNCTUATOR_SEMI_COLON)) {
            continue;
        }
        auto stmt = ParseTopLevelStatement();
        GetContext().Status() &= ~ParserStatus::IN_AMBIENT_CONTEXT;
        if (stmt != nullptr) {
            statements.emplace_back(stmt);
        }
    }

    return statements;
}

ir::Statement *ETSParser::ParseTopLevelDeclStatement(StatementParsingFlags flags)
{
    auto [memberModifiers, startLoc] = ParseMemberModifiers();
    if ((memberModifiers & (ir::ModifierFlags::EXPORTED)) != 0U &&
        (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY ||
         Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE)) {
        return ParseExport(startLoc, memberModifiers);
    }

    ir::Statement *result = nullptr;
    auto token = Lexer()->GetToken();
    switch (token.Type()) {
        case lexer::TokenType::KEYW_FUNCTION: {
            result = ParseFunctionDeclaration(false, memberModifiers);
            result->SetStart(startLoc);
            break;
        }
        case lexer::TokenType::KEYW_CONST: {
            memberModifiers |= ir::ModifierFlags::CONST;
            [[fallthrough]];
        }
        case lexer::TokenType::KEYW_LET: {
            result = ParseStatement(flags);
            break;
        }
        case lexer::TokenType::KEYW_NAMESPACE:
        case lexer::TokenType::KEYW_STATIC:
        case lexer::TokenType::KEYW_ABSTRACT:
        case lexer::TokenType::KEYW_FINAL:
        case lexer::TokenType::KEYW_ENUM:
        case lexer::TokenType::KEYW_INTERFACE:
        case lexer::TokenType::KEYW_CLASS: {
            result = ParseTypeDeclaration(false);
            break;
        }
        case lexer::TokenType::LITERAL_IDENT: {
            result = ParseIdentKeyword();
            break;
        }
        default: {
        }
    }
    if (result != nullptr) {
        if ((memberModifiers & ir::ModifierFlags::EXPORT_TYPE) != 0U &&
            !(result->IsClassDeclaration() || result->IsTSInterfaceDeclaration() ||
              result->IsTSTypeAliasDeclaration())) {
            ThrowSyntaxError("Can only type export class or interface!");
        }
        result->AddModifier(memberModifiers);
    }
    return result;
}

ir::Statement *ETSParser::ParseTopLevelStatement()
{
    const auto flags = StatementParsingFlags::ALLOW_LEXICAL;
    static const std::unordered_set<lexer::TokenType> ALLOWED_TOP_LEVEL_STMTS = {
        lexer::TokenType::PUNCTUATOR_LEFT_BRACE,
        lexer::TokenType::PUNCTUATOR_SEMI_COLON,
        lexer::TokenType::KEYW_ASSERT,
        lexer::TokenType::KEYW_IF,
        lexer::TokenType::KEYW_DO,
        lexer::TokenType::KEYW_FOR,
        lexer::TokenType::KEYW_TRY,
        lexer::TokenType::KEYW_WHILE,
        lexer::TokenType::KEYW_BREAK,
        lexer::TokenType::KEYW_CONTINUE,
        lexer::TokenType::KEYW_THROW,
        lexer::TokenType::KEYW_SWITCH,
        lexer::TokenType::KEYW_DEBUGGER,
        lexer::TokenType::LITERAL_IDENT,
    };

    auto result = ParseTopLevelDeclStatement(flags);
    if (result == nullptr) {
        auto const tokenType = Lexer()->GetToken().Type();
        if (ALLOWED_TOP_LEVEL_STMTS.count(tokenType) != 0U) {
            result = ParseStatement(flags);
        } else {
            ThrowUnexpectedToken(tokenType);
        }
    }
    return result;
}

ArenaVector<ir::Statement *> ETSParser::ParseTopLevelDeclaration()
{
    auto topStatements = ParseTopLevelStatements();
    Lexer()->NextToken();
    return topStatements;
}

void ETSParser::ValidateLabeledStatement(lexer::TokenType type)
{
    if (type != lexer::TokenType::KEYW_DO && type != lexer::TokenType::KEYW_WHILE &&
        type != lexer::TokenType::KEYW_FOR && type != lexer::TokenType::KEYW_SWITCH) {
        ThrowSyntaxError("Label must be followed by a loop statement", Lexer()->GetToken().Start());
    }
}

void ETSParser::ValidateForInStatement()
{
    ThrowUnexpectedToken(lexer::TokenType::KEYW_IN);
}

ir::DebuggerStatement *ETSParser::ParseDebuggerStatement()
{
    ThrowUnexpectedToken(lexer::TokenType::KEYW_DEBUGGER);
}

ir::Statement *ETSParser::ParseFunctionStatement([[maybe_unused]] const StatementParsingFlags flags)
{
    ASSERT((flags & StatementParsingFlags::GLOBAL) == 0);
    ThrowSyntaxError("Nested functions are not allowed");
}

ir::Statement *ETSParser::ParseAssertStatement()
{
    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();
    Lexer()->NextToken();

    ir::Expression *test = ParseExpression();
    lexer::SourcePosition endLoc = test->End();
    ir::Expression *second = nullptr;

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        second = ParseExpression();
        endLoc = second->End();
    }

    auto *asStatement = AllocNode<ir::AssertStatement>(test, second);
    asStatement->SetRange({startLoc, endLoc});
    ConsumeSemicolon(asStatement);

    return asStatement;
}

ir::Statement *ETSParser::ParseTryStatement()
{
    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat the 'try' keyword

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        ThrowSyntaxError("Unexpected token, expected '{'");
    }

    ir::BlockStatement *body = ParseBlockStatement();

    ArenaVector<ir::CatchClause *> catchClauses(Allocator()->Adapter());

    while (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_CATCH) {
        ir::CatchClause *clause {};

        clause = ParseCatchClause();

        catchClauses.push_back(clause);
    }

    ir::BlockStatement *finalizer = nullptr;
    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_FINALLY) {
        Lexer()->NextToken();  // eat 'finally' keyword

        finalizer = ParseBlockStatement();
    }

    if (catchClauses.empty() && finalizer == nullptr) {
        ThrowSyntaxError("A try statement should contain either finally clause or at least one catch clause.",
                         startLoc);
    }

    lexer::SourcePosition endLoc = finalizer != nullptr ? finalizer->End() : catchClauses.back()->End();

    ArenaVector<std::pair<compiler::LabelPair, const ir::Statement *>> finalizerInsertions(Allocator()->Adapter());

    auto *tryStatement = AllocNode<ir::TryStatement>(body, std::move(catchClauses), finalizer, finalizerInsertions);
    tryStatement->SetRange({startLoc, endLoc});
    ConsumeSemicolon(tryStatement);

    return tryStatement;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::ClassDeclaration *ETSParser::ParseClassStatement([[maybe_unused]] StatementParsingFlags flags,
                                                     ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags modFlags)
{
    return ParseClassDeclaration(modifiers | ir::ClassDefinitionModifiers::ID_REQUIRED |
                                     ir::ClassDefinitionModifiers::CLASS_DECL | ir::ClassDefinitionModifiers::LOCAL,
                                 modFlags);
}

// NOLINTNEXTLINE(google-default-arguments)
ir::ETSStructDeclaration *ETSParser::ParseStructStatement([[maybe_unused]] StatementParsingFlags flags,
                                                          [[maybe_unused]] ir::ClassDefinitionModifiers modifiers,
                                                          [[maybe_unused]] ir::ModifierFlags modFlags)
{
    ThrowSyntaxError("Illegal start of expression", Lexer()->GetToken().Start());
}

}  // namespace ark::es2panda::parser