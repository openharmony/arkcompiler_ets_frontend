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
#include "util/errorRecovery.h"
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
#include "ir/statements/annotationDeclaration.h"
#include "ir/statements/annotationUsage.h"
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
        util::ErrorRecursionGuard infiniteLoopBlocker(Lexer());

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

static ir::Statement *ValidateExportableStatement(ETSParser *parser, ir::Statement *stmt,
                                                  ark::es2panda::ir::ModifierFlags memberModifiers,
                                                  lexer::SourcePosition pos)
{
    if (stmt != nullptr) {
        if ((memberModifiers & ir::ModifierFlags::EXPORT_TYPE) != 0U &&
            !(stmt->IsClassDeclaration() || stmt->IsTSInterfaceDeclaration() || stmt->IsTSTypeAliasDeclaration())) {
            parser->LogSyntaxError("Can only type export class or interface!", stmt->Start());
        }
        if (stmt->IsAnnotationDeclaration()) {
            if ((memberModifiers & ir::ModifierFlags::DEFAULT_EXPORT) != 0U) {
                parser->LogSyntaxError("Can not export annotation default!", stmt->Start());
            }
        }
        stmt->AddModifier(memberModifiers);
    } else {
        if ((memberModifiers &
             (ir::ModifierFlags::EXPORT | ir::ModifierFlags::DEFAULT_EXPORT | ir::ModifierFlags::EXPORT_TYPE)) != 0U) {
            parser->LogSyntaxError("Export is allowed only for declarations.", pos);
        }
    }

    return stmt;
}

ir::Statement *ETSParser::ParseAnnotation(StatementParsingFlags flags, ir::ModifierFlags memberModifiers)
{
    ir::Statement *result = nullptr;

    Lexer()->NextToken();  // eat '@'
    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_INTERFACE) {
        result = ParseAnnotationDeclaration(memberModifiers);
    } else {
        auto annotations = ParseAnnotations(memberModifiers);
        auto savePos = Lexer()->GetToken().Start();
        result = ParseTopLevelDeclStatement(flags);
        if (result != nullptr) {
            ApplyAnnotationsToNode(result, std::move(annotations), savePos);
        }
    }

    return result;
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
            if (result = ParseFunctionDeclaration(false, memberModifiers); result != nullptr) {  // Error processing.
                result->SetStart(startLoc);
            }
            break;
        }
        case lexer::TokenType::KEYW_CONST:
            memberModifiers |= ir::ModifierFlags::CONST;
            [[fallthrough]];
        case lexer::TokenType::KEYW_LET:
            result = ParseStatement(flags);
            break;
        case lexer::TokenType::KEYW_NAMESPACE:
        case lexer::TokenType::KEYW_STATIC:
        case lexer::TokenType::KEYW_ABSTRACT:
        case lexer::TokenType::KEYW_FINAL:
        case lexer::TokenType::KEYW_ENUM:
        case lexer::TokenType::KEYW_INTERFACE:
        case lexer::TokenType::KEYW_CLASS:
            result = ParseTypeDeclaration(false);
            break;
        case lexer::TokenType::PUNCTUATOR_AT:
            result = ParseAnnotation(flags, memberModifiers);
            break;
        case lexer::TokenType::LITERAL_IDENT: {
            result = ParseIdentKeyword();
            if (result == nullptr && (memberModifiers & (ir::ModifierFlags::EXPORTED)) != 0U) {
                return ParseExport(startLoc, memberModifiers);
            }
            break;
        }
        default: {
        }
    }

    return ValidateExportableStatement(this, result, memberModifiers, startLoc);
}

ir::Statement *ETSParser::ParseTopLevelStatement()
{
    const auto flags = StatementParsingFlags::ALLOW_LEXICAL;

    auto result = ParseTopLevelDeclStatement(flags);
    if (result == nullptr) {
        result = ParseStatement(flags);
    }
    return result;
}

ArenaVector<ir::Statement *> ETSParser::ParseTopLevelDeclaration()
{
    auto topStatements = ParseTopLevelStatements();
    Lexer()->NextToken();
    return topStatements;
}

bool ETSParser::ValidateLabeledStatement(lexer::TokenType type)
{
    if (type != lexer::TokenType::KEYW_DO && type != lexer::TokenType::KEYW_WHILE &&
        type != lexer::TokenType::KEYW_FOR && type != lexer::TokenType::KEYW_SWITCH) {
        LogSyntaxError("Label must be followed by a loop statement", Lexer()->GetToken().Start());
        return false;
    }

    return true;
}

bool ETSParser::ValidateForInStatement()
{
    LogSyntaxError({"Unexpected token: '", lexer::TokenToString(lexer::TokenType::KEYW_IN), "'."});
    return false;
}

ir::DebuggerStatement *ETSParser::ParseDebuggerStatement()
{
    LogSyntaxError({"Unexpected token: '", lexer::TokenToString(lexer::TokenType::KEYW_DEBUGGER), "'."});
    return nullptr;
}

ir::Statement *ETSParser::ParseFunctionStatement(const StatementParsingFlags flags)
{
    ASSERT((flags & StatementParsingFlags::GLOBAL) == 0);
    LogSyntaxError("Nested functions are not allowed");
    ParserImpl::ParseFunctionStatement(flags);  // Try to parse function body but skip result.
    return nullptr;
}

ir::Statement *ETSParser::ParseAssertStatement()
{
    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();
    Lexer()->NextToken();

    ir::Expression *test = ParseExpression();
    if (test == nullptr) {  // Error processing.
        return nullptr;
    }

    lexer::SourcePosition endLoc = test->End();
    ir::Expression *second = nullptr;

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        second = ParseExpression();
        if (second != nullptr) {  // Error processing.
            endLoc = second->End();
        }
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
        LogSyntaxError("A try statement should contain either finally clause or at least one catch clause.", startLoc);
        return nullptr;
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
    modFlags |= ParseClassModifiers();
    return ParseClassDeclaration(modifiers | ir::ClassDefinitionModifiers::ID_REQUIRED |
                                     ir::ClassDefinitionModifiers::CLASS_DECL | ir::ClassDefinitionModifiers::LOCAL,
                                 modFlags);
}

// NOLINTNEXTLINE(google-default-arguments)
ir::ETSStructDeclaration *ETSParser::ParseStructStatement([[maybe_unused]] StatementParsingFlags flags,
                                                          ir::ClassDefinitionModifiers modifiers,
                                                          ir::ModifierFlags modFlags)
{
    LogSyntaxError("Illegal start of STRUCT expression", Lexer()->GetToken().Start());
    ParseClassDeclaration(modifiers | ir::ClassDefinitionModifiers::ID_REQUIRED |
                              ir::ClassDefinitionModifiers::CLASS_DECL | ir::ClassDefinitionModifiers::LOCAL,
                          modFlags);  // Try to parse struct and drop the result.
    return nullptr;
}

}  // namespace ark::es2panda::parser
