/**
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "util/es2pandaMacros.h"
#include "parser/parserFlags.h"
#include "util/errorRecovery.h"
#include "util/helpers.h"
#include "utils/arena_containers.h"
#include "varbinder/varbinder.h"
#include "varbinder/ETSBinder.h"
#include "lexer/lexer.h"
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
#include "ir/ets/etsModule.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/ets/etsNullishTypes.h"
#include "ir/ets/etsUnionType.h"
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
#include "generated/diagnostic.h"

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
        if (stmt->IsETSModule()) {
            return stmt;
        }
        if ((memberModifiers & ir::ModifierFlags::EXPORT_TYPE) != 0U &&
            !(stmt->IsClassDeclaration() || stmt->IsTSInterfaceDeclaration() || stmt->IsTSTypeAliasDeclaration())) {
            parser->LogError(diagnostic::ONLY_EXPORT_CLASS_OR_INTERFACE, {}, stmt->Start());
        }
        if (stmt->IsAnnotationDeclaration()) {
            if ((memberModifiers & ir::ModifierFlags::DEFAULT_EXPORT) != 0U) {
                parser->LogError(diagnostic::INVALID_EXPORT_DEFAULT, {}, stmt->Start());
            }
        }
        stmt->AddModifier(memberModifiers);
    } else {
        if ((memberModifiers &
             (ir::ModifierFlags::EXPORT | ir::ModifierFlags::DEFAULT_EXPORT | ir::ModifierFlags::EXPORT_TYPE)) != 0U) {
            parser->LogError(diagnostic::EXPORT_NON_DECLARATION, {}, pos);
        }
    }

    return stmt;
}
bool ETSParser::IsExportedDeclaration(ir::ModifierFlags memberModifiers)
{
    return (memberModifiers & ir::ModifierFlags::EXPORTED) != 0U &&
           (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY ||
            Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE);
}

bool ETSParser::IsInitializerBlockStart() const
{
    if (Lexer()->GetToken().Type() != lexer::TokenType::KEYW_STATIC) {
        return false;
    }

    auto savedPos = Lexer()->Save();
    Lexer()->NextToken();
    const bool validStart = Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE &&
                            (GetContext().Status() & ParserStatus::IN_NAMESPACE) != 0;
    Lexer()->Rewind(savedPos);
    return validStart;
}

ir::Statement *ETSParser::ParseTopLevelDeclStatement(StatementParsingFlags flags)
{
    auto [memberModifiers, startLoc] = ParseMemberModifiers();
    if (IsExportedDeclaration(memberModifiers)) {
        return ParseExport(startLoc, memberModifiers);
    }

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_GET ||
        Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_SET) {
        return ParseAccessorWithReceiver(memberModifiers);
    }

    ir::Statement *result = nullptr;
    auto token = Lexer()->GetToken();
    switch (token.Type()) {
        case lexer::TokenType::KEYW_FUNCTION: {
            result = ParseFunctionDeclaration(false, memberModifiers);
            result->SetStart(startLoc);
            break;
        }
        case lexer::TokenType::KEYW_CONST:
            memberModifiers |= ir::ModifierFlags::CONST;
            [[fallthrough]];
        case lexer::TokenType::KEYW_LET:
            result = ParseStatement(flags);
            break;
        case lexer::TokenType::KEYW_STATIC:
        case lexer::TokenType::KEYW_ABSTRACT:
        case lexer::TokenType::KEYW_FINAL:
        case lexer::TokenType::KEYW_ENUM:
        case lexer::TokenType::KEYW_INTERFACE:
        case lexer::TokenType::KEYW_CLASS:
            result = ParseTypeDeclaration(IsInitializerBlockStart());
            break;
        case lexer::TokenType::PUNCTUATOR_AT:
            result = ParseTopLevelAnnotation(memberModifiers);
            break;
        case lexer::TokenType::LITERAL_IDENT: {
            if (IsNamespaceDecl()) {
                return ParseNamespaceStatement(memberModifiers);
            }
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

ir::Statement *ETSParser::ParseAnnotationsInStatement(StatementParsingFlags flags)
{
    Lexer()->NextToken();  // eat '@'

    auto annotations = ParseAnnotations(false);
    auto savePos = Lexer()->GetToken().Start();
    ir::Statement *result = ParseStatement(flags);
    if (result != nullptr) {
        ApplyAnnotationsToNode(result, std::move(annotations), savePos);
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
        LogError(diagnostic::MISSING_LOOP_AFTER_LABEL, {}, Lexer()->GetToken().Start());
        return false;
    }

    return true;
}

bool ETSParser::ValidateForInStatement()
{
    LogUnexpectedToken(lexer::TokenType::KEYW_IN);
    return false;
}

ir::Statement *ETSParser::ParseDebuggerStatement()
{
    LogUnexpectedToken(lexer::TokenType::KEYW_DEBUGGER);
    return AllocBrokenStatement(Lexer()->GetToken().Loc());
}

ir::Statement *ETSParser::ParseFunctionStatement(const StatementParsingFlags flags)
{
    ES2PANDA_ASSERT((flags & StatementParsingFlags::GLOBAL) == 0);
    LogError(diagnostic::NESTED_FUNCTIONS_NOT_ALLOWED);
    ParserImpl::ParseFunctionStatement(flags);  // Try to parse function body but skip result.
    return AllocBrokenStatement(Lexer()->GetToken().Loc());
}

ir::Statement *ETSParser::ParseTryStatement()
{
    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat the 'try' keyword

    ir::BlockStatement *body = ParseBlockStatement();

    ArenaVector<ir::CatchClause *> catchClauses(Allocator()->Adapter());

    while (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_CATCH) {
        catchClauses.push_back(ParseCatchClause());
    }

    ir::BlockStatement *finalizer = nullptr;
    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_FINALLY) {
        Lexer()->NextToken();  // eat 'finally' keyword

        finalizer = ParseBlockStatement();
    }

    if (catchClauses.empty() && finalizer == nullptr) {
        LogError(diagnostic::MISSING_CATCH_OR_FINALLY_AFTER_TRY, {}, startLoc);
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
ir::Statement *ETSParser::ParseClassStatement([[maybe_unused]] StatementParsingFlags flags,
                                              ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags modFlags)
{
    modFlags |= ParseClassModifiers();
    return ParseClassDeclaration(modifiers | ir::ClassDefinitionModifiers::ID_REQUIRED |
                                     ir::ClassDefinitionModifiers::CLASS_DECL | ir::ClassDefinitionModifiers::LOCAL,
                                 modFlags);
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Statement *ETSParser::ParseStructStatement([[maybe_unused]] StatementParsingFlags flags,
                                               ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags modFlags)
{
    const auto &rangeStruct = Lexer()->GetToken().Loc();
    LogError(diagnostic::ILLEGAL_START_STRUCT, {}, rangeStruct.start);
    ParseClassDeclaration(modifiers | ir::ClassDefinitionModifiers::ID_REQUIRED |
                              ir::ClassDefinitionModifiers::CLASS_DECL | ir::ClassDefinitionModifiers::LOCAL,
                          modFlags);  // Try to parse struct and drop the result.
    return AllocBrokenStatement(rangeStruct);
}

}  // namespace ark::es2panda::parser
