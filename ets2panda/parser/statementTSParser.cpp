/**
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "TSparser.h"

#include "parserFlags.h"
#include "util/helpers.h"
#include "varbinder/privateBinding.h"
#include "varbinder/scope.h"
#include "varbinder/tsBinding.h"
#include "lexer/TSLexer.h"
#include "ir/base/spreadElement.h"
#include "ir/base/decorator.h"
#include "ir/base/classElement.h"
#include "ir/base/classDefinition.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/module/importDefaultSpecifier.h"
#include "ir/module/exportDefaultDeclaration.h"
#include "ir/module/exportAllDeclaration.h"
#include "ir/module/exportNamedDeclaration.h"
#include "ir/module/importDeclaration.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/sequenceExpression.h"
#include "ir/expressions/templateLiteral.h"
#include "ir/expressions/taggedTemplateExpression.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/arrowFunctionExpression.h"
#include "ir/expressions/yieldExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/objectExpression.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/literals/bigIntLiteral.h"
#include "ir/expressions/literals/booleanLiteral.h"
#include "ir/expressions/literals/nullLiteral.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/stringLiteral.h"
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
#include "ir/ts/tsLiteralType.h"
#include "ir/ts/tsMappedType.h"
#include "ir/ts/tsImportType.h"
#include "ir/ts/tsThisType.h"
#include "ir/ts/tsConditionalType.h"
#include "ir/ts/tsTypeOperator.h"
#include "ir/ts/tsInferType.h"
#include "ir/ts/tsTupleType.h"
#include "ir/ts/tsNamedTupleMember.h"
#include "ir/ts/tsQualifiedName.h"
#include "ir/ts/tsIndexedAccessType.h"
#include "ir/ts/tsTypeQuery.h"
#include "ir/ts/tsTypeReference.h"
#include "ir/ts/tsTypePredicate.h"
#include "ir/ts/tsTypeLiteral.h"
#include "ir/ts/tsArrayType.h"
#include "ir/ts/tsUnionType.h"
#include "ir/ts/tsIntersectionType.h"
#include "ir/ts/tsAnyKeyword.h"
#include "ir/ts/tsUndefinedKeyword.h"
#include "ir/ts/tsVoidKeyword.h"
#include "ir/ts/tsNumberKeyword.h"
#include "ir/ts/tsStringKeyword.h"
#include "ir/ts/tsBooleanKeyword.h"
#include "ir/ts/tsBigintKeyword.h"
#include "ir/ts/tsUnknownKeyword.h"
#include "ir/ts/tsNullKeyword.h"
#include "ir/ts/tsNeverKeyword.h"
#include "ir/ts/tsObjectKeyword.h"
#include "ir/ts/tsFunctionType.h"
#include "ir/ts/tsConstructorType.h"
#include "ir/ts/tsParenthesizedType.h"
#include "ir/ts/tsTypeAssertion.h"
#include "ir/ts/tsAsExpression.h"
#include "ir/ts/tsNonNullExpression.h"
#include "ir/ts/tsEnumDeclaration.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "ir/ts/tsTypeAliasDeclaration.h"
#include "ir/ts/tsModuleDeclaration.h"
#include "ir/ts/tsTypeParameterInstantiation.h"
#include "ir/ts/tsInterfaceHeritage.h"
#include "ir/base/tsSignatureDeclaration.h"
#include "ir/base/tsIndexSignature.h"
#include "ir/base/tsMethodSignature.h"
#include "ir/base/tsPropertySignature.h"
#include "ir/ts/tsParameterProperty.h"
#include "ir/ts/tsClassImplements.h"
#include "ir/ts/tsImportEqualsDeclaration.h"
#include "ir/ts/tsExternalModuleReference.h"

namespace ark::es2panda::parser {
// NOLINTNEXTLINE(google-default-arguments)
ir::Statement *TSParser::ParseStatement(StatementParsingFlags flags)
{
    return ParseDeclareAndDecorators(flags);
}
ir::TSImportEqualsDeclaration *TSParser::ParseTsImportEqualsDeclaration(const lexer::SourcePosition &startLoc,
                                                                        bool isExport)
{
    ES2PANDA_ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::KEYW_IMPORT);
    Lexer()->NextToken();
    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Unexpected token");
    }

    auto *id = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    id->SetRange(Lexer()->GetToken().Loc());
    Lexer()->NextToken();  // eat id name

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        ThrowSyntaxError("'=' expected");
    }
    Lexer()->NextToken();  // eat substitution

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("identifier expected");
    }

    auto *importEqualsDecl = AllocNode<ir::TSImportEqualsDeclaration>(id, ParseModuleReference(), isExport);
    importEqualsDecl->SetRange({startLoc, Lexer()->GetToken().End()});

    ConsumeSemicolon(importEqualsDecl);

    return importEqualsDecl;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::ExportDefaultDeclaration *TSParser::ParseExportDefaultDeclaration(const lexer::SourcePosition &startLoc,
                                                                      bool isExportEquals)
{
    Lexer()->NextToken();  // eat `default` keyword or `=`

    ir::AstNode *declNode = nullptr;
    bool eatSemicolon = false;

    switch (Lexer()->GetToken().KeywordType()) {
        case lexer::TokenType::KEYW_FUNCTION: {
            declNode = ParseFunctionDeclaration(true);
            break;
        }
        case lexer::TokenType::KEYW_CLASS: {
            declNode = ParseClassDeclaration(ir::ClassDefinitionModifiers::ID_REQUIRED);
            break;
        }
        case lexer::TokenType::KEYW_INTERFACE: {
            declNode = ParseInterfaceDeclaration(false);
            break;
        }
        case lexer::TokenType::KEYW_ASYNC: {
            if ((Lexer()->GetToken().Flags() & lexer::TokenFlags::HAS_ESCAPE) == 0) {
                Lexer()->NextToken();  // eat `async`
                declNode = ParseFunctionDeclaration(false, ParserStatus::ASYNC_FUNCTION);
                break;
            }
            [[fallthrough]];
        }
        default: {
            declNode = ParseExpression();
            eatSemicolon = true;
            break;
        }
    }

    lexer::SourcePosition endLoc = declNode->End();
    auto *exportDeclaration = AllocNode<ir::ExportDefaultDeclaration>(declNode, isExportEquals);
    exportDeclaration->SetRange({startLoc, endLoc});

    if (eatSemicolon) {
        ConsumeSemicolon(exportDeclaration);
    }

    return exportDeclaration;
}

ir::Statement *TSParser::GetDeclarationForNamedExport(ir::ClassDefinitionModifiers &classModifiers,
                                                      ir::ModifierFlags &flags)
{
    switch (Lexer()->GetToken().KeywordType()) {
        case lexer::TokenType::KEYW_VAR: {
            return ParseVariableDeclaration(VariableParsingFlags::VAR);
        }
        case lexer::TokenType::KEYW_CONST: {
            return ParseVariableDeclaration(VariableParsingFlags::CONST);
        }
        case lexer::TokenType::KEYW_LET: {
            return ParseVariableDeclaration(VariableParsingFlags::LET);
        }
        case lexer::TokenType::KEYW_FUNCTION: {
            return ParseFunctionDeclaration(false, ParserStatus::NO_OPTS);
        }
        case lexer::TokenType::KEYW_CLASS: {
            return ParseClassDeclaration(classModifiers, flags);
        }
        case lexer::TokenType::KEYW_ENUM: {
            return ParseEnumDeclaration();
        }
        case lexer::TokenType::KEYW_INTERFACE: {
            return ParseInterfaceDeclaration(false);
        }
        case lexer::TokenType::KEYW_TYPE: {
            return ParseTypeAliasDeclaration();
        }
        case lexer::TokenType::KEYW_GLOBAL:
        case lexer::TokenType::KEYW_MODULE:
        case lexer::TokenType::KEYW_NAMESPACE: {
            return ParseModuleDeclaration();
        }
        default: {
            if (!Lexer()->GetToken().IsAsyncModifier()) {
                ThrowSyntaxError("Unexpected token");
            }

            Lexer()->NextToken();  // eat `async` keyword
            return ParseFunctionDeclaration(false, ParserStatus::ASYNC_FUNCTION);
        }
    }
}
ir::Statement *TSParser::ParseNamedExportDeclaration(const lexer::SourcePosition &startLoc)
{
    ir::ClassDefinitionModifiers classModifiers = ir::ClassDefinitionModifiers::ID_REQUIRED;
    ir::ModifierFlags flags = ir::ModifierFlags::NONE;

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_DECLARE) {
        CheckDeclare();
    }

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_ABSTRACT) {
        Lexer()->NextToken();  // eat 'abstract'
        flags |= ir::ModifierFlags::ABSTRACT;
    }

    ir::Statement *decl = GetDeclarationForNamedExport(classModifiers, flags);

    if (decl->IsVariableDeclaration()) {
        ConsumeSemicolon(decl);
    }

    lexer::SourcePosition endLoc = decl->End();
    ArenaVector<ir::ExportSpecifier *> specifiers(Allocator()->Adapter());
    auto *exportDeclaration = AllocNode<ir::ExportNamedDeclaration>(Allocator(), decl, std::move(specifiers));
    exportDeclaration->SetRange({startLoc, endLoc});

    return exportDeclaration;
}

ir::Statement *TSParser::ParseExportDeclaration(StatementParsingFlags flags)
{
    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat `export` keyword

    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::KEYW_DEFAULT: {
            return ParseExportDefaultDeclaration(startLoc);
        }
        case lexer::TokenType::PUNCTUATOR_MULTIPLY: {
            return ParseExportAllDeclaration(startLoc);
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_BRACE: {
            return ParseExportNamedSpecifiers(startLoc);
        }
        case lexer::TokenType::KEYW_IMPORT: {
            return ParseTsImportEqualsDeclaration(startLoc, true);
        }
        case lexer::TokenType::PUNCTUATOR_SUBSTITUTION: {
            return ParseExportDefaultDeclaration(startLoc, true);
        }
        default: {
            auto ret = ParseNamedExportDeclaration(startLoc);
            if (ret->IsBrokenStatement()) {
                return ret;
            }
            ir::ExportNamedDeclaration *exportDecl = ret->AsExportNamedDeclaration();
            if (exportDecl->Decl()->IsVariableDeclaration() && ((flags & StatementParsingFlags::GLOBAL) == 0) &&
                exportDecl->Parent() != nullptr && !exportDecl->Parent()->IsTSModuleBlock() &&
                !GetContext().IsModule()) {
                ThrowSyntaxError("Modifiers cannot appear here'");
            }

            return exportDecl;
        }
    }
}

ir::Statement *TSParser::ParseConstStatement(StatementParsingFlags flags)
{
    lexer::SourcePosition constVarStar = Lexer()->GetToken().Start();
    Lexer()->NextToken();

    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_ENUM) {
        return ParseEnumDeclaration(true);
    }

    if ((flags & StatementParsingFlags::ALLOW_LEXICAL) == 0) {
        ThrowSyntaxError("Lexical declaration is not allowed in single statement context");
    }

    auto *variableDecl = ParseVariableDeclaration(VariableParsingFlags::CONST | VariableParsingFlags::NO_SKIP_VAR_KIND);
    variableDecl->SetStart(constVarStar);
    ConsumeSemicolon(variableDecl);

    return variableDecl;
}

ir::Statement *TSParser::ParsePotentialConstEnum(VariableParsingFlags flags)
{
    if ((flags & VariableParsingFlags::CONST) == 0) {
        ThrowSyntaxError("Variable declaration expected.");
    }

    return ParseEnumDeclaration(true);
}

ir::Statement *TSParser::ParseImportDeclaration([[maybe_unused]] StatementParsingFlags flags)
{
    char32_t nextChar = Lexer()->Lookahead();
    if (nextChar == lexer::LEX_CHAR_LEFT_PAREN || nextChar == lexer::LEX_CHAR_DOT) {
        return ParseExpressionStatement();
    }

    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat import

    ArenaVector<ir::AstNode *> specifiers(Allocator()->Adapter());

    ir::StringLiteral *source = nullptr;

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_STRING) {
        ir::AstNode *astNode = ParseImportSpecifiers(&specifiers);
        if (astNode != nullptr) {
            ES2PANDA_ASSERT(astNode->IsTSImportEqualsDeclaration());
            astNode->SetRange({startLoc, Lexer()->GetToken().End()});
            ConsumeSemicolon(astNode->AsTSImportEqualsDeclaration());
            return astNode->AsTSImportEqualsDeclaration();
        }
        source = ParseFromClause(true);
    } else {
        source = ParseFromClause(false);
    }

    lexer::SourcePosition endLoc = source->End();
    auto *importDeclaration = AllocNode<ir::ImportDeclaration>(source, std::move(specifiers));
    importDeclaration->SetRange({startLoc, endLoc});

    ConsumeSemicolon(importDeclaration);

    return importDeclaration;
}

}  // namespace ark::es2panda::parser