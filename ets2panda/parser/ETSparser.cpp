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
#include "util/helpers.h"
#include "util/language.h"
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
#include "ir/ts/tsIntersectionType.h"
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
using namespace std::literals::string_literals;

ETSParser::ETSParser(Program *program, const CompilerOptions &options, ParserStatus status)
    : TypedParser(program, options, status), globalProgram_(GetProgram())
{
    importPathManager_ = std::make_unique<util::ImportPathManager>(Allocator(), ArkTSConfig(), GetOptions().stdLib);
}

bool ETSParser::IsETSParser() const noexcept
{
    return true;
}

const ArenaMap<util::StringView, util::ImportPathManager::ModuleInfo> &ETSParser::ModuleList() const
{
    return importPathManager_->ModuleList();
}

std::unique_ptr<lexer::Lexer> ETSParser::InitLexer(const SourceFile &sourceFile)
{
    GetProgram()->SetSource(sourceFile);
    auto lexer = std::make_unique<lexer::ETSLexer>(&GetContext());
    SetLexer(lexer.get());
    return lexer;
}

void ETSParser::ParseProgram(ScriptKind kind)
{
    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();
    Lexer()->NextToken();
    GetProgram()->SetKind(kind);

    if (GetProgram()->SourceFilePath().Utf8()[0] == '@') {
        // NOTE(user): handle multiple sourceFiles
    }

    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());
    auto decl = ParsePackageDeclaration();
    if (decl != nullptr) {
        statements.emplace_back(decl);
    }
    auto script = ParseETSGlobalScript(startLoc, statements);

    AddExternalSource(ParseSources());
    GetProgram()->VarBinder()->AsETSBinder()->SetModuleList(this->ModuleList());
    GetProgram()->SetAst(script);
}

ir::ETSScript *ETSParser::ParseETSGlobalScript(lexer::SourcePosition startLoc, ArenaVector<ir::Statement *> &statements)
{
    ETSNolintParser etsnolintParser(this);
    etsnolintParser.CollectETSNolints();

    auto imports = ParseImportDeclarations();
    statements.insert(statements.end(), imports.begin(), imports.end());

    auto topLevelStatements = ParseTopLevelDeclaration();
    statements.insert(statements.end(), topLevelStatements.begin(), topLevelStatements.end());

    etsnolintParser.ApplyETSNolintsToStatements(statements);

    auto *etsScript = AllocNode<ir::ETSScript>(Allocator(), std::move(statements), GetProgram());
    etsScript->SetRange({startLoc, Lexer()->GetToken().End()});
    return etsScript;
}

void ETSParser::AddExternalSource(const std::vector<Program *> &programs)
{
    for (auto *newProg : programs) {
        auto &extSources = globalProgram_->ExternalSources();

        const util::StringView name =
            newProg->Ast()->Statements().empty() ? newProg->FileName() : newProg->GetPackageName();
        if (extSources.count(name) == 0) {
            extSources.emplace(name, Allocator()->Adapter());
        }
        extSources.at(name).emplace_back(newProg);
    }
}

ArenaVector<ir::ETSImportDeclaration *> ETSParser::ParseDefaultSources(std::string_view srcFile,
                                                                       std::string_view importSrc)
{
    auto isp = InnerSourceParser(this);
    SourceFile source(srcFile, importSrc);
    auto lexer = InitLexer(source);

    Lexer()->NextToken();

    GetContext().Status() |= ParserStatus::IN_DEFAULT_IMPORTS;
    auto statements = ParseImportDeclarations();
    GetContext().Status() &= ~ParserStatus::IN_DEFAULT_IMPORTS;

    AddExternalSource(ParseSources());
    return statements;
}

std::vector<Program *> ETSParser::ParseSources()
{
    std::vector<Program *> programs;

    auto &parseList = importPathManager_->ParseList();

    // This parse list `paths` can grow in the meantime, so keep this index-based iteration
    // NOLINTNEXTLINE(modernize-loop-convert)
    for (size_t idx = 0; idx < parseList.size(); idx++) {
        // check if already parsed
        if (parseList[idx].isParsed) {
            continue;
        }
        std::ifstream inputStream(parseList[idx].sourcePath.Mutf8());
        const auto data = importPathManager_->GetImportData(parseList[idx].sourcePath, Extension());
        if (!data.hasDecl) {
            continue;
        }

        if (GetProgram()->SourceFilePath().Is(parseList[idx].sourcePath.Mutf8())) {
            break;
        }

        if (inputStream.fail()) {
            ThrowSyntaxError({"Failed to open file: ", parseList[idx].sourcePath.Mutf8()});
        }

        std::stringstream ss;
        ss << inputStream.rdbuf();
        auto externalSource = ss.str();

        auto currentLang = GetContext().SetLanguage(data.lang);
        auto extSrc = Allocator()->New<util::UString>(externalSource, Allocator());
        auto newProg = ParseSource(
            {parseList[idx].sourcePath.Utf8(), extSrc->View().Utf8(), parseList[idx].sourcePath.Utf8(), false});

        programs.emplace_back(newProg);
        GetContext().SetLanguage(currentLang);
    }

    return programs;
}

parser::Program *ETSParser::ParseSource(const SourceFile &sourceFile)
{
    importPathManager_->MarkAsParsed(sourceFile.filePath);
    auto *program = Allocator()->New<parser::Program>(Allocator(), GetProgram()->VarBinder());
    auto esp = ExternalSourceParser(this, program);
    auto lexer = InitLexer(sourceFile);

    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();
    Lexer()->NextToken();

    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());
    auto decl = ParsePackageDeclaration();
    if (decl != nullptr) {
        statements.emplace_back(decl);
    }
    auto script = ParseETSGlobalScript(startLoc, statements);
    program->SetAst(script);
    return program;
}

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
    if ((memberModifiers & (ir::ModifierFlags::EXPORT | ir::ModifierFlags::DEFAULT_EXPORT)) != 0U &&
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
            break;
        }
    }
    if (result != nullptr) {
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

static bool IsClassModifier(lexer::TokenType type)
{
    return type == lexer::TokenType::KEYW_STATIC || type == lexer::TokenType::KEYW_ABSTRACT ||
           type == lexer::TokenType::KEYW_FINAL;
}

ir::Statement *ETSParser::ParseIdentKeyword()
{
    const auto token = Lexer()->GetToken();
    ASSERT(token.Type() == lexer::TokenType::LITERAL_IDENT);
    switch (token.KeywordType()) {
        case lexer::TokenType::KEYW_STRUCT: {
            return ParseTypeDeclaration(false);
        }
        case lexer::TokenType::KEYW_TYPE: {
            return ParseTypeAliasDeclaration();
        }
        default: {
            break;
        }
    }
    return nullptr;
}

ir::ModifierFlags ETSParser::ParseClassModifiers()
{
    ir::ModifierFlags flags = ir::ModifierFlags::NONE;

    while (IsClassModifier(Lexer()->GetToken().KeywordType())) {
        ir::ModifierFlags currentFlag = ir::ModifierFlags::NONE;

        lexer::TokenFlags tokenFlags = Lexer()->GetToken().Flags();
        if ((tokenFlags & lexer::TokenFlags::HAS_ESCAPE) != 0) {
            ThrowSyntaxError("Keyword must not contain escaped characters");
        }

        switch (Lexer()->GetToken().KeywordType()) {
            case lexer::TokenType::KEYW_STATIC: {
                currentFlag = ir::ModifierFlags::STATIC;
                break;
            }
            case lexer::TokenType::KEYW_FINAL: {
                currentFlag = ir::ModifierFlags::FINAL;
                break;
            }
            case lexer::TokenType::KEYW_ABSTRACT: {
                currentFlag = ir::ModifierFlags::ABSTRACT;
                break;
            }
            default: {
                UNREACHABLE();
            }
        }

        if ((flags & currentFlag) != 0) {
            ThrowSyntaxError("Duplicated modifier is not allowed");
        }

        Lexer()->NextToken();
        flags |= currentFlag;
    }

    return flags;
}

std::tuple<ir::Expression *, ir::TSTypeParameterInstantiation *> ETSParser::ParseClassImplementsElement()
{
    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR |
                                           TypeAnnotationParsingOptions::IGNORE_FUNCTION_TYPE |
                                           TypeAnnotationParsingOptions::ALLOW_WILDCARD;
    return {ParseTypeReference(&options), nullptr};
}

ir::Expression *ETSParser::ParseSuperClassReference()
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_EXTENDS) {
        Lexer()->NextToken();

        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR |
                                               TypeAnnotationParsingOptions::IGNORE_FUNCTION_TYPE |
                                               TypeAnnotationParsingOptions::ALLOW_WILDCARD;
        return ParseTypeReference(&options);
    }

    return nullptr;
}

ir::TypeNode *ETSParser::ParseInterfaceExtendsElement()
{
    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR |
                                           TypeAnnotationParsingOptions::IGNORE_FUNCTION_TYPE |
                                           TypeAnnotationParsingOptions::ALLOW_WILDCARD;
    return ParseTypeReference(&options);
}

static bool IsClassMemberAccessModifier(lexer::TokenType type)
{
    return type == lexer::TokenType::KEYW_PUBLIC || type == lexer::TokenType::KEYW_PRIVATE ||
           type == lexer::TokenType::KEYW_PROTECTED || type == lexer::TokenType::KEYW_INTERNAL;
}

std::tuple<ir::ModifierFlags, bool> ETSParser::ParseClassMemberAccessModifiers()
{
    if (IsClassMemberAccessModifier(Lexer()->GetToken().Type())) {
        char32_t nextCp = Lexer()->Lookahead();
        if (!(nextCp != lexer::LEX_CHAR_EQUALS && nextCp != lexer::LEX_CHAR_COLON &&
              nextCp != lexer::LEX_CHAR_LEFT_PAREN)) {
            return {ir::ModifierFlags::NONE, false};
        }

        lexer::TokenFlags tokenFlags = Lexer()->GetToken().Flags();
        if ((tokenFlags & lexer::TokenFlags::HAS_ESCAPE) != 0) {
            ThrowSyntaxError("Keyword must not contain escaped characters");
        }

        ir::ModifierFlags accessFlag = ir::ModifierFlags::NONE;

        switch (Lexer()->GetToken().KeywordType()) {
            case lexer::TokenType::KEYW_PUBLIC: {
                accessFlag = ir::ModifierFlags::PUBLIC;
                break;
            }
            case lexer::TokenType::KEYW_PRIVATE: {
                accessFlag = ir::ModifierFlags::PRIVATE;
                break;
            }
            case lexer::TokenType::KEYW_PROTECTED: {
                accessFlag = ir::ModifierFlags::PROTECTED;
                break;
            }
            case lexer::TokenType::KEYW_INTERNAL: {
                Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
                if (Lexer()->GetToken().KeywordType() != lexer::TokenType::KEYW_PROTECTED) {
                    accessFlag = ir::ModifierFlags::INTERNAL;
                    return {accessFlag, true};
                }
                accessFlag = ir::ModifierFlags::INTERNAL_PROTECTED;
                break;
            }
            default: {
                UNREACHABLE();
            }
        }
        if (((GetContext().Status() & ParserStatus::FUNCTION) != 0) &&
            (accessFlag == ir::ModifierFlags::PUBLIC || accessFlag == ir::ModifierFlags::PRIVATE ||
             accessFlag == ir::ModifierFlags::PROTECTED)) {
            ThrowSyntaxError("Local class declaration members can not have access modifies",
                             Lexer()->GetToken().Start());
        }

        Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
        return {accessFlag, true};
    }

    return {ir::ModifierFlags::PUBLIC, false};
}

static bool IsClassFieldModifier(lexer::TokenType type)
{
    return type == lexer::TokenType::KEYW_STATIC || type == lexer::TokenType::KEYW_READONLY;
}

ir::ModifierFlags ETSParser::ParseClassFieldModifiers(bool seenStatic)
{
    ir::ModifierFlags flags = seenStatic ? ir::ModifierFlags::STATIC : ir::ModifierFlags::NONE;

    while (IsClassFieldModifier(Lexer()->GetToken().KeywordType())) {
        char32_t nextCp = Lexer()->Lookahead();
        if (!(nextCp != lexer::LEX_CHAR_EQUALS && nextCp != lexer::LEX_CHAR_COLON)) {
            return flags;
        }

        ir::ModifierFlags currentFlag;

        lexer::TokenFlags tokenFlags = Lexer()->GetToken().Flags();
        if ((tokenFlags & lexer::TokenFlags::HAS_ESCAPE) != 0) {
            ThrowSyntaxError("Keyword must not contain escaped characters");
        }

        switch (Lexer()->GetToken().KeywordType()) {
            case lexer::TokenType::KEYW_STATIC: {
                currentFlag = ir::ModifierFlags::STATIC;
                break;
            }
            case lexer::TokenType::KEYW_READONLY: {
                // NOTE(OCs): Use ir::ModifierFlags::READONLY once compiler is ready for it.
                currentFlag = ir::ModifierFlags::CONST;
                break;
            }
            default: {
                UNREACHABLE();
            }
        }

        if ((flags & currentFlag) != 0) {
            ThrowSyntaxError("Duplicated modifier is not allowed");
        }

        Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
        flags |= currentFlag;
    }

    return flags;
}

bool ETSParser::IsClassMethodModifier(lexer::TokenType type) noexcept
{
    switch (type) {
        case lexer::TokenType::KEYW_STATIC:
        case lexer::TokenType::KEYW_FINAL:
        case lexer::TokenType::KEYW_NATIVE:
        case lexer::TokenType::KEYW_ASYNC:
        case lexer::TokenType::KEYW_OVERRIDE:
        case lexer::TokenType::KEYW_ABSTRACT: {
            return true;
        }
        default: {
            break;
        }
    }

    return false;
}

ir::ModifierFlags ETSParser::ParseClassMethodModifiers(bool seenStatic)
{
    ir::ModifierFlags flags = seenStatic ? ir::ModifierFlags::STATIC : ir::ModifierFlags::NONE;

    while (IsClassMethodModifier(Lexer()->GetToken().KeywordType())) {
        char32_t nextCp = Lexer()->Lookahead();
        if (!(nextCp != lexer::LEX_CHAR_LEFT_PAREN)) {
            return flags;
        }

        ir::ModifierFlags currentFlag = ir::ModifierFlags::NONE;

        lexer::TokenFlags tokenFlags = Lexer()->GetToken().Flags();
        if ((tokenFlags & lexer::TokenFlags::HAS_ESCAPE) != 0) {
            ThrowSyntaxError("Keyword must not contain escaped characters");
        }

        switch (Lexer()->GetToken().KeywordType()) {
            case lexer::TokenType::KEYW_STATIC: {
                currentFlag = ir::ModifierFlags::STATIC;
                break;
            }
            case lexer::TokenType::KEYW_FINAL: {
                currentFlag = ir::ModifierFlags::FINAL;
                break;
            }
            case lexer::TokenType::KEYW_NATIVE: {
                currentFlag = ir::ModifierFlags::NATIVE;
                break;
            }
            case lexer::TokenType::KEYW_ASYNC: {
                currentFlag = ir::ModifierFlags::ASYNC;
                break;
            }
            case lexer::TokenType::KEYW_OVERRIDE: {
                currentFlag = ir::ModifierFlags::OVERRIDE;
                break;
            }
            case lexer::TokenType::KEYW_ABSTRACT: {
                currentFlag = ir::ModifierFlags::ABSTRACT;
                break;
            }
            case lexer::TokenType::KEYW_DECLARE: {
                currentFlag = ir::ModifierFlags::DECLARE;
                break;
            }
            default: {
                UNREACHABLE();
            }
        }

        if ((flags & currentFlag) != 0) {
            ThrowSyntaxError("Duplicated modifier is not allowed");
        }

        Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
        flags |= currentFlag;
        if ((flags & ir::ModifierFlags::ASYNC) != 0 && (flags & ir::ModifierFlags::NATIVE) != 0) {
            ThrowSyntaxError("Native method cannot be async");
        }
    }

    return flags;
}

// NOLINTNEXTLINE(google-default-arguments)
void ETSParser::ParseClassFieldDefinition(ir::Identifier *fieldName, ir::ModifierFlags modifiers,
                                          ArenaVector<ir::AstNode *> *declarations)
{
    lexer::SourcePosition endLoc = fieldName->End();
    ir::TypeNode *typeAnnotation = nullptr;
    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
    bool optionalField = false;

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_QUESTION_MARK) {
        Lexer()->NextToken();  // eat '?'
        optionalField = true;
    }
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        typeAnnotation = ParseTypeAnnotation(&options);
        endLoc = typeAnnotation->End();
    }

    ir::Expression *initializer = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        Lexer()->NextToken();  // eat '='
        initializer = ParseExpression();
    } else if (typeAnnotation == nullptr) {
        ThrowSyntaxError("Field type annotation expected");
    }

    bool isDeclare = (modifiers & ir::ModifierFlags::DECLARE) != 0;

    if (isDeclare && initializer != nullptr) {
        ThrowSyntaxError("Initializers are not allowed in ambient contexts.");
    }

    auto *field = AllocNode<ir::ClassProperty>(fieldName, initializer, typeAnnotation, modifiers, Allocator(), false);
    field->SetRange({fieldName->Start(), initializer != nullptr ? initializer->End() : endLoc});
    if (optionalField) {
        field->AddModifier(ir::ModifierFlags::OPTIONAL);
    }

    declarations->push_back(field);

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
        Lexer()->NextToken();
        ir::Identifier *nextName = ExpectIdentifier(false, true);
        ParseClassFieldDefinition(nextName, modifiers, declarations);
    }
}

ir::MethodDefinition *ETSParser::ParseClassMethodDefinition(ir::Identifier *methodName, ir::ModifierFlags modifiers,
                                                            ir::Identifier *className)
{
    auto newStatus = ParserStatus::NEED_RETURN_TYPE | ParserStatus::ALLOW_SUPER;
    auto methodKind = ir::MethodDefinitionKind::METHOD;

    if (className != nullptr) {
        methodKind = ir::MethodDefinitionKind::EXTENSION_METHOD;
        newStatus |= ParserStatus::IN_EXTENSION_FUNCTION;
    }

    if ((modifiers & ir::ModifierFlags::CONSTRUCTOR) != 0) {
        newStatus = ParserStatus::CONSTRUCTOR_FUNCTION | ParserStatus::ALLOW_SUPER | ParserStatus::ALLOW_SUPER_CALL;
        methodKind = ir::MethodDefinitionKind::CONSTRUCTOR;
    }

    if ((modifiers & ir::ModifierFlags::ASYNC) != 0) {
        newStatus |= ParserStatus::ASYNC_FUNCTION;
    }

    if ((modifiers & ir::ModifierFlags::STATIC) == 0) {
        newStatus |= ParserStatus::ALLOW_THIS_TYPE;
    }

    ir::ScriptFunction *func = ParseFunction(newStatus, className);
    func->SetIdent(methodName);
    auto *funcExpr = AllocNode<ir::FunctionExpression>(func);
    funcExpr->SetRange(func->Range());
    func->AddModifier(modifiers);

    if (className != nullptr) {
        func->AddFlag(ir::ScriptFunctionFlags::INSTANCE_EXTENSION_METHOD);
    }
    auto *method = AllocNode<ir::MethodDefinition>(methodKind, methodName->Clone(Allocator(), nullptr)->AsExpression(),
                                                   funcExpr, modifiers, Allocator(), false);
    method->SetRange(funcExpr->Range());
    func->Id()->SetReference();
    return method;
}

ir::ScriptFunction *ETSParser::ParseFunction(ParserStatus newStatus, ir::Identifier *className)
{
    FunctionContext functionContext(this, newStatus | ParserStatus::FUNCTION);
    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();
    auto [signature, throwMarker] = ParseFunctionSignature(newStatus, className);

    ir::AstNode *body = nullptr;
    lexer::SourcePosition endLoc = startLoc;
    bool isOverload = false;
    bool isArrow = (newStatus & ParserStatus::ARROW_FUNCTION) != 0;

    if ((newStatus & ParserStatus::ASYNC_FUNCTION) != 0) {
        functionContext.AddFlag(ir::ScriptFunctionFlags::ASYNC);
    }

    if (isArrow) {
        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_ARROW) {
            ThrowSyntaxError("'=>' expected");
        }

        functionContext.AddFlag(ir::ScriptFunctionFlags::ARROW);
        Lexer()->NextToken();
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        std::tie(std::ignore, body, endLoc, isOverload) =
            ParseFunctionBody(signature.Params(), newStatus, GetContext().Status());
    } else if (isArrow) {
        body = ParseExpression();
        endLoc = body->AsExpression()->End();
        functionContext.AddFlag(ir::ScriptFunctionFlags::EXPRESSION);
    }

    if ((GetContext().Status() & ParserStatus::FUNCTION_HAS_RETURN_STATEMENT) != 0) {
        functionContext.AddFlag(ir::ScriptFunctionFlags::HAS_RETURN);
        GetContext().Status() ^= ParserStatus::FUNCTION_HAS_RETURN_STATEMENT;
    }
    functionContext.AddFlag(throwMarker);

    // clang-format off
    auto *funcNode = AllocNode<ir::ScriptFunction>(
        Allocator(), ir::ScriptFunction::ScriptFunctionData {
                        body, std::move(signature), functionContext.Flags(), {}, false, GetContext().GetLanguage()});
    // clang-format on

    funcNode->SetRange({startLoc, endLoc});

    return funcNode;
}

ir::MethodDefinition *ETSParser::ParseClassMethod(ClassElementDescriptor *desc,
                                                  const ArenaVector<ir::AstNode *> &properties,
                                                  ir::Expression *propName, lexer::SourcePosition *propEnd)
{
    if (desc->methodKind != ir::MethodDefinitionKind::SET &&
        (desc->newStatus & ParserStatus::CONSTRUCTOR_FUNCTION) == 0) {
        desc->newStatus |= ParserStatus::NEED_RETURN_TYPE;
    }

    ir::ScriptFunction *func = ParseFunction(desc->newStatus);
    if (propName->IsIdentifier()) {
        func->SetIdent(propName->AsIdentifier()->Clone(Allocator(), nullptr));
        func->Id()->SetReference();
    }

    auto *funcExpr = AllocNode<ir::FunctionExpression>(func);
    funcExpr->SetRange(func->Range());

    if (desc->methodKind == ir::MethodDefinitionKind::SET) {
        ValidateClassSetter(desc, properties, propName, func);
    } else if (desc->methodKind == ir::MethodDefinitionKind::GET) {
        ValidateClassGetter(desc, properties, propName, func);
    }

    *propEnd = func->End();
    func->AddFlag(ir::ScriptFunctionFlags::METHOD);
    auto *method =
        AllocNode<ir::MethodDefinition>(desc->methodKind, propName->Clone(Allocator(), nullptr)->AsExpression(),
                                        funcExpr, desc->modifiers, Allocator(), desc->isComputed);
    method->SetRange(funcExpr->Range());

    return method;
}

std::tuple<bool, ir::BlockStatement *, lexer::SourcePosition, bool> ETSParser::ParseFunctionBody(
    [[maybe_unused]] const ArenaVector<ir::Expression *> &params, [[maybe_unused]] ParserStatus newStatus,
    [[maybe_unused]] ParserStatus contextStatus)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE);

    ir::BlockStatement *body = ParseBlockStatement();

    return {true, body, body->End(), false};
}

ir::TypeNode *ETSParser::ParseFunctionReturnType([[maybe_unused]] ParserStatus status)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        if ((status & ParserStatus::CONSTRUCTOR_FUNCTION) != 0U) {
            ThrowSyntaxError("Type annotation isn't allowed for constructor.");
        }
        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR |
                                               TypeAnnotationParsingOptions::CAN_BE_TS_TYPE_PREDICATE |
                                               TypeAnnotationParsingOptions::RETURN_TYPE;
        return ParseTypeAnnotation(&options);
    }

    return nullptr;
}

ir::ScriptFunctionFlags ETSParser::ParseFunctionThrowMarker(bool isRethrowsAllowed)
{
    ir::ScriptFunctionFlags throwMarker = ir::ScriptFunctionFlags::NONE;

    if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
        if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_THROWS) {
            Lexer()->NextToken();  // eat 'throws'
            throwMarker = ir::ScriptFunctionFlags::THROWS;
        } else if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_RETHROWS) {
            if (isRethrowsAllowed) {
                Lexer()->NextToken();  // eat 'rethrows'
                throwMarker = ir::ScriptFunctionFlags::RETHROWS;
            } else {
                ThrowSyntaxError("Only 'throws' can be used with function types");
            }
        }
    }

    return throwMarker;
}

void ETSParser::ValidateLabeledStatement(lexer::TokenType type)
{
    if (type != lexer::TokenType::KEYW_DO && type != lexer::TokenType::KEYW_WHILE &&
        type != lexer::TokenType::KEYW_FOR && type != lexer::TokenType::KEYW_SWITCH) {
        ThrowSyntaxError("Label must be followed by a loop statement", Lexer()->GetToken().Start());
    }
}

ir::AstNode *ETSParser::ParseInnerTypeDeclaration(ir::ModifierFlags memberModifiers, lexer::LexerPosition savedPos,
                                                  bool isStepToken, bool seenStatic)
{
    if ((GetContext().Status() & ParserStatus::IN_NAMESPACE) == 0) {
        ThrowSyntaxError("Local type declaration (class, struct, interface and enum) support is not yet implemented.");
    }

    // remove saved_pos nolint
    Lexer()->Rewind(savedPos);
    if (isStepToken) {
        Lexer()->NextToken();
    }

    Lexer()->GetToken().SetTokenType(Lexer()->GetToken().KeywordType());
    ir::AstNode *typeDecl = ParseTypeDeclaration(true);
    memberModifiers &= (ir::ModifierFlags::PUBLIC | ir::ModifierFlags::PROTECTED | ir::ModifierFlags::PRIVATE |
                        ir::ModifierFlags::INTERNAL);
    typeDecl->AddModifier(memberModifiers);

    if (!seenStatic) {
        if (typeDecl->IsClassDeclaration()) {
            typeDecl->AsClassDeclaration()->Definition()->AsClassDefinition()->SetInnerModifier();
        } else if (typeDecl->IsETSStructDeclaration()) {
            typeDecl->AsETSStructDeclaration()->Definition()->AsClassDefinition()->SetInnerModifier();
        }
    }

    return typeDecl;
}

ir::AstNode *ETSParser::ParseInnerConstructorDeclaration(ir::ModifierFlags memberModifiers,
                                                         const lexer::SourcePosition &startLoc)
{
    if ((GetContext().Status() & ParserStatus::IN_NAMESPACE) != 0) {
        ThrowSyntaxError({"Namespaces should not have a constructor"});
    }
    if ((memberModifiers & ir::ModifierFlags::ASYNC) != 0) {
        ThrowSyntaxError({"Constructor should not be async."});
    }
    auto *memberName = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    memberModifiers |= ir::ModifierFlags::CONSTRUCTOR;
    Lexer()->NextToken();
    auto *classMethod = ParseClassMethodDefinition(memberName, memberModifiers);
    classMethod->SetStart(startLoc);

    return classMethod;
}

ir::AstNode *ETSParser::ParseInnerRest(const ArenaVector<ir::AstNode *> &properties,
                                       ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags memberModifiers,
                                       const lexer::SourcePosition &startLoc)
{
    if (Lexer()->Lookahead() != lexer::LEX_CHAR_LEFT_PAREN && Lexer()->Lookahead() != lexer::LEX_CHAR_LESS_THAN &&
        (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_GET ||
         Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_SET)) {
        return ParseClassGetterSetterMethod(properties, modifiers, memberModifiers);
    }

    if ((GetContext().Status() & ParserStatus::IN_NAMESPACE) != 0) {
        auto type = Lexer()->GetToken().Type();
        if (type == lexer::TokenType::KEYW_FUNCTION || type == lexer::TokenType::KEYW_LET ||
            type == lexer::TokenType::KEYW_CONST) {
            Lexer()->NextToken();
        }
    }

    auto *memberName = ExpectIdentifier();

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS ||
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        auto *classMethod = ParseClassMethodDefinition(memberName, memberModifiers, nullptr);
        classMethod->SetStart(startLoc);
        return classMethod;
    }

    ArenaVector<ir::AstNode *> fieldDeclarations(Allocator()->Adapter());
    auto *placeholder = AllocNode<ir::TSInterfaceBody>(std::move(fieldDeclarations));
    ParseClassFieldDefinition(memberName, memberModifiers, placeholder->BodyPtr());
    return placeholder;
}

ir::AstNode *ETSParser::ParseClassElement(const ArenaVector<ir::AstNode *> &properties,
                                          ir::ClassDefinitionModifiers modifiers,
                                          [[maybe_unused]] ir::ModifierFlags flags)
{
    auto startLoc = Lexer()->GetToken().Start();
    auto savedPos = Lexer()->Save();  // NOLINT(clang-analyzer-deadcode.DeadStores)

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_STATIC &&
        Lexer()->Lookahead() == lexer::LEX_CHAR_LEFT_BRACE) {
        return ParseClassStaticBlock();
    }

    auto [memberModifiers, isStepToken] = ParseClassMemberAccessModifiers();

    if (InAmbientContext()) {
        memberModifiers |= ir::ModifierFlags::DECLARE;
    }

    bool seenStatic = false;
    char32_t nextCp = Lexer()->Lookahead();
    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_STATIC && nextCp != lexer::LEX_CHAR_EQUALS &&
        nextCp != lexer::LEX_CHAR_COLON && nextCp != lexer::LEX_CHAR_LEFT_PAREN &&
        nextCp != lexer::LEX_CHAR_LESS_THAN) {
        Lexer()->NextToken();
        memberModifiers |= ir::ModifierFlags::STATIC;
        seenStatic = true;
    }

    if (IsClassFieldModifier(Lexer()->GetToken().KeywordType())) {
        memberModifiers |= ParseClassFieldModifiers(seenStatic);
    } else if (IsClassMethodModifier(Lexer()->GetToken().Type())) {
        memberModifiers |= ParseClassMethodModifiers(seenStatic);
    }

    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::KEYW_INTERFACE:
        case lexer::TokenType::KEYW_CLASS:
        case lexer::TokenType::KEYW_ENUM: {
            return ParseInnerTypeDeclaration(memberModifiers, savedPos, isStepToken, seenStatic);
        }
        case lexer::TokenType::KEYW_CONSTRUCTOR: {
            return ParseInnerConstructorDeclaration(memberModifiers, startLoc);
        }
        case lexer::TokenType::KEYW_PUBLIC:
        case lexer::TokenType::KEYW_PRIVATE:
        case lexer::TokenType::KEYW_PROTECTED: {
            ThrowSyntaxError("Access modifier must precede field and method modifiers.");
            break;
        }
        default: {
            break;
        }
    }

    return ParseInnerRest(properties, modifiers, memberModifiers, startLoc);
}

ir::MethodDefinition *ETSParser::ParseClassGetterSetterMethod(const ArenaVector<ir::AstNode *> &properties,
                                                              const ir::ClassDefinitionModifiers modifiers,
                                                              const ir::ModifierFlags memberModifiers)
{
    ClassElementDescriptor desc(Allocator());
    desc.methodKind = Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_GET ? ir::MethodDefinitionKind::GET
                                                                                      : ir::MethodDefinitionKind::SET;
    Lexer()->NextToken();  // eat get/set
    auto *methodName = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    if (desc.methodKind == ir::MethodDefinitionKind::GET) {
        methodName->SetAccessor();
    } else {
        methodName->SetMutator();
    }

    Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);

    desc.newStatus = ParserStatus::ALLOW_SUPER;
    desc.hasSuperClass = (modifiers & ir::ClassDefinitionModifiers::HAS_SUPER) != 0U;
    desc.propStart = Lexer()->GetToken().Start();
    desc.modifiers = memberModifiers;

    lexer::SourcePosition propEnd = methodName->End();
    ir::MethodDefinition *method = ParseClassMethod(&desc, properties, methodName, &propEnd);
    method->Function()->AddModifier(desc.modifiers);
    method->SetRange({desc.propStart, propEnd});
    if (desc.methodKind == ir::MethodDefinitionKind::GET) {
        method->Function()->AddFlag(ir::ScriptFunctionFlags::GETTER);
    } else {
        method->Function()->AddFlag(ir::ScriptFunctionFlags::SETTER);
    }

    return method;
}

ir::MethodDefinition *ETSParser::ParseInterfaceGetterSetterMethod(const ir::ModifierFlags modifiers)
{
    auto methodKind = Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_GET ? ir::MethodDefinitionKind::GET
                                                                                      : ir::MethodDefinitionKind::SET;
    Lexer()->NextToken();  // eat get/set
    ExpectToken(lexer::TokenType::LITERAL_IDENT, false);
    ir::MethodDefinition *method = ParseInterfaceMethod(modifiers, methodKind);
    method->AddModifier(ir::ModifierFlags::PUBLIC);
    method->SetRange({Lexer()->GetToken().Start(), method->Id()->End()});
    if (methodKind == ir::MethodDefinitionKind::GET) {
        method->Id()->SetAccessor();
        method->Function()->AddFlag(ir::ScriptFunctionFlags::GETTER);
    } else {
        method->Id()->SetMutator();
        method->Function()->AddFlag(ir::ScriptFunctionFlags::SETTER);
    }
    method->AddModifier(ir::ModifierFlags::PUBLIC);

    method->Function()->SetIdent(method->Id()->Clone(Allocator(), nullptr));
    method->Function()->AddModifier(method->Modifiers());

    return method;
}

ir::Statement *ETSParser::ParseTypeDeclarationAbstractFinal(bool allowStatic, ir::ClassDefinitionModifiers modifiers)
{
    auto flags = ParseClassModifiers();
    if (allowStatic && (flags & ir::ModifierFlags::STATIC) == 0U) {
        modifiers |= ir::ClassDefinitionModifiers::INNER;
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_CLASS) {
        return ParseClassDeclaration(modifiers, flags);
    }

    if (IsStructKeyword()) {
        return ParseStructDeclaration(modifiers, flags);
    }

    ThrowUnexpectedToken(Lexer()->GetToken().Type());
}

ir::Statement *ETSParser::ParseTypeDeclaration(bool allowStatic)
{
    auto savedPos = Lexer()->Save();

    auto modifiers = ir::ClassDefinitionModifiers::ID_REQUIRED | ir::ClassDefinitionModifiers::CLASS_DECL;

    auto tokenType = Lexer()->GetToken().Type();
    switch (tokenType) {
        case lexer::TokenType::KEYW_STATIC: {
            if (!allowStatic) {
                ThrowUnexpectedToken(Lexer()->GetToken().Type());
            }

            Lexer()->NextToken();

            if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_INTERFACE) {
                return ParseInterfaceDeclaration(true);
            }

            Lexer()->Rewind(savedPos);
            [[fallthrough]];
        }
        case lexer::TokenType::KEYW_ABSTRACT:
        case lexer::TokenType::KEYW_FINAL: {
            return ParseTypeDeclarationAbstractFinal(allowStatic, modifiers);
        }
        case lexer::TokenType::KEYW_ENUM: {
            return ParseEnumDeclaration(false);
        }
        case lexer::TokenType::KEYW_INTERFACE: {
            return ParseInterfaceDeclaration(false);
        }
        case lexer::TokenType::KEYW_NAMESPACE: {
            if (!InAmbientContext()) {
                ThrowSyntaxError("Namespaces are declare only");
            }
            GetContext().Status() |= ParserStatus::IN_NAMESPACE;
            auto *ns = ParseClassDeclaration(modifiers, ir::ModifierFlags::STATIC);
            GetContext().Status() &= ~ParserStatus::IN_NAMESPACE;
            return ns;
        }
        case lexer::TokenType::KEYW_CLASS: {
            return ParseClassDeclaration(modifiers);
        }
        case lexer::TokenType::KEYW_TYPE: {
            return ParseTypeAliasDeclaration();
        }
        case lexer::TokenType::LITERAL_IDENT: {
            if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_STRUCT) {
                return ParseStructDeclaration(modifiers);
            }
            [[fallthrough]];
        }
        case lexer::TokenType::LITERAL_NUMBER:
        case lexer::TokenType::LITERAL_NULL:
        case lexer::TokenType::KEYW_UNDEFINED:
        case lexer::TokenType::LITERAL_STRING:
        case lexer::TokenType::LITERAL_FALSE:
        case lexer::TokenType::LITERAL_TRUE:
        case lexer::TokenType::LITERAL_CHAR: {
            std::string errMsg("Cannot used in global scope '");

            std::string text = tokenType == lexer::TokenType::LITERAL_CHAR
                                   ? util::Helpers::UTF16toUTF8(Lexer()->GetToken().Utf16())
                                   : Lexer()->GetToken().Ident().Mutf8();

            if ((Lexer()->GetToken().Flags() & lexer::TokenFlags::HAS_ESCAPE) == 0) {
                errMsg.append(text);
            } else {
                errMsg.append(util::Helpers::CreateEscapedString(text));
            }

            errMsg.append("'");
            ThrowSyntaxError(errMsg.c_str());
        }
        default: {
            ThrowUnexpectedToken(Lexer()->GetToken().Type());
        }
    }
}

ir::TSTypeAliasDeclaration *ETSParser::ParseTypeAliasDeclaration()
{
    ASSERT(Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_TYPE);

    if ((GetContext().Status() & parser::ParserStatus::FUNCTION) != 0U) {
        ThrowSyntaxError("Type alias is allowed only as top-level declaration");
    }

    lexer::SourcePosition typeStart = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat type keyword

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Identifier expected");
    }

    if (Lexer()->GetToken().IsReservedTypeName()) {
        std::string errMsg("Type alias name cannot be '");
        errMsg.append(TokenToString(Lexer()->GetToken().KeywordType()));
        errMsg.append("'");
        ThrowSyntaxError(errMsg.c_str());
    }

    const util::StringView ident = Lexer()->GetToken().Ident();
    auto *id = AllocNode<ir::Identifier>(ident, Allocator());
    id->SetRange(Lexer()->GetToken().Loc());

    auto *typeAliasDecl = AllocNode<ir::TSTypeAliasDeclaration>(Allocator(), id);

    Lexer()->NextToken();  // eat alias name

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        auto options =
            TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::ALLOW_DECLARATION_SITE_VARIANCE;
        ir::TSTypeParameterDeclaration *params = ParseTypeParameterDeclaration(&options);
        typeAliasDecl->SetTypeParameters(params);
        params->SetParent(typeAliasDecl);
    }

    if (!Lexer()->TryEatTokenType(lexer::TokenType::PUNCTUATOR_SUBSTITUTION)) {
        ThrowSyntaxError("'=' expected");
    }

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
    ir::TypeNode *typeAnnotation = ParseTypeAnnotation(&options);
    typeAliasDecl->SetTsTypeAnnotation(typeAnnotation);
    typeAliasDecl->SetRange({typeStart, Lexer()->GetToken().End()});
    typeAnnotation->SetParent(typeAliasDecl);

    return typeAliasDecl;
}

ir::TSInterfaceDeclaration *ETSParser::ParseInterfaceBody(ir::Identifier *name, bool isStatic)
{
    GetContext().Status() |= ParserStatus::ALLOW_THIS_TYPE;

    ir::TSTypeParameterDeclaration *typeParamDecl = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        auto options =
            TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::ALLOW_DECLARATION_SITE_VARIANCE;
        typeParamDecl = ParseTypeParameterDeclaration(&options);
    }

    ArenaVector<ir::TSInterfaceHeritage *> extends(Allocator()->Adapter());
    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_EXTENDS) {
        extends = ParseInterfaceExtendsClause();
    }

    lexer::SourcePosition bodyStart = Lexer()->GetToken().Start();
    auto members = ParseTypeLiteralOrInterface();

    for (auto &member : members) {
        if (member->Type() == ir::AstNodeType::CLASS_DECLARATION ||
            member->Type() == ir::AstNodeType::STRUCT_DECLARATION ||
            member->Type() == ir::AstNodeType::TS_ENUM_DECLARATION ||
            member->Type() == ir::AstNodeType::TS_INTERFACE_DECLARATION) {
            ThrowSyntaxError(
                "Local type declaration (class, struct, interface and enum) support is not yet implemented.");
        }
    }

    auto *body = AllocNode<ir::TSInterfaceBody>(std::move(members));
    body->SetRange({bodyStart, Lexer()->GetToken().End()});

    const auto isExternal = IsExternal();
    auto *interfaceDecl = AllocNode<ir::TSInterfaceDeclaration>(
        Allocator(), name, typeParamDecl, body, std::move(extends), isStatic, isExternal, GetContext().GetLanguage());

    Lexer()->NextToken();
    GetContext().Status() &= ~ParserStatus::ALLOW_THIS_TYPE;

    return interfaceDecl;
}

ir::Statement *ETSParser::ParseInterfaceDeclaration(bool isStatic)
{
    lexer::SourcePosition interfaceStart = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat interface keyword

    auto *id = ExpectIdentifier(false, true);

    auto *declNode = ParseInterfaceBody(id, isStatic);

    declNode->SetRange({interfaceStart, Lexer()->GetToken().End()});
    return declNode;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Statement *ETSParser::ParseEnumDeclaration(bool isConst, bool isStatic)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::KEYW_ENUM);

    if ((GetContext().Status() & parser::ParserStatus::FUNCTION) != 0U) {
        ThrowSyntaxError("Local enum declaration support is not yet implemented.");
    }

    lexer::SourcePosition enumStart = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat enum keyword

    auto *key = ExpectIdentifier(false, true);

    auto *declNode = ParseEnumMembers(key, enumStart, isConst, isStatic);

    return declNode;
}

ir::Expression *ETSParser::ParseLaunchExpression(ExpressionParseFlags flags)
{
    lexer::SourcePosition start = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat launch

    ir::Expression *expr = ParseLeftHandSideExpression(flags);
    if (!expr->IsCallExpression()) {
        ThrowSyntaxError("Only call expressions are allowed after 'launch'", expr->Start());
    }
    auto call = expr->AsCallExpression();
    auto *launchExpression = AllocNode<ir::ETSLaunchExpression>(call);
    launchExpression->SetRange({start, call->End()});

    return launchExpression;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::ClassDefinition *ETSParser::ParseClassDefinition(ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags flags)
{
    Lexer()->NextToken();

    ir::Identifier *identNode = ParseClassIdent(modifiers);

    ir::TSTypeParameterDeclaration *typeParamDecl = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        auto options =
            TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::ALLOW_DECLARATION_SITE_VARIANCE;
        typeParamDecl = ParseTypeParameterDeclaration(&options);
    }

    // Parse SuperClass
    auto [superClass, superTypeParams] = ParseSuperClass();

    if (superClass != nullptr) {
        modifiers |= ir::ClassDefinitionModifiers::HAS_SUPER;
        GetContext().Status() |= ParserStatus::ALLOW_SUPER;
    }

    if (InAmbientContext()) {
        flags |= ir::ModifierFlags::DECLARE;
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

    auto *classDefinition = AllocNode<ir::ClassDefinition>(
        util::StringView(), identNode, typeParamDecl, superTypeParams, std::move(implements), ctor, superClass,
        std::move(properties), modifiers, flags, GetContext().GetLanguage());

    classDefinition->SetRange(bodyRange);

    GetContext().Status() &= ~ParserStatus::ALLOW_SUPER;

    return classDefinition;
}

static bool IsInterfaceMethodModifier(lexer::TokenType type)
{
    // NOTE (psiket) Rewrite this
    return type == lexer::TokenType::KEYW_STATIC || type == lexer::TokenType::KEYW_PRIVATE ||
           type == lexer::TokenType::KEYW_PROTECTED || type == lexer::TokenType::KEYW_PUBLIC;
}

ir::ModifierFlags ETSParser::ParseInterfaceMethodModifiers()
{
    ir::ModifierFlags flags = ir::ModifierFlags::NONE;

    while (IsInterfaceMethodModifier(Lexer()->GetToken().Type())) {
        ir::ModifierFlags currentFlag = ir::ModifierFlags::NONE;

        if ((GetContext().Status() & ParserStatus::FUNCTION) != 0) {
            if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_PUBLIC ||
                Lexer()->GetToken().Type() == lexer::TokenType::KEYW_PROTECTED ||
                Lexer()->GetToken().Type() == lexer::TokenType::KEYW_PRIVATE) {
                ThrowSyntaxError("Local interface declaration members can not have access modifies",
                                 Lexer()->GetToken().Start());
            }
        } else if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_PUBLIC ||
                   Lexer()->GetToken().Type() == lexer::TokenType::KEYW_PROTECTED) {
            break;
        }
        switch (Lexer()->GetToken().Type()) {
            case lexer::TokenType::KEYW_STATIC: {
                currentFlag = ir::ModifierFlags::STATIC;
                break;
            }
            case lexer::TokenType::KEYW_PRIVATE: {
                currentFlag = ir::ModifierFlags::PRIVATE;
                break;
            }
            default: {
                UNREACHABLE();
            }
        }

        char32_t nextCp = Lexer()->Lookahead();
        if (nextCp == lexer::LEX_CHAR_COLON || nextCp == lexer::LEX_CHAR_LEFT_PAREN ||
            nextCp == lexer::LEX_CHAR_EQUALS) {
            break;
        }

        if ((flags & currentFlag) != 0) {
            ThrowSyntaxError("Duplicated modifier is not allowed");
        }

        Lexer()->NextToken();
        flags |= currentFlag;
    }

    return flags;
}

ir::ClassProperty *ETSParser::ParseInterfaceField()
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT);
    auto *name = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    name->SetRange(Lexer()->GetToken().Loc());
    Lexer()->NextToken();
    bool optionalField = false;

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_QUESTION_MARK) {
        Lexer()->NextToken();  // eat '?'
        optionalField = true;
    }

    ir::TypeNode *typeAnnotation = nullptr;
    if (!Lexer()->TryEatTokenType(lexer::TokenType::PUNCTUATOR_COLON)) {
        ThrowSyntaxError("Interface fields must have type annotation.");
    }
    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
    typeAnnotation = ParseTypeAnnotation(&options);

    name->SetTsTypeAnnotation(typeAnnotation);
    typeAnnotation->SetParent(name);

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_EQUAL) {
        ThrowSyntaxError("Initializers are not allowed on interface properties.");
    }

    ir::ModifierFlags fieldModifiers = ir::ModifierFlags::PUBLIC;

    if (InAmbientContext()) {
        fieldModifiers |= ir::ModifierFlags::DECLARE;
    }

    auto *field = AllocNode<ir::ClassProperty>(name, nullptr, typeAnnotation->Clone(Allocator(), nullptr),
                                               fieldModifiers, Allocator(), false);
    if (optionalField) {
        field->AddModifier(ir::ModifierFlags::OPTIONAL);
    }
    field->SetEnd(Lexer()->GetToken().End());

    return field;
}

ir::MethodDefinition *ETSParser::ParseInterfaceMethod(ir::ModifierFlags flags, ir::MethodDefinitionKind methodKind)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT);
    auto *name = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    name->SetRange(Lexer()->GetToken().Loc());
    Lexer()->NextToken();

    FunctionContext functionContext(this, ParserStatus::FUNCTION);

    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();

    auto [signature, throwMarker] = ParseFunctionSignature(ParserStatus::NEED_RETURN_TYPE);

    ir::BlockStatement *body = nullptr;

    bool isDeclare = InAmbientContext();
    if (isDeclare) {
        flags |= ir::ModifierFlags::DECLARE;
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        if (methodKind == ir::MethodDefinitionKind::SET || methodKind == ir::MethodDefinitionKind::GET) {
            ThrowSyntaxError("Getter and setter methods must be abstracts in the interface body", startLoc);
        }
        body = ParseBlockStatement();
    } else if ((flags & (ir::ModifierFlags::PRIVATE | ir::ModifierFlags::STATIC)) != 0 && !isDeclare) {
        ThrowSyntaxError("Private or static interface methods must have body", startLoc);
    }

    functionContext.AddFlag(throwMarker);

    if ((GetContext().Status() & ParserStatus::FUNCTION_HAS_RETURN_STATEMENT) != 0) {
        functionContext.AddFlag(ir::ScriptFunctionFlags::HAS_RETURN);
        GetContext().Status() ^= ParserStatus::FUNCTION_HAS_RETURN_STATEMENT;
    }

    auto *func = AllocNode<ir::ScriptFunction>(
        Allocator(), ir::ScriptFunction::ScriptFunctionData {body, std::move(signature), functionContext.Flags(), flags,
                                                             true, GetContext().GetLanguage()});

    if ((flags & ir::ModifierFlags::STATIC) == 0 && body == nullptr) {
        func->AddModifier(ir::ModifierFlags::ABSTRACT);
    }
    func->SetRange({startLoc, body != nullptr                           ? body->End()
                              : func->ReturnTypeAnnotation() != nullptr ? func->ReturnTypeAnnotation()->End()
                              : func->Params().empty()                  ? Lexer()->GetToken().End()
                                                                        : (*func->Params().end())->End()});

    auto *funcExpr = AllocNode<ir::FunctionExpression>(func);
    funcExpr->SetRange(func->Range());
    func->AddFlag(ir::ScriptFunctionFlags::METHOD);

    func->SetIdent(name);
    auto *method = AllocNode<ir::MethodDefinition>(ir::MethodDefinitionKind::METHOD,
                                                   name->Clone(Allocator(), nullptr)->AsExpression(), funcExpr, flags,
                                                   Allocator(), false);
    method->SetRange(funcExpr->Range());

    func->Id()->SetReference();

    ConsumeSemicolon(method);

    return method;
}

std::pair<bool, std::size_t> ETSParser::CheckDefaultParameters(const ir::ScriptFunction *const function) const
{
    bool hasDefaultParameter = false;
    bool hasRestParameter = false;
    std::size_t requiredParametersNumber = 0U;

    for (auto *const it : function->Params()) {
        auto const *const param = it->AsETSParameterExpression();

        if (param->IsRestParameter()) {
            hasRestParameter = true;
            continue;
        }

        if (hasRestParameter) {
            ThrowSyntaxError("Rest parameter should be the last one.", param->Start());
        }

        if (param->IsDefault()) {
            hasDefaultParameter = true;
            continue;
        }

        if (hasDefaultParameter) {
            ThrowSyntaxError("Required parameter follows default parameter(s).", param->Start());
        }

        ++requiredParametersNumber;
    }

    if (hasDefaultParameter && hasRestParameter) {
        ThrowSyntaxError("Both optional and rest parameters are not allowed in function's parameter list.",
                         function->Start());
    }

    return std::make_pair(hasDefaultParameter, requiredParametersNumber);
}

std::string ETSParser::PrimitiveTypeToName(ir::PrimitiveType type)
{
    switch (type) {
        case ir::PrimitiveType::BYTE:
            return "byte";
        case ir::PrimitiveType::INT:
            return "int";
        case ir::PrimitiveType::LONG:
            return "long";
        case ir::PrimitiveType::SHORT:
            return "short";
        case ir::PrimitiveType::FLOAT:
            return "float";
        case ir::PrimitiveType::DOUBLE:
            return "double";
        case ir::PrimitiveType::BOOLEAN:
            return "boolean";
        case ir::PrimitiveType::CHAR:
            return "char";
        case ir::PrimitiveType::VOID:
            return "void";
        default:
            UNREACHABLE();
    }
}

std::string ETSParser::GetNameForETSUnionType(const ir::TypeNode *typeAnnotation) const
{
    ASSERT(typeAnnotation->IsETSUnionType());
    std::string newstr;
    for (size_t i = 0; i < typeAnnotation->AsETSUnionType()->Types().size(); i++) {
        auto type = typeAnnotation->AsETSUnionType()->Types()[i];
        std::string str = GetNameForTypeNode(type);
        newstr += str;
        if (i != typeAnnotation->AsETSUnionType()->Types().size() - 1) {
            newstr += "|";
        }
    }
    return newstr;
}

std::string ETSParser::GetNameForTypeNode(const ir::TypeNode *typeAnnotation) const
{
    if (typeAnnotation->IsETSUnionType()) {
        return GetNameForETSUnionType(typeAnnotation);
    }
    if (typeAnnotation->IsETSPrimitiveType()) {
        return PrimitiveTypeToName(typeAnnotation->AsETSPrimitiveType()->GetPrimitiveType());
    }

    if (typeAnnotation->IsETSTypeReference()) {
        std::string typeParamNames;
        auto typeParam = typeAnnotation->AsETSTypeReference()->Part()->TypeParams();
        if (typeParam != nullptr && typeParam->IsTSTypeParameterInstantiation()) {
            typeParamNames = "<";
            auto paramList = typeParam->Params();
            for (auto param : paramList) {
                std::string typeParamName = GetNameForTypeNode(param);
                typeParamNames += typeParamName + ",";
            }
            typeParamNames.pop_back();
            typeParamNames += ">";
        }
        return typeAnnotation->AsETSTypeReference()->Part()->Name()->AsIdentifier()->Name().Mutf8() + typeParamNames;
    }

    if (typeAnnotation->IsETSFunctionType()) {
        std::string lambdaParams = " ";

        for (const auto *const param : typeAnnotation->AsETSFunctionType()->Params()) {
            lambdaParams += param->AsETSParameterExpression()->Ident()->Name().Mutf8();
            lambdaParams += ":";
            lambdaParams += GetNameForTypeNode(param->AsETSParameterExpression()->Ident()->TypeAnnotation());
            lambdaParams += ",";
        }

        lambdaParams.pop_back();
        const std::string returnTypeName = GetNameForTypeNode(typeAnnotation->AsETSFunctionType()->ReturnType());

        return "((" + lambdaParams + ") => " + returnTypeName + ")";
    }

    if (typeAnnotation->IsTSArrayType()) {
        // Note! array is required for the rest parameter.
        return GetNameForTypeNode(typeAnnotation->AsTSArrayType()->ElementType()) + "[]";
    }

    if (typeAnnotation->IsETSNullType()) {
        return "null";
    }

    if (typeAnnotation->IsETSUndefinedType()) {
        return "undefined";
    }

    UNREACHABLE();
}

void ETSParser::ValidateRestParameter(ir::Expression *param)
{
    if (param->IsETSParameterExpression()) {
        if (param->AsETSParameterExpression()->IsRestParameter()) {
            GetContext().Status() |= ParserStatus::HAS_COMPLEX_PARAM;

            if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
                ThrowSyntaxError("Rest parameter must be the last formal parameter.");
            }
        }
    }
}

ir::AstNode *ETSParser::ParseTypeLiteralOrInterfaceMember()
{
    auto startLoc = Lexer()->GetToken().Start();
    ir::ModifierFlags methodFlags = ParseInterfaceMethodModifiers();
    if (methodFlags != ir::ModifierFlags::NONE) {
        if ((methodFlags & ir::ModifierFlags::PRIVATE) == 0) {
            methodFlags |= ir::ModifierFlags::PUBLIC;
        }

        auto *method = ParseInterfaceMethod(methodFlags, ir::MethodDefinitionKind::METHOD);
        method->SetStart(startLoc);
        return method;
    }

    if (Lexer()->Lookahead() != lexer::LEX_CHAR_LEFT_PAREN && Lexer()->Lookahead() != lexer::LEX_CHAR_LESS_THAN &&
        (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_GET ||
         Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_SET)) {
        return ParseInterfaceGetterSetterMethod(methodFlags);
    }

    if (Lexer()->TryEatTokenKeyword(lexer::TokenType::KEYW_READONLY)) {
        auto *field = ParseInterfaceField();
        field->SetStart(startLoc);
        field->AddModifier(ir::ModifierFlags::READONLY);
        return field;
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
        char32_t nextCp = Lexer()->Lookahead();
        if (nextCp == lexer::LEX_CHAR_LEFT_PAREN || nextCp == lexer::LEX_CHAR_LESS_THAN) {
            auto *method = ParseInterfaceMethod(ir::ModifierFlags::PUBLIC, ir::MethodDefinitionKind::METHOD);
            method->SetStart(startLoc);
            return method;
        }

        auto *field = ParseInterfaceField();
        field->SetStart(startLoc);
        return field;
    }

    return ParseTypeDeclaration(true);
}

std::tuple<ir::Expression *, ir::TSTypeParameterInstantiation *> ETSParser::ParseTypeReferencePart(
    TypeAnnotationParsingOptions *options)
{
    ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS;

    if (((*options) & TypeAnnotationParsingOptions::POTENTIAL_CLASS_LITERAL) != 0) {
        flags |= ExpressionParseFlags::POTENTIAL_CLASS_LITERAL;
    }

    auto *typeName = ParseQualifiedName(flags);
    if (typeName == nullptr) {
        return {nullptr, nullptr};
    }

    if (((*options) & TypeAnnotationParsingOptions::POTENTIAL_CLASS_LITERAL) != 0 &&
        (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_CLASS || IsStructKeyword())) {
        return {typeName, nullptr};
    }

    ir::TSTypeParameterInstantiation *typeParamInst = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SHIFT ||
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SHIFT) {
            Lexer()->BackwardToken(lexer::TokenType::PUNCTUATOR_LESS_THAN, 1);
        }
        *options |= TypeAnnotationParsingOptions::ALLOW_WILDCARD;
        typeParamInst = ParseTypeParameterInstantiation(options);
        *options &= ~TypeAnnotationParsingOptions::ALLOW_WILDCARD;
    }

    return {typeName, typeParamInst};
}

ir::TypeNode *ETSParser::ParseTypeReference(TypeAnnotationParsingOptions *options)
{
    auto startPos = Lexer()->GetToken().Start();
    ir::ETSTypeReferencePart *typeRefPart = nullptr;

    while (true) {
        auto partPos = Lexer()->GetToken().Start();
        auto [typeName, typeParams] = ParseTypeReferencePart(options);
        if (typeName == nullptr) {
            return nullptr;
        }

        typeRefPart = AllocNode<ir::ETSTypeReferencePart>(typeName, typeParams, typeRefPart);
        typeRefPart->SetRange({partPos, Lexer()->GetToken().End()});

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_PERIOD) {
            break;
        }

        Lexer()->NextToken();

        if (((*options) & TypeAnnotationParsingOptions::POTENTIAL_CLASS_LITERAL) != 0 &&
            (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_CLASS || IsStructKeyword())) {
            break;
        }
    }

    auto *typeReference = AllocNode<ir::ETSTypeReference>(typeRefPart);
    typeReference->SetRange({startPos, Lexer()->GetToken().End()});
    return typeReference;
}

ir::TypeNode *ETSParser::ParseBaseTypeReference(TypeAnnotationParsingOptions *options)
{
    ir::TypeNode *typeAnnotation = nullptr;

    switch (Lexer()->GetToken().KeywordType()) {
        case lexer::TokenType::KEYW_BOOLEAN: {
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::BOOLEAN);
            break;
        }
        case lexer::TokenType::KEYW_BYTE: {
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::BYTE);
            break;
        }
        case lexer::TokenType::KEYW_CHAR: {
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::CHAR);
            break;
        }
        case lexer::TokenType::KEYW_DOUBLE: {
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::DOUBLE);
            break;
        }
        case lexer::TokenType::KEYW_FLOAT: {
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::FLOAT);
            break;
        }
        case lexer::TokenType::KEYW_INT: {
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::INT);
            break;
        }
        case lexer::TokenType::KEYW_LONG: {
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::LONG);
            break;
        }
        case lexer::TokenType::KEYW_SHORT: {
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::SHORT);
            break;
        }

        default: {
            break;
        }
    }

    return typeAnnotation;
}

ir::TypeNode *ETSParser::ParsePrimitiveType(TypeAnnotationParsingOptions *options, ir::PrimitiveType type)
{
    if (((*options) & TypeAnnotationParsingOptions::DISALLOW_PRIMARY_TYPE) != 0) {
        ThrowSyntaxError("Primitive type is not allowed here.");
    }

    auto *typeAnnotation = AllocNode<ir::ETSPrimitiveType>(type);
    typeAnnotation->SetRange(Lexer()->GetToken().Loc());
    Lexer()->NextToken();
    return typeAnnotation;
}

ir::TypeNode *ETSParser::ParseUnionType(ir::TypeNode *const firstType)
{
    ArenaVector<ir::TypeNode *> types(Allocator()->Adapter());
    types.push_back(firstType->AsTypeNode());

    while (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_BITWISE_OR) {
        Lexer()->NextToken();  // eat '|'

        auto options = TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::DISALLOW_UNION;
        types.push_back(ParseTypeAnnotation(&options));
    }

    auto const endLoc = types.back()->End();
    auto *const unionType = AllocNode<ir::ETSUnionType>(std::move(types));
    unionType->SetRange({firstType->Start(), endLoc});
    return unionType;
}

ir::TSIntersectionType *ETSParser::ParseIntersectionType(ir::Expression *type)
{
    auto startLoc = type->Start();
    ArenaVector<ir::Expression *> types(Allocator()->Adapter());
    types.push_back(type);
    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;

    while (true) {
        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_BITWISE_AND) {
            break;
        }

        Lexer()->NextToken();  // eat '&'
        types.push_back(ParseTypeReference(&options));
    }

    lexer::SourcePosition endLoc = types.back()->End();
    auto *intersectionType = AllocNode<ir::TSIntersectionType>(std::move(types));
    intersectionType->SetRange({startLoc, endLoc});
    return intersectionType;
}

ir::TypeNode *ETSParser::GetTypeAnnotationOfPrimitiveType([[maybe_unused]] lexer::TokenType tokenType,
                                                          TypeAnnotationParsingOptions *options)
{
    ir::TypeNode *typeAnnotation = nullptr;
    switch (tokenType) {
        case lexer::TokenType::KEYW_BOOLEAN:
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::BOOLEAN);
            break;
        case lexer::TokenType::KEYW_DOUBLE:
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::DOUBLE);
            break;
        case lexer::TokenType::KEYW_BYTE:
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::BYTE);
            break;
        case lexer::TokenType::KEYW_FLOAT:
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::FLOAT);
            break;
        case lexer::TokenType::KEYW_SHORT:
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::SHORT);
            break;
        case lexer::TokenType::KEYW_INT:
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::INT);
            break;
        case lexer::TokenType::KEYW_CHAR:
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::CHAR);
            break;
        case lexer::TokenType::KEYW_LONG:
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::LONG);
            break;
        case lexer::TokenType::KEYW_VOID:
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::VOID);
            break;
        default:
            typeAnnotation = ParseTypeReference(options);
            break;
    }
    return typeAnnotation;
}

ir::TypeNode *ETSParser::ParseWildcardType(TypeAnnotationParsingOptions *options)
{
    const auto varianceStartLoc = Lexer()->GetToken().Start();
    const auto varianceEndLoc = Lexer()->GetToken().End();
    const auto varianceModifier = ParseTypeVarianceModifier(options);

    auto *typeReference = [this, &varianceModifier, options]() -> ir::ETSTypeReference * {
        if (varianceModifier == ir::ModifierFlags::OUT &&
            (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_GREATER_THAN ||
             Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA)) {
            // unbounded 'out'
            return nullptr;
        }
        return ParseTypeReference(options)->AsETSTypeReference();
    }();

    auto *wildcardType = AllocNode<ir::ETSWildcardType>(typeReference, varianceModifier);
    wildcardType->SetRange({varianceStartLoc, typeReference == nullptr ? varianceEndLoc : typeReference->End()});

    return wildcardType;
}

ir::TypeNode *ETSParser::ParseFunctionType()
{
    auto startLoc = Lexer()->GetToken().Start();
    auto params = ParseFunctionParams();

    auto *const returnTypeAnnotation = [this]() -> ir::TypeNode * {
        ExpectToken(lexer::TokenType::PUNCTUATOR_ARROW);
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        return ParseTypeAnnotation(&options);
    }();

    ir::ScriptFunctionFlags throwMarker = ParseFunctionThrowMarker(false);

    auto *funcType = AllocNode<ir::ETSFunctionType>(
        ir::FunctionSignature(nullptr, std::move(params), returnTypeAnnotation), throwMarker);
    const auto endLoc = returnTypeAnnotation->End();
    funcType->SetRange({startLoc, endLoc});

    return funcType;
}

ir::TypeNode *ETSParser::ParseETSTupleType(TypeAnnotationParsingOptions *const options)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET);

    const auto startLoc = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat '['

    ArenaVector<ir::TypeNode *> tupleTypeList(Allocator()->Adapter());
    auto *const tupleType = AllocNode<ir::ETSTuple>(Allocator());

    bool spreadTypePresent = false;

    while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
        // Parse named parameter if name presents
        if ((Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) &&
            (Lexer()->Lookahead() == lexer::LEX_CHAR_COLON)) {
            ExpectIdentifier();
            Lexer()->NextToken();  // eat ':'
        }

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD) {
            if (spreadTypePresent) {
                ThrowSyntaxError("Only one spread type declaration allowed, at the last index");
            }

            spreadTypePresent = true;
            Lexer()->NextToken();  // eat '...'
        } else if (spreadTypePresent) {
            // This can't be implemented to any index, with type consistency. If a spread type is in the middle of
            // the tuple, then bounds check can't be made for element access, so the type of elements after the
            // spread can't be determined in compile time.
            ThrowSyntaxError("Spread type must be at the last index in the tuple type");
        }

        auto *const currentTypeAnnotation = ParseTypeAnnotation(options);
        currentTypeAnnotation->SetParent(tupleType);

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_QUESTION_MARK) {
            // NOTE(mmartin): implement optional types for tuples
            ThrowSyntaxError("Optional types in tuples are not yet implemented.");
        }

        if (spreadTypePresent) {
            if (!currentTypeAnnotation->IsTSArrayType()) {
                ThrowSyntaxError("Spread type must be an array type");
            }

            tupleType->SetSpreadType(currentTypeAnnotation);
        } else {
            tupleTypeList.push_back(currentTypeAnnotation);
        }

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
            Lexer()->NextToken();  // eat comma
            continue;
        }

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
            ThrowSyntaxError("Comma is mandatory between elements in a tuple type declaration");
        }
    }

    Lexer()->NextToken();  // eat ']'

    tupleType->SetTypeAnnotationsList(tupleTypeList);
    const auto endLoc = Lexer()->GetToken().End();
    tupleType->SetRange({startLoc, endLoc});

    return tupleType;
}

std::optional<lexer::SourcePosition> ETSParser::GetDefaultParamPosition(ArenaVector<ir::Expression *> params)
{
    for (auto &param : params) {
        if (param->IsETSParameterExpression() && param->AsETSParameterExpression()->IsDefault()) {
            return param->AsETSParameterExpression()->Initializer()->Start();
        }
    }
    return {};
}

// Just to reduce the size of ParseTypeAnnotation(...) method
std::pair<ir::TypeNode *, bool> ETSParser::GetTypeAnnotationFromToken(TypeAnnotationParsingOptions *options)
{
    ir::TypeNode *typeAnnotation = nullptr;

    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::LITERAL_IDENT: {
            typeAnnotation = ParseLiteralIdent(options);
            if (((*options) & TypeAnnotationParsingOptions::POTENTIAL_CLASS_LITERAL) != 0 &&
                (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_CLASS || IsStructKeyword())) {
                return std::make_pair(typeAnnotation, false);
            }
            break;
        }
        case lexer::TokenType::KEYW_VOID: {
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::VOID);
            break;
        }
        case lexer::TokenType::KEYW_BOOLEAN: {
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::BOOLEAN);
            break;
        }
        case lexer::TokenType::KEYW_BYTE: {
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::BYTE);
            break;
        }
        case lexer::TokenType::KEYW_CHAR: {
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::CHAR);
            break;
        }
        case lexer::TokenType::KEYW_DOUBLE: {
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::DOUBLE);
            break;
        }
        case lexer::TokenType::KEYW_FLOAT: {
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::FLOAT);
            break;
        }
        case lexer::TokenType::KEYW_INT: {
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::INT);
            break;
        }
        case lexer::TokenType::KEYW_LONG: {
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::LONG);
            break;
        }
        case lexer::TokenType::KEYW_SHORT: {
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::SHORT);
            break;
        }
        case lexer::TokenType::LITERAL_NULL: {
            typeAnnotation = AllocNode<ir::ETSNullType>();
            typeAnnotation->SetRange(Lexer()->GetToken().Loc());
            Lexer()->NextToken();
            break;
        }
        case lexer::TokenType::KEYW_UNDEFINED: {
            typeAnnotation = AllocNode<ir::ETSUndefinedType>();
            typeAnnotation->SetRange(Lexer()->GetToken().Loc());
            Lexer()->NextToken();
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS: {
            auto startLoc = Lexer()->GetToken().Start();
            lexer::LexerPosition savedPos = Lexer()->Save();
            Lexer()->NextToken();  // eat '('

            if (((*options) & TypeAnnotationParsingOptions::IGNORE_FUNCTION_TYPE) == 0 &&
                (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS ||
                 Lexer()->Lookahead() == lexer::LEX_CHAR_COLON)) {
                typeAnnotation = ParseFunctionType();
                typeAnnotation->SetStart(startLoc);

                if (auto position = GetDefaultParamPosition(typeAnnotation->AsETSFunctionType()->Params())) {
                    ThrowSyntaxError("Default parameters can not be used in functional type", position.value());
                }

                return std::make_pair(typeAnnotation, false);
            }

            typeAnnotation = ParseTypeAnnotation(options);
            typeAnnotation->SetStart(startLoc);

            if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_BITWISE_OR) {
                typeAnnotation = ParseUnionType(typeAnnotation);
            }

            if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_QUESTION_MARK) {
                ThrowSyntaxError("Default parameters can not be used in functional type");
            }

            ParseRightParenthesis(options, typeAnnotation, savedPos);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_FORMAT: {
            typeAnnotation = ParseTypeFormatPlaceholder();
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET: {
            typeAnnotation = ParseETSTupleType(options);
            break;
        }
        case lexer::TokenType::KEYW_THIS: {
            typeAnnotation = ParseThisType(options);
            break;
        }
        default: {
            break;
        }
    }

    return std::make_pair(typeAnnotation, true);
}

ir::TypeNode *ETSParser::ParseLiteralIdent(TypeAnnotationParsingOptions *options)
{
    if (const auto keyword = Lexer()->GetToken().KeywordType();
        keyword == lexer::TokenType::KEYW_IN || keyword == lexer::TokenType::KEYW_OUT) {
        return ParseWildcardType(options);
    }

    if (Lexer()->GetToken().IsDefinableTypeName()) {
        return GetTypeAnnotationOfPrimitiveType(Lexer()->GetToken().KeywordType(), options);
    }

    return ParseTypeReference(options);
}

void ETSParser::ParseRightParenthesis(TypeAnnotationParsingOptions *options, ir::TypeNode *&typeAnnotation,
                                      lexer::LexerPosition savedPos)
{
    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        if (((*options) & TypeAnnotationParsingOptions::THROW_ERROR) != 0) {
            ThrowExpectedToken(lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS);
        }

        Lexer()->Rewind(savedPos);
        typeAnnotation = nullptr;
    } else {
        Lexer()->NextToken();  // eat ')'
    }
}

ir::TypeNode *ETSParser::ParseThisType(TypeAnnotationParsingOptions *options)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::KEYW_THIS);

    // A syntax error should be thrown if
    // - the usage of 'this' as a type is not allowed in the current context, or
    // - 'this' is not used as a return type, or
    // - the current context is an arrow function (might be inside a method of a class where 'this' is allowed).
    if (((*options & TypeAnnotationParsingOptions::THROW_ERROR) != 0) &&
        (((GetContext().Status() & ParserStatus::ALLOW_THIS_TYPE) == 0) ||
         ((*options & TypeAnnotationParsingOptions::RETURN_TYPE) == 0) ||
         ((GetContext().Status() & ParserStatus::ARROW_FUNCTION) != 0))) {
        ThrowSyntaxError("A 'this' type is available only as return type in a non-static method of a class or struct.");
    }

    auto *thisType = AllocNode<ir::TSThisType>();
    thisType->SetRange(Lexer()->GetToken().Loc());

    Lexer()->NextToken();  // eat 'this'

    return thisType;
}

ir::TypeNode *ETSParser::ParseTypeAnnotation(TypeAnnotationParsingOptions *options)
{
    bool const throwError = ((*options) & TypeAnnotationParsingOptions::THROW_ERROR) != 0;

    auto [typeAnnotation, needFurtherProcessing] = GetTypeAnnotationFromToken(options);

    if (typeAnnotation == nullptr) {
        if (throwError) {
            ThrowSyntaxError("Invalid Type");
        }
        return nullptr;
    }

    if (!needFurtherProcessing) {
        return typeAnnotation;
    }

    const lexer::SourcePosition &startPos = Lexer()->GetToken().Start();

    if (((*options) & TypeAnnotationParsingOptions::ALLOW_INTERSECTION) != 0 &&
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_BITWISE_AND) {
        if (typeAnnotation->IsETSPrimitiveType()) {
            if (throwError) {
                ThrowSyntaxError("Invalid intersection type.");
            }
            return nullptr;
        }

        return ParseIntersectionType(typeAnnotation);
    }

    while (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
        Lexer()->NextToken();  // eat '['

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
            if (throwError) {
                ThrowExpectedToken(lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET);
            }
            return nullptr;
        }

        Lexer()->NextToken();  // eat ']'
        typeAnnotation = AllocNode<ir::TSArrayType>(typeAnnotation);
        typeAnnotation->SetRange({startPos, Lexer()->GetToken().End()});
    }

    if (((*options) & TypeAnnotationParsingOptions::DISALLOW_UNION) == 0 &&
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_BITWISE_OR) {
        return ParseUnionType(typeAnnotation);
    }

    return typeAnnotation;
}

void ETSParser::ThrowIfVarDeclaration(VariableParsingFlags flags)
{
    if ((flags & VariableParsingFlags::VAR) != 0) {
        ThrowUnexpectedToken(lexer::TokenType::KEYW_VAR);
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

ir::Statement *ETSParser::ParseExport(lexer::SourcePosition startLoc, ir::ModifierFlags modifiers)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY ||
           Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE);
    ArenaVector<ir::AstNode *> specifiers(Allocator()->Adapter());

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY) {
        ParseNameSpaceSpecifier(&specifiers, true);
    } else {
        auto specs = ParseNamedSpecifiers();

        if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_FROM) {
            specifiers = util::Helpers::ConvertVector<ir::AstNode>(specs);
        } else {
            ArenaVector<ir::ExportSpecifier *> exports(Allocator()->Adapter());
            for (auto spec : specs) {
                exports.emplace_back(AllocNode<ir::ExportSpecifier>(spec->Local(), spec->Imported()));
            }
            auto result = AllocNode<ir::ExportNamedDeclaration>(Allocator(), static_cast<ir::StringLiteral *>(nullptr),
                                                                std::move(exports));
            result->AddModifier(modifiers);
            return result;
        }
    }

    // re-export directive
    ir::ImportSource *reExportSource = ParseSourceFromClause(true);

    lexer::SourcePosition endLoc = reExportSource->Source()->End();
    auto *reExportDeclaration = AllocNode<ir::ETSImportDeclaration>(reExportSource, specifiers);
    reExportDeclaration->SetRange({startLoc, endLoc});

    ConsumeSemicolon(reExportDeclaration);

    auto reExport = AllocNode<ir::ETSReExportDeclaration>(reExportDeclaration, std::vector<std::string>(),
                                                          GetProgram()->SourceFilePath(), Allocator());
    reExport->AddModifier(modifiers);
    return reExport;
}

ir::Statement *ETSParser::ParseFunctionStatement([[maybe_unused]] const StatementParsingFlags flags)
{
    ASSERT((flags & StatementParsingFlags::GLOBAL) == 0);
    ThrowSyntaxError("Nested functions are not allowed");
}

ir::ETSPackageDeclaration *ETSParser::ParsePackageDeclaration()
{
    auto startLoc = Lexer()->GetToken().Start();

    if (Lexer()->GetToken().Type() != lexer::TokenType::KEYW_PACKAGE) {
        if (!IsETSModule() && GetProgram()->IsEntryPoint()) {
            // NOTE(rsipka): consider adding a filename name as module name to entry points as well
            importPathManager_->InsertModuleInfo(GetProgram()->AbsoluteName(),
                                                 util::ImportPathManager::ModuleInfo {util::StringView(""), false});
            return nullptr;
        }
        importPathManager_->InsertModuleInfo(GetProgram()->AbsoluteName(),
                                             util::ImportPathManager::ModuleInfo {GetProgram()->FileName(), false});
        GetProgram()->SetPackageName(GetProgram()->FileName());
        return nullptr;
    }

    Lexer()->NextToken();

    ir::Expression *name = ParseQualifiedName();

    auto *packageDeclaration = AllocNode<ir::ETSPackageDeclaration>(name);
    packageDeclaration->SetRange({startLoc, Lexer()->GetToken().End()});

    ConsumeSemicolon(packageDeclaration);

    auto packageName =
        name->IsIdentifier() ? name->AsIdentifier()->Name() : name->AsTSQualifiedName()->ToString(Allocator());

    GetProgram()->SetPackageName(packageName);
    // NOTE(rsipka): handle these two cases, check that is it really required
    importPathManager_->InsertModuleInfo(GetProgram()->AbsoluteName(),
                                         util::ImportPathManager::ModuleInfo {packageName, true});
    importPathManager_->InsertModuleInfo(GetProgram()->ResolvedFilePath(),
                                         util::ImportPathManager::ModuleInfo {packageName, true});

    return packageDeclaration;
}

ir::ImportSource *ETSParser::ParseSourceFromClause(bool requireFrom)
{
    if (Lexer()->GetToken().KeywordType() != lexer::TokenType::KEYW_FROM) {
        if (requireFrom) {
            ThrowSyntaxError("Unexpected token.");
        }
    } else {
        Lexer()->NextToken();  // eat `from`
    }

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_STRING) {
        ThrowSyntaxError("Unexpected token.");
    }

    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_STRING);
    auto importPath = Lexer()->GetToken().Ident();

    auto resolvedImportPath = importPathManager_->ResolvePath(GetProgram()->AbsoluteName(), importPath);
    importPathManager_->AddToParseList(resolvedImportPath,
                                       (GetContext().Status() & ParserStatus::IN_DEFAULT_IMPORTS) != 0U);

    auto *resolvedSource = AllocNode<ir::StringLiteral>(resolvedImportPath);
    auto importData = importPathManager_->GetImportData(resolvedImportPath, Extension());
    auto *source = AllocNode<ir::StringLiteral>(importPath);
    source->SetRange(Lexer()->GetToken().Loc());

    Lexer()->NextToken();

    return Allocator()->New<ir::ImportSource>(source, resolvedSource, importData.lang, importData.hasDecl);
}

ArenaVector<ir::ETSImportDeclaration *> ETSParser::ParseImportDeclarations()
{
    std::vector<std::string> userPaths;
    ArenaVector<ir::ETSImportDeclaration *> statements(Allocator()->Adapter());

    while (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_IMPORT) {
        auto startLoc = Lexer()->GetToken().Start();
        Lexer()->NextToken();  // eat import

        ArenaVector<ir::AstNode *> specifiers(Allocator()->Adapter());

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY) {
            ParseNameSpaceSpecifier(&specifiers);
        } else if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
            auto specs = ParseNamedSpecifiers();
            specifiers = util::Helpers::ConvertVector<ir::AstNode>(specs);
        } else {
            ParseImportDefaultSpecifier(&specifiers);
        }

        ir::ImportSource *importSource = ParseSourceFromClause(true);

        lexer::SourcePosition endLoc = importSource->Source()->End();
        auto *importDeclaration = AllocNode<ir::ETSImportDeclaration>(importSource, std::move(specifiers));
        importDeclaration->SetRange({startLoc, endLoc});

        ConsumeSemicolon(importDeclaration);

        statements.push_back(importDeclaration);
    }

    std::sort(statements.begin(), statements.end(), [](const auto *s1, const auto *s2) -> bool {
        return s1->Specifiers()[0]->IsImportNamespaceSpecifier() && !s2->Specifiers()[0]->IsImportNamespaceSpecifier();
    });

    return statements;
}

ArenaVector<ir::ImportSpecifier *> ETSParser::ParseNamedSpecifiers()
{
    // NOTE(user): handle qualifiedName in file bindings: qualifiedName '.' '*'
    if (!Lexer()->TryEatTokenType(lexer::TokenType::PUNCTUATOR_LEFT_BRACE)) {
        ThrowExpectedToken(lexer::TokenType::PUNCTUATOR_LEFT_BRACE);
    }

    auto fileName = GetProgram()->SourceFilePath().Mutf8();

    ArenaVector<ir::ImportSpecifier *> result(Allocator()->Adapter());

    while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY) {
            ThrowSyntaxError("The '*' token is not allowed as a selective binding (between braces)");
        }

        if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
            ThrowSyntaxError("Unexpected token");
        }

        lexer::Token importedToken = Lexer()->GetToken();
        auto *imported = AllocNode<ir::Identifier>(importedToken.Ident(), Allocator());
        ir::Identifier *local = nullptr;
        imported->SetReference();
        imported->SetRange(Lexer()->GetToken().Loc());

        Lexer()->NextToken();  // eat import/export name

        if (CheckModuleAsModifier() && Lexer()->TryEatTokenType(lexer::TokenType::KEYW_AS)) {
            local = ParseNamedImport(Lexer()->GetToken());
            Lexer()->NextToken();  // eat local name
        } else {
            local = ParseNamedImport(importedToken);
        }

        auto *specifier = AllocNode<ir::ImportSpecifier>(imported, local);
        specifier->SetRange({imported->Start(), local->End()});

        util::Helpers::CheckImportedName(result, specifier, fileName);

        result.emplace_back(specifier);

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
            Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat comma
        }
    }

    Lexer()->NextToken();  // eat '}'

    return result;
}

void ETSParser::ParseNameSpaceSpecifier(ArenaVector<ir::AstNode *> *specifiers, bool isReExport)
{
    lexer::SourcePosition namespaceStart = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat `*` character

    if (!CheckModuleAsModifier()) {
        ThrowSyntaxError("Unexpected token.");
    }

    // Note (oeotvos) As a temporary solution we allow the stdlib to use namespace import without an alias, but this
    // should be handled at some point.
    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_FROM && !isReExport &&
        (GetContext().Status() & ParserStatus::IN_DEFAULT_IMPORTS) == 0) {
        ThrowSyntaxError("Unexpected token, expected 'as' but found 'from'");
    }

    auto *local = AllocNode<ir::Identifier>(util::StringView(""), Allocator());
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA ||
        Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_FROM || isReExport) {
        local->SetReference();
        auto *specifier = AllocNode<ir::ImportNamespaceSpecifier>(local);
        specifier->SetRange({namespaceStart, Lexer()->GetToken().End()});
        specifiers->push_back(specifier);
        return;
    }

    Lexer()->NextToken();  // eat `as` literal
    local = ParseNamedImport(Lexer()->GetToken());

    auto *specifier = AllocNode<ir::ImportNamespaceSpecifier>(local);
    specifier->SetRange({namespaceStart, Lexer()->GetToken().End()});
    specifiers->push_back(specifier);

    Lexer()->NextToken();  // eat local name
}

ir::AstNode *ETSParser::ParseImportDefaultSpecifier(ArenaVector<ir::AstNode *> *specifiers)
{
    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Unexpected token, expected an identifier");
    }

    auto *imported = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    imported->SetReference();
    imported->SetRange(Lexer()->GetToken().Loc());
    Lexer()->NextToken();  // Eat import specifier.

    if (Lexer()->GetToken().KeywordType() != lexer::TokenType::KEYW_FROM) {
        ThrowSyntaxError("Unexpected token, expected 'from'");
    }

    auto *specifier = AllocNode<ir::ImportDefaultSpecifier>(imported);
    specifier->SetRange({imported->Start(), imported->End()});
    specifiers->push_back(specifier);

    return nullptr;
}

bool ETSParser::CheckModuleAsModifier()
{
    if ((Lexer()->GetToken().Flags() & lexer::TokenFlags::HAS_ESCAPE) != 0U) {
        ThrowSyntaxError("Escape sequences are not allowed in 'as' keyword");
    }

    return true;
}

ir::AnnotatedExpression *ETSParser::GetAnnotatedExpressionFromParam()
{
    ir::AnnotatedExpression *parameter;

    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::LITERAL_IDENT: {
            parameter = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
            if (parameter->AsIdentifier()->Decorators().empty()) {
                parameter->SetRange(Lexer()->GetToken().Loc());
            } else {
                parameter->SetRange(
                    {parameter->AsIdentifier()->Decorators().front()->Start(), Lexer()->GetToken().End()});
            }
            break;
        }

        case lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD: {
            const auto startLoc = Lexer()->GetToken().Start();
            Lexer()->NextToken();

            if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
                ThrowSyntaxError("Unexpected token, expected an identifier.");
            }

            auto *const restIdent = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
            restIdent->SetRange(Lexer()->GetToken().Loc());

            parameter = AllocNode<ir::SpreadElement>(ir::AstNodeType::REST_ELEMENT, Allocator(), restIdent);
            parameter->SetRange({startLoc, Lexer()->GetToken().End()});
            break;
        }

        default: {
            ThrowSyntaxError("Unexpected token, expected an identifier.");
        }
    }

    Lexer()->NextToken();
    return parameter;
}

// NOLINTBEGIN(modernize-avoid-c-arrays)
static constexpr char const NO_DEFAULT_FOR_REST[] = "Rest parameter cannot have the default value.";
static constexpr char const ONLY_ARRAY_FOR_REST[] = "Rest parameter should be of an array type.";
static constexpr char const EXPLICIT_PARAM_TYPE[] = "Parameter declaration should have an explicit type annotation.";
// NOLINTEND(modernize-avoid-c-arrays)

ir::ETSUnionType *ETSParser::CreateOptionalParameterTypeNode(ir::TypeNode *typeAnnotation,
                                                             ir::ETSUndefinedType *defaultUndef)
{
    ArenaVector<ir::TypeNode *> types(Allocator()->Adapter());
    if (typeAnnotation->IsETSUnionType()) {
        for (auto const &type : typeAnnotation->AsETSUnionType()->Types()) {
            types.push_back(type);
        }
    } else {
        types.push_back(typeAnnotation);
    }
    types.push_back(defaultUndef);

    auto *const unionType = AllocNode<ir::ETSUnionType>(std::move(types));
    unionType->SetRange({typeAnnotation->Start(), typeAnnotation->End()});
    return unionType;
}

ir::Expression *ETSParser::ParseFunctionParameterExpression(ir::AnnotatedExpression *const paramIdent,
                                                            ir::ETSUndefinedType *defaultUndef)
{
    ir::ETSParameterExpression *paramExpression;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        if (paramIdent->IsRestElement()) {
            ThrowSyntaxError(NO_DEFAULT_FOR_REST);
        }

        auto const lexerPos = Lexer()->Save().Iterator();
        Lexer()->NextToken();  // eat '='

        if (defaultUndef != nullptr) {
            ThrowSyntaxError("Not enable default value with default undefined");
        }
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS ||
            Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
            ThrowSyntaxError("You didn't set the value.");
        }

        paramExpression = AllocNode<ir::ETSParameterExpression>(paramIdent->AsIdentifier(), ParseExpression());

        std::string value = Lexer()->SourceView(lexerPos.Index(), Lexer()->Save().Iterator().Index()).Mutf8();
        while (value.back() == ' ') {
            value.pop_back();
        }
        if (value.back() == ')' || value.back() == ',') {
            value.pop_back();
        }
        paramExpression->SetLexerSaved(util::UString(value, Allocator()).View());

        paramExpression->SetRange({paramIdent->Start(), paramExpression->Initializer()->End()});
    } else if (paramIdent->IsIdentifier()) {
        auto *typeAnnotation = paramIdent->AsIdentifier()->TypeAnnotation();

        const auto typeAnnotationValue = [this, typeAnnotation,
                                          defaultUndef]() -> std::pair<ir::Expression *, std::string> {
            if (typeAnnotation == nullptr) {
                return std::make_pair(nullptr, "");
            }
            return std::make_pair(defaultUndef != nullptr ? AllocNode<ir::UndefinedLiteral>() : nullptr, "undefined");
        }();

        paramExpression =
            AllocNode<ir::ETSParameterExpression>(paramIdent->AsIdentifier(), std::get<0>(typeAnnotationValue));
        if (defaultUndef != nullptr) {
            paramExpression->SetLexerSaved(util::UString(std::get<1>(typeAnnotationValue), Allocator()).View());
        }
        paramExpression->SetRange({paramIdent->Start(), paramIdent->End()});
    } else {
        paramExpression = AllocNode<ir::ETSParameterExpression>(paramIdent->AsRestElement(), nullptr);
        paramExpression->SetRange({paramIdent->Start(), paramIdent->End()});
    }
    return paramExpression;
}

ir::Expression *ETSParser::ParseFunctionParameter()
{
    auto *const paramIdent = GetAnnotatedExpressionFromParam();

    ir::ETSUndefinedType *defaultUndef = nullptr;

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_QUESTION_MARK) {
        if (paramIdent->IsRestElement()) {
            ThrowSyntaxError(NO_DEFAULT_FOR_REST);
        }
        defaultUndef = AllocNode<ir::ETSUndefinedType>();
        defaultUndef->SetRange({Lexer()->GetToken().Start(), Lexer()->GetToken().End()});
        Lexer()->NextToken();  // eat '?'
    }

    const bool isArrow = (GetContext().Status() & ParserStatus::ARROW_FUNCTION) != 0;

    if (Lexer()->TryEatTokenType(lexer::TokenType::PUNCTUATOR_COLON)) {
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        ir::TypeNode *typeAnnotation = ParseTypeAnnotation(&options);

        if (defaultUndef != nullptr) {
            typeAnnotation = CreateOptionalParameterTypeNode(typeAnnotation, defaultUndef);
        }

        if (paramIdent->IsRestElement() && !typeAnnotation->IsTSArrayType()) {
            ThrowSyntaxError(ONLY_ARRAY_FOR_REST);
        }

        typeAnnotation->SetParent(paramIdent);
        paramIdent->SetTsTypeAnnotation(typeAnnotation);
        paramIdent->SetEnd(typeAnnotation->End());
    } else if (!isArrow && defaultUndef == nullptr) {
        ThrowSyntaxError(EXPLICIT_PARAM_TYPE);
    }

    return ParseFunctionParameterExpression(paramIdent, defaultUndef);
}

ir::Expression *ETSParser::CreateParameterThis(const util::StringView className)
{
    auto *paramIdent = AllocNode<ir::Identifier>(varbinder::TypedBinder::MANDATORY_PARAM_THIS, Allocator());
    paramIdent->SetRange(Lexer()->GetToken().Loc());

    ir::Expression *classTypeName = AllocNode<ir::Identifier>(className, Allocator());
    classTypeName->AsIdentifier()->SetReference();
    classTypeName->SetRange(Lexer()->GetToken().Loc());

    auto typeRefPart = AllocNode<ir::ETSTypeReferencePart>(classTypeName, nullptr, nullptr);
    ir::TypeNode *typeAnnotation = AllocNode<ir::ETSTypeReference>(typeRefPart);

    typeAnnotation->SetParent(paramIdent);
    paramIdent->SetTsTypeAnnotation(typeAnnotation);

    auto *paramExpression = AllocNode<ir::ETSParameterExpression>(paramIdent, nullptr);
    paramExpression->SetRange({paramIdent->Start(), paramIdent->End()});

    return paramExpression;
}

ir::AnnotatedExpression *ETSParser::ParseVariableDeclaratorKey([[maybe_unused]] VariableParsingFlags flags)
{
    ir::Identifier *init = ExpectIdentifier();
    ir::TypeNode *typeAnnotation = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_QUESTION_MARK) {
        if ((flags & VariableParsingFlags::FOR_OF) != 0U) {
            ThrowSyntaxError("Optional variable is not allowed in for of statements");
        }
        Lexer()->NextToken();  // eat '?'
        init->AddModifier(ir::ModifierFlags::OPTIONAL);
    }

    if (auto const tokenType = Lexer()->GetToken().Type(); tokenType == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        typeAnnotation = ParseTypeAnnotation(&options);
    } else if (tokenType != lexer::TokenType::PUNCTUATOR_SUBSTITUTION && (flags & VariableParsingFlags::FOR_OF) == 0U) {
        ThrowSyntaxError("Variable must be initialized or it's type must be declared");
    }

    if (typeAnnotation != nullptr) {
        init->SetTsTypeAnnotation(typeAnnotation);
        typeAnnotation->SetParent(init);
    }

    return init;
}

ir::VariableDeclarator *ETSParser::ParseVariableDeclaratorInitializer(ir::Expression *init, VariableParsingFlags flags,
                                                                      const lexer::SourcePosition &startLoc)
{
    if ((flags & VariableParsingFlags::DISALLOW_INIT) != 0) {
        ThrowSyntaxError("for-await-of loop variable declaration may not have an initializer");
    }

    Lexer()->NextToken();

    ir::Expression *initializer = ParseExpression();

    lexer::SourcePosition endLoc = initializer->End();

    auto *declarator = AllocNode<ir::VariableDeclarator>(GetFlag(flags), init, initializer);
    declarator->SetRange({startLoc, endLoc});

    return declarator;
}

ir::VariableDeclarator *ETSParser::ParseVariableDeclarator(ir::Expression *init, lexer::SourcePosition startLoc,
                                                           VariableParsingFlags flags)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        return ParseVariableDeclaratorInitializer(init, flags, startLoc);
    }

    if ((flags & VariableParsingFlags::CONST) != 0 &&
        static_cast<uint32_t>(flags & VariableParsingFlags::ACCEPT_CONST_NO_INIT) == 0U) {
        ThrowSyntaxError("Missing initializer in const declaration");
    }

    if (init->AsIdentifier()->TypeAnnotation() == nullptr && (flags & VariableParsingFlags::FOR_OF) == 0U) {
        ThrowSyntaxError("Variable must be initialized or it's type must be declared");
    }

    lexer::SourcePosition endLoc = init->End();
    auto declarator = AllocNode<ir::VariableDeclarator>(GetFlag(flags), init);
    declarator->SetRange({startLoc, endLoc});

    // NOTE (psiket)  Transfer the OPTIONAL flag from the init to the declarator?
    return declarator;
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

ir::Expression *ETSParser::ParseCatchParam()
{
    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        ThrowSyntaxError("Unexpected token, expected '('");
    }

    ir::AnnotatedExpression *param = nullptr;

    Lexer()->NextToken();  // eat left paren

    if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
        CheckRestrictedBinding();
        param = ExpectIdentifier();
    } else {
        ThrowSyntaxError("Unexpected token in catch parameter, expected an identifier");
    }

    ParseCatchParamTypeAnnotation(param);

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError("Unexpected token, expected ')'");
    }

    Lexer()->NextToken();  // eat right paren

    return param;
}

void ETSParser::ParseCatchParamTypeAnnotation([[maybe_unused]] ir::AnnotatedExpression *param)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'

        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        if (auto *typeAnnotation = ParseTypeAnnotation(&options); typeAnnotation != nullptr) {
            typeAnnotation->SetParent(param);
            param->SetTsTypeAnnotation(typeAnnotation);
        }
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        ThrowSyntaxError("Catch clause variable cannot have an initializer");
    }
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

ir::Statement *ETSParser::ParseImportDeclaration([[maybe_unused]] StatementParsingFlags flags)
{
    char32_t nextChar = Lexer()->Lookahead();
    if (nextChar == lexer::LEX_CHAR_LEFT_PAREN || nextChar == lexer::LEX_CHAR_DOT) {
        return ParseExpressionStatement();
    }

    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat import

    ArenaVector<ir::AstNode *> specifiers(Allocator()->Adapter());

    ir::ImportSource *importSource = nullptr;

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_STRING) {
        ir::AstNode *astNode = ParseImportSpecifiers(&specifiers);
        if (astNode != nullptr) {
            ASSERT(astNode->IsTSImportEqualsDeclaration());
            astNode->SetRange({startLoc, Lexer()->GetToken().End()});
            ConsumeSemicolon(astNode->AsTSImportEqualsDeclaration());
            return astNode->AsTSImportEqualsDeclaration();
        }
        importSource = ParseSourceFromClause(true);
    } else {
        importSource = ParseSourceFromClause(false);
    }

    lexer::SourcePosition endLoc = importSource->Source()->End();
    auto *importDeclaration = AllocNode<ir::ETSImportDeclaration>(importSource, std::move(specifiers));
    importDeclaration->SetRange({startLoc, endLoc});

    ConsumeSemicolon(importDeclaration);

    return importDeclaration;
}

ir::Statement *ETSParser::ParseExportDeclaration([[maybe_unused]] StatementParsingFlags flags)
{
    ThrowUnexpectedToken(lexer::TokenType::KEYW_EXPORT);
}

ir::Expression *ETSParser::ResolveArgumentUnaryExpr(ExpressionParseFlags flags)
{
    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::PUNCTUATOR_PLUS:
        case lexer::TokenType::PUNCTUATOR_MINUS:
        case lexer::TokenType::PUNCTUATOR_TILDE:
        case lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK:
        case lexer::TokenType::PUNCTUATOR_DOLLAR_DOLLAR:
        case lexer::TokenType::PUNCTUATOR_PLUS_PLUS:
        case lexer::TokenType::PUNCTUATOR_MINUS_MINUS:
        case lexer::TokenType::KEYW_TYPEOF: {
            return ParseUnaryOrPrefixUpdateExpression();
        }
        default: {
            return ParseLeftHandSideExpression(flags);
        }
    }
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ETSParser::ParseUnaryOrPrefixUpdateExpression(ExpressionParseFlags flags)
{
    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::PUNCTUATOR_PLUS_PLUS:
        case lexer::TokenType::PUNCTUATOR_MINUS_MINUS:
        case lexer::TokenType::PUNCTUATOR_PLUS:
        case lexer::TokenType::PUNCTUATOR_MINUS:
        case lexer::TokenType::PUNCTUATOR_TILDE:
        case lexer::TokenType::PUNCTUATOR_DOLLAR_DOLLAR:
        case lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK:
        case lexer::TokenType::KEYW_TYPEOF: {
            break;
        }
        case lexer::TokenType::KEYW_LAUNCH: {
            return ParseLaunchExpression(flags);
        }
        default: {
            return ParseLeftHandSideExpression(flags);
        }
    }

    lexer::TokenType operatorType = Lexer()->GetToken().Type();
    auto start = Lexer()->GetToken().Start();
    Lexer()->NextToken();

    ir::Expression *argument = ResolveArgumentUnaryExpr(flags);

    if (lexer::Token::IsUpdateToken(operatorType)) {
        if (!argument->IsIdentifier() && !argument->IsMemberExpression()) {
            ThrowSyntaxError("Invalid left-hand side in prefix operation");
        }
    }

    lexer::SourcePosition end = argument->End();

    ir::Expression *returnExpr = nullptr;
    if (lexer::Token::IsUpdateToken(operatorType)) {
        returnExpr = AllocNode<ir::UpdateExpression>(argument, operatorType, true);
    } else if (operatorType == lexer::TokenType::KEYW_TYPEOF) {
        returnExpr = AllocNode<ir::TypeofExpression>(argument);
    } else {
        returnExpr = AllocNode<ir::UnaryExpression>(argument, operatorType);
    }

    returnExpr->SetRange({start, end});

    return returnExpr;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ETSParser::ParseDefaultPrimaryExpression(ExpressionParseFlags flags)
{
    auto startLoc = Lexer()->GetToken().Start();
    auto savedPos = Lexer()->Save();
    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::POTENTIAL_CLASS_LITERAL |
                                           TypeAnnotationParsingOptions::IGNORE_FUNCTION_TYPE |
                                           TypeAnnotationParsingOptions::DISALLOW_UNION;
    ir::TypeNode *potentialType = ParseTypeAnnotation(&options);

    if (potentialType != nullptr) {
        if (potentialType->IsTSArrayType()) {
            return potentialType;
        }

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD) {
            Lexer()->NextToken();  // eat '.'
        }

        if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_CLASS || IsStructKeyword()) {
            Lexer()->NextToken();  // eat 'class' and 'struct'
            auto *classLiteral = AllocNode<ir::ETSClassLiteral>(potentialType);
            classLiteral->SetRange({startLoc, Lexer()->GetToken().End()});
            return classLiteral;
        }
    }

    Lexer()->Rewind(savedPos);

    Lexer()->NextToken();
    bool pretendArrow = Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_ARROW;
    Lexer()->Rewind(savedPos);

    if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT && !pretendArrow) {
        return ParsePrimaryExpressionIdent(flags);
    }

    ThrowSyntaxError({"Unexpected token '", lexer::TokenToString(Lexer()->GetToken().Type()), "'."});
    return nullptr;
}

ir::Expression *ETSParser::ParsePrimaryExpressionWithLiterals(ExpressionParseFlags flags)
{
    switch (Lexer()->GetToken().Type()) {
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
            return ParseCoercedNumberLiteral();
        }
        case lexer::TokenType::LITERAL_STRING: {
            return ParseStringLiteral();
        }
        case lexer::TokenType::LITERAL_CHAR: {
            return ParseCharLiteral();
        }
        default: {
            return ParseDefaultPrimaryExpression(flags);
        }
    }
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ETSParser::ParsePrimaryExpression(ExpressionParseFlags flags)
{
    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS: {
            return ParseCoverParenthesizedExpressionAndArrowParameterList(flags);
        }
        case lexer::TokenType::KEYW_THIS: {
            return ParseThisExpression();
        }
        case lexer::TokenType::KEYW_SUPER: {
            return ParseSuperExpression();
        }
        case lexer::TokenType::KEYW_NEW: {
            return ParseNewExpression();
        }
        case lexer::TokenType::KEYW_ASYNC: {
            return ParseAsyncExpression();
        }
        case lexer::TokenType::KEYW_AWAIT: {
            return ParseAwaitExpression();
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET: {
            return ParseArrayExpression(CarryPatternFlags(flags));
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_BRACE: {
            return ParseObjectExpression(CarryPatternFlags(flags));
        }
        case lexer::TokenType::PUNCTUATOR_BACK_TICK: {
            return ParseTemplateLiteral();
        }
        case lexer::TokenType::KEYW_TYPE: {
            ThrowSyntaxError("Type alias is allowed only as top-level declaration");
        }
        case lexer::TokenType::PUNCTUATOR_FORMAT: {
            return ParseExpressionFormatPlaceholder();
        }
        case lexer::TokenType::KEYW_TYPEOF: {
            return ParseUnaryOrPrefixUpdateExpression();
        }
        default: {
            return ParsePrimaryExpressionWithLiterals(flags);
        }
    }
}

bool IsPunctuartorSpecialCharacter(lexer::TokenType tokenType)
{
    switch (tokenType) {
        case lexer::TokenType::PUNCTUATOR_COLON:
        case lexer::TokenType::PUNCTUATOR_COMMA:
        case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET:
        case lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET:
        case lexer::TokenType::PUNCTUATOR_LESS_THAN:
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN:
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR:
            return true;
        default:
            return false;
    }
}

ir::Expression *ETSParser::ParseExpressionOrTypeAnnotation(lexer::TokenType type,
                                                           [[maybe_unused]] ExpressionParseFlags flags)
{
    if (type == lexer::TokenType::KEYW_INSTANCEOF) {
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;

        if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_NULL) {
            auto *typeAnnotation = AllocNode<ir::NullLiteral>();
            typeAnnotation->SetRange(Lexer()->GetToken().Loc());
            Lexer()->NextToken();

            return typeAnnotation;
        }

        return ParseTypeAnnotation(&options);
    }

    return ParseExpression(ExpressionParseFlags::DISALLOW_YIELD);
}

bool ETSParser::IsArrowFunctionExpressionStart()
{
    const auto savedPos = Lexer()->Save();
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
    Lexer()->NextToken();
    auto tokenType = Lexer()->GetToken().Type();

    size_t openBrackets = 1;
    bool expectIdentifier = true;
    while (tokenType != lexer::TokenType::EOS && openBrackets > 0) {
        switch (tokenType) {
            case lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS:
                --openBrackets;
                break;
            case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS:
                ++openBrackets;
                break;
            case lexer::TokenType::PUNCTUATOR_COMMA:
                expectIdentifier = true;
                break;
            case lexer::TokenType::PUNCTUATOR_SEMI_COLON:
                Lexer()->Rewind(savedPos);
                return false;
            default:
                if (!expectIdentifier) {
                    break;
                }
                if (tokenType != lexer::TokenType::LITERAL_IDENT &&
                    tokenType != lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD) {
                    Lexer()->Rewind(savedPos);
                    return false;
                }
                expectIdentifier = false;
        }
        Lexer()->NextToken();
        tokenType = Lexer()->GetToken().Type();
    }

    while (tokenType != lexer::TokenType::EOS && tokenType != lexer::TokenType::PUNCTUATOR_ARROW) {
        if (lexer::Token::IsPunctuatorToken(tokenType) && !IsPunctuartorSpecialCharacter(tokenType)) {
            break;
        }
        Lexer()->NextToken();
        tokenType = Lexer()->GetToken().Type();
    }
    Lexer()->Rewind(savedPos);
    return tokenType == lexer::TokenType::PUNCTUATOR_ARROW;
}

ir::ArrowFunctionExpression *ETSParser::ParseArrowFunctionExpression()
{
    auto newStatus = ParserStatus::ARROW_FUNCTION;
    auto *func = ParseFunction(newStatus);
    auto *arrowFuncNode = AllocNode<ir::ArrowFunctionExpression>(Allocator(), func);
    arrowFuncNode->SetRange(func->Range());
    return arrowFuncNode;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ETSParser::ParseCoverParenthesizedExpressionAndArrowParameterList(ExpressionParseFlags flags)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
    if (IsArrowFunctionExpressionStart()) {
        return ParseArrowFunctionExpression();
    }

    lexer::SourcePosition start = Lexer()->GetToken().Start();
    Lexer()->NextToken();

    ExpressionParseFlags newFlags = ExpressionParseFlags::ACCEPT_COMMA;
    if ((flags & ExpressionParseFlags::INSTANCEOF) != 0) {
        newFlags |= ExpressionParseFlags::INSTANCEOF;
    };

    ir::Expression *expr = ParseExpression(newFlags);

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError("Unexpected token, expected ')'");
    }

    expr->SetGrouped();
    expr->SetRange({start, Lexer()->GetToken().End()});
    Lexer()->NextToken();

    return expr;
}

bool ETSParser::ParsePotentialGenericFunctionCall(ir::Expression *primaryExpr, ir::Expression **returnExpression,
                                                  [[maybe_unused]] const lexer::SourcePosition &startLoc,
                                                  bool ignoreCallExpression)
{
    if (Lexer()->Lookahead() == lexer::LEX_CHAR_LESS_THAN ||
        (!primaryExpr->IsIdentifier() && !primaryExpr->IsMemberExpression())) {
        return true;
    }

    const auto savedPos = Lexer()->Save();

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SHIFT) {
        Lexer()->BackwardToken(lexer::TokenType::PUNCTUATOR_LESS_THAN, 1);
    }

    TypeAnnotationParsingOptions options =
        TypeAnnotationParsingOptions::ALLOW_WILDCARD | TypeAnnotationParsingOptions::IGNORE_FUNCTION_TYPE;
    ir::TSTypeParameterInstantiation *typeParams = ParseTypeParameterInstantiation(&options);

    if (typeParams == nullptr) {
        Lexer()->Rewind(savedPos);
        return true;
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::EOS) {
        ThrowSyntaxError("'(' expected");
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        if (!ignoreCallExpression) {
            *returnExpression = ParseCallExpression(*returnExpression, false, false);
            (*returnExpression)->AsCallExpression()->SetTypeParams(typeParams);
            return false;
        }

        return true;
    }

    Lexer()->Rewind(savedPos);
    return true;
}

ir::Expression *ETSParser::ParsePostPrimaryExpression(ir::Expression *primaryExpr, lexer::SourcePosition startLoc,
                                                      bool ignoreCallExpression,
                                                      [[maybe_unused]] bool *isChainExpression)
{
    ir::Expression *returnExpression = primaryExpr;

    while (true) {
        switch (Lexer()->GetToken().Type()) {
            case lexer::TokenType::PUNCTUATOR_QUESTION_DOT: {
                if (*isChainExpression) {
                    break;  // terminate current chain
                }
                *isChainExpression = true;
                Lexer()->NextToken();  // eat ?.

                if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
                    returnExpression = ParseElementAccess(returnExpression, true);
                    continue;
                }

                if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
                    returnExpression = ParseCallExpression(returnExpression, true, false);
                    continue;
                }

                returnExpression = ParsePropertyAccess(returnExpression, true);
                continue;
            }
            case lexer::TokenType::PUNCTUATOR_PERIOD: {
                Lexer()->NextToken();  // eat period

                returnExpression = ParsePropertyAccess(returnExpression);
                continue;
            }
            case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET: {
                returnExpression = ParseElementAccess(returnExpression);
                continue;
            }
            case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT:
            case lexer::TokenType::PUNCTUATOR_LESS_THAN: {
                if (ParsePotentialGenericFunctionCall(returnExpression, &returnExpression, startLoc,
                                                      ignoreCallExpression)) {
                    break;
                }

                continue;
            }
            case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS: {
                if (ignoreCallExpression) {
                    break;
                }
                returnExpression = ParseCallExpression(returnExpression, false, false);
                continue;
            }
            case lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK: {
                const bool shouldBreak = ParsePotentialNonNullExpression(&returnExpression, startLoc);
                if (shouldBreak) {
                    break;
                }

                continue;
            }
            case lexer::TokenType::PUNCTUATOR_FORMAT: {
                ThrowUnexpectedToken(lexer::TokenType::PUNCTUATOR_FORMAT);
            }
            default: {
                break;
            }
        }

        break;
    }

    return returnExpression;
}

ir::Expression *ETSParser::ParsePotentialAsExpression(ir::Expression *primaryExpr)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::KEYW_AS);
    Lexer()->NextToken();

    TypeAnnotationParsingOptions options =
        TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::ALLOW_INTERSECTION;
    ir::TypeNode *type = ParseTypeAnnotation(&options);

    auto *asExpression = AllocNode<ir::TSAsExpression>(primaryExpr, type, false);
    asExpression->SetRange(primaryExpr->Range());
    return asExpression;
}

//  Extracted from 'ParseNewExpression()' to reduce function's size
ir::ClassDefinition *ETSParser::CreateClassDefinitionForNewExpression(ArenaVector<ir::Expression *> &arguments,
                                                                      ir::TypeNode *typeReference,
                                                                      ir::TypeNode *baseTypeReference)
{
    lexer::SourcePosition endLoc = typeReference->End();

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        if (baseTypeReference != nullptr) {
            ThrowSyntaxError("Can not use 'new' on primitive types.", baseTypeReference->Start());
        }

        Lexer()->NextToken();

        while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
            ir::Expression *argument = ParseExpression();
            arguments.push_back(argument);

            if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
                Lexer()->NextToken();
                continue;
            }
        }

        endLoc = Lexer()->GetToken().End();
        Lexer()->NextToken();
    }

    ir::ClassDefinition *classDefinition {};

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        ArenaVector<ir::TSClassImplements *> implements(Allocator()->Adapter());
        auto modifiers = ir::ClassDefinitionModifiers::ANONYMOUS | ir::ClassDefinitionModifiers::HAS_SUPER;
        auto [ctor, properties, bodyRange] = ParseClassBody(modifiers);

        auto newIdent = AllocNode<ir::Identifier>("#0", Allocator());
        classDefinition = AllocNode<ir::ClassDefinition>(
            "#0", newIdent, nullptr, nullptr, std::move(implements), ctor,  // remove name
            typeReference->Clone(Allocator(), nullptr), std::move(properties), modifiers, ir::ModifierFlags::NONE,
            Language(Language::Id::ETS));

        classDefinition->SetRange(bodyRange);
    }

    return classDefinition;
}

ir::Expression *ETSParser::ParseNewExpression()
{
    lexer::SourcePosition start = Lexer()->GetToken().Start();

    Lexer()->NextToken();  // eat new

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
    ir::TypeNode *baseTypeReference = ParseBaseTypeReference(&options);
    ir::TypeNode *typeReference = baseTypeReference;
    if (typeReference == nullptr) {
        options |= TypeAnnotationParsingOptions::IGNORE_FUNCTION_TYPE | TypeAnnotationParsingOptions::ALLOW_WILDCARD;
        typeReference = ParseTypeReference(&options);
    } else if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        ThrowSyntaxError("Invalid { after base types.");
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
        Lexer()->NextToken();
        ir::Expression *dimension = ParseExpression();

        auto endLoc = Lexer()->GetToken().End();
        ExpectToken(lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET);

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
            auto *arrInstance = AllocNode<ir::ETSNewArrayInstanceExpression>(typeReference, dimension);
            arrInstance->SetRange({start, endLoc});
            return arrInstance;
        }

        ArenaVector<ir::Expression *> dimensions(Allocator()->Adapter());
        dimensions.push_back(dimension);

        do {
            Lexer()->NextToken();
            dimensions.push_back(ParseExpression());

            endLoc = Lexer()->GetToken().End();
            ExpectToken(lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET);
        } while (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET);

        auto *multiArray = AllocNode<ir::ETSNewMultiDimArrayInstanceExpression>(typeReference, std::move(dimensions));
        multiArray->SetRange({start, endLoc});
        return multiArray;
    }

    ArenaVector<ir::Expression *> arguments(Allocator()->Adapter());
    ir::ClassDefinition *classDefinition =
        CreateClassDefinitionForNewExpression(arguments, typeReference, baseTypeReference);

    auto *newExprNode =
        AllocNode<ir::ETSNewClassInstanceExpression>(typeReference, std::move(arguments), classDefinition);
    newExprNode->SetRange({start, Lexer()->GetToken().End()});

    return newExprNode;
}

ir::Expression *ETSParser::ParseAsyncExpression()
{
    Lexer()->NextToken();  // eat 'async'
    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS ||
        !IsArrowFunctionExpressionStart()) {
        ThrowSyntaxError("Unexpected token. expected '('");
    }

    auto newStatus = ParserStatus::NEED_RETURN_TYPE | ParserStatus::ARROW_FUNCTION | ParserStatus::ASYNC_FUNCTION;
    auto *func = ParseFunction(newStatus);
    auto *arrowFuncNode = AllocNode<ir::ArrowFunctionExpression>(Allocator(), func);
    arrowFuncNode->SetRange(func->Range());
    return arrowFuncNode;
}

ir::Expression *ETSParser::ParseAwaitExpression()
{
    lexer::SourcePosition start = Lexer()->GetToken().Start();
    Lexer()->NextToken();
    ir::Expression *argument = ParseExpression();
    auto *awaitExpression = AllocNode<ir::AwaitExpression>(argument);
    awaitExpression->SetRange({start, Lexer()->GetToken().End()});
    return awaitExpression;
}

ir::ModifierFlags ETSParser::ParseTypeVarianceModifier(TypeAnnotationParsingOptions *const options)
{
    if ((*options & TypeAnnotationParsingOptions::ALLOW_WILDCARD) == 0 &&
        (*options & TypeAnnotationParsingOptions::ALLOW_DECLARATION_SITE_VARIANCE) == 0) {
        ThrowSyntaxError("Variance modifier is not allowed here.");
    }

    switch (Lexer()->GetToken().KeywordType()) {
        case lexer::TokenType::KEYW_IN: {
            Lexer()->NextToken();
            return ir::ModifierFlags::IN;
        }
        case lexer::TokenType::KEYW_OUT: {
            Lexer()->NextToken();
            return ir::ModifierFlags::OUT;
        }
        default: {
            return ir::ModifierFlags::NONE;
        }
    }
}

ir::TSTypeParameter *ETSParser::ParseTypeParameter([[maybe_unused]] TypeAnnotationParsingOptions *options)
{
    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();

    const auto varianceModifier = [this, options] {
        switch (Lexer()->GetToken().KeywordType()) {
            case lexer::TokenType::KEYW_IN:
            case lexer::TokenType::KEYW_OUT:
                return ParseTypeVarianceModifier(options);
            default:
                return ir::ModifierFlags::NONE;
        }
    }();

    auto *paramIdent = ExpectIdentifier();

    ir::TypeNode *constraint = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_EXTENDS) {
        Lexer()->NextToken();
        TypeAnnotationParsingOptions newOptions = TypeAnnotationParsingOptions::THROW_ERROR |
                                                  TypeAnnotationParsingOptions::ALLOW_INTERSECTION |
                                                  TypeAnnotationParsingOptions::IGNORE_FUNCTION_TYPE;
        constraint = ParseTypeAnnotation(&newOptions);
    }

    ir::TypeNode *defaultType = nullptr;

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        Lexer()->NextToken();  // eat '='
        defaultType = ParseTypeAnnotation(options);
    }

    auto *typeParam = AllocNode<ir::TSTypeParameter>(paramIdent, constraint, defaultType, varianceModifier);

    typeParam->SetRange({startLoc, Lexer()->GetToken().End()});
    return typeParam;
}

// NOLINTBEGIN(cert-err58-cpp)
static std::string const DUPLICATE_ENUM_VALUE = "Duplicate enum initialization value "s;
static std::string const INVALID_ENUM_TYPE = "Invalid enum initialization type"s;
static std::string const INVALID_ENUM_VALUE = "Invalid enum initialization value"s;
static std::string const MISSING_COMMA_IN_ENUM = "Missing comma between enum constants"s;
static std::string const TRAILING_COMMA_IN_ENUM = "Trailing comma is not allowed in enum constant list"s;
// NOLINTEND(cert-err58-cpp)

ir::TSEnumDeclaration *ETSParser::ParseEnumMembers(ir::Identifier *const key, const lexer::SourcePosition &enumStart,
                                                   const bool isConst, const bool isStatic)
{
    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        ThrowSyntaxError("'{' expected");
    }

    Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat '{'

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        ThrowSyntaxError("An enum must have at least one enum constant");
    }

    // Lambda to check if enum underlying type is string:
    auto const isStringEnum = [this]() -> bool {
        Lexer()->NextToken();
        auto tokenType = Lexer()->GetToken().Type();
        while (tokenType != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE &&
               tokenType != lexer::TokenType::PUNCTUATOR_COMMA) {
            if (tokenType == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
                Lexer()->NextToken();
                if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_STRING) {
                    return true;
                }
            }
            Lexer()->NextToken();
            tokenType = Lexer()->GetToken().Type();
        }
        return false;
    };

    // Get the underlying type of enum (number or string). It is defined from the first element ONLY!
    auto const pos = Lexer()->Save();
    auto const stringTypeEnum = isStringEnum();
    Lexer()->Rewind(pos);

    ArenaVector<ir::AstNode *> members(Allocator()->Adapter());

    if (stringTypeEnum) {
        ParseStringEnum(members);
    } else {
        ParseNumberEnum(members);
    }

    auto *const enumDeclaration =
        AllocNode<ir::TSEnumDeclaration>(Allocator(), key, std::move(members), isConst, isStatic, InAmbientContext());
    enumDeclaration->SetRange({enumStart, Lexer()->GetToken().End()});

    Lexer()->NextToken();  // eat '}'

    return enumDeclaration;
}

void ETSParser::ParseNumberEnum(ArenaVector<ir::AstNode *> &members)
{
    checker::ETSEnumType::ValueType currentValue {};

    // Lambda to parse enum member (maybe with initializer)
    auto const parseMember = [this, &members, &currentValue]() {
        auto *const ident = ExpectIdentifier(false, true);

        ir::NumberLiteral *ordinal;
        lexer::SourcePosition endLoc;

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
            // Case when user explicitly set the value for enumeration constant

            bool minusSign = false;

            Lexer()->NextToken();
            if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PLUS) {
                Lexer()->NextToken();
            } else if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MINUS) {
                minusSign = true;
                Lexer()->NextToken();
            }

            if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_NUMBER) {
                ThrowSyntaxError(INVALID_ENUM_TYPE);
            }

            ordinal = ParseNumberLiteral()->AsNumberLiteral();
            if (minusSign) {
                ordinal->Number().Negate();
            }
            if (!ordinal->Number().CanGetValue<checker::ETSEnumType::ValueType>()) {
                ThrowSyntaxError(INVALID_ENUM_VALUE);
            }

            currentValue = ordinal->Number().GetValue<checker::ETSEnumType::ValueType>();

            endLoc = ordinal->End();
        } else {
            // Default enumeration constant value. Equal to 0 for the first item and = previous_value + 1 for all
            // the others.

            ordinal = AllocNode<ir::NumberLiteral>(lexer::Number(currentValue));

            endLoc = ident->End();
        }

        auto *const member = AllocNode<ir::TSEnumMember>(ident, ordinal);
        member->SetRange({ident->Start(), endLoc});
        members.emplace_back(member);

        ++currentValue;
    };

    parseMember();

    while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COMMA) {
            ThrowSyntaxError(MISSING_COMMA_IN_ENUM);
        }

        Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat ','

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
            break;
        }

        parseMember();
    }
}

void ETSParser::ParseStringEnum(ArenaVector<ir::AstNode *> &members)
{
    // Lambda to parse enum member (maybe with initializer)
    auto const parseMember = [this, &members]() {
        auto *const ident = ExpectIdentifier();

        ir::StringLiteral *itemValue;

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
            // Case when user explicitly set the value for enumeration constant

            Lexer()->NextToken();
            if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_STRING) {
                ThrowSyntaxError(INVALID_ENUM_TYPE);
            }

            itemValue = ParseStringLiteral();
        } else {
            // Default item value is not allowed for string type enumerations!
            ThrowSyntaxError("All items of string-type enumeration should be explicitly initialized.");
        }

        auto *const member = AllocNode<ir::TSEnumMember>(ident, itemValue);
        member->SetRange({ident->Start(), itemValue->End()});
        members.emplace_back(member);
    };

    parseMember();

    while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COMMA) {
            ThrowSyntaxError(MISSING_COMMA_IN_ENUM);
        }

        Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat ','

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
            ThrowSyntaxError(TRAILING_COMMA_IN_ENUM);
        }

        parseMember();
    }
}

ir::ThisExpression *ETSParser::ParseThisExpression()
{
    auto *thisExpression = TypedParser::ParseThisExpression();

    if (Lexer()->GetToken().NewLine()) {
        return thisExpression;
    }

    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::PUNCTUATOR_PERIOD:
        case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS:
        case lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS:
        case lexer::TokenType::PUNCTUATOR_SEMI_COLON:
        case lexer::TokenType::PUNCTUATOR_COLON:
        case lexer::TokenType::PUNCTUATOR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_STRICT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_COMMA:
        case lexer::TokenType::PUNCTUATOR_QUESTION_MARK:
        case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET:
        case lexer::TokenType::KEYW_INSTANCEOF:
        case lexer::TokenType::KEYW_AS: {
            break;
        }
        default: {
            ThrowUnexpectedToken(Lexer()->GetToken().Type());
            break;
        }
    }

    return thisExpression;
}

ir::Identifier *ETSParser::ParseClassIdent([[maybe_unused]] ir::ClassDefinitionModifiers modifiers)
{
    return ExpectIdentifier(false, true);
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

bool ETSParser::CheckClassElement(ir::AstNode *property, [[maybe_unused]] ir::MethodDefinition *&ctor,
                                  [[maybe_unused]] ArenaVector<ir::AstNode *> &properties)
{
    if (property->IsClassStaticBlock()) {
        if (std::any_of(properties.cbegin(), properties.cend(),
                        [](const auto *prop) { return prop->IsClassStaticBlock(); })) {
            ThrowSyntaxError("Only one static block is allowed", property->Start());
        }

        auto *id = AllocNode<ir::Identifier>(compiler::Signatures::CCTOR, Allocator());
        property->AsClassStaticBlock()->Function()->SetIdent(id);
    }

    if (property->IsTSInterfaceBody()) {
        return CheckClassElementInterfaceBody(property, properties);
    }

    if (!property->IsMethodDefinition()) {
        return false;
    }

    auto const *const method = property->AsMethodDefinition();
    auto const *const function = method->Function();

    //  Check the special '$_get' and '$_set' methods using for object's index access
    if (method->Kind() == ir::MethodDefinitionKind::METHOD) {
        CheckPredefinedMethods(function, property->Start());
    }

    return false;  // resolve overloads later on scopes stage
}

void ETSParser::CheckPredefinedMethods(ir::ScriptFunction const *function, const lexer::SourcePosition &position) const
{
    auto const name = function->Id()->Name();

    auto const checkAsynchronous = [this, function, &name, &position]() -> void {
        if (function->IsAsyncFunc()) {
            ThrowSyntaxError(std::string {ir::PREDEFINED_METHOD} + std::string {name.Utf8()} +
                                 std::string {"' cannot be asynchronous."},
                             position);
        }
    };

    if (name.Is(compiler::Signatures::GET_INDEX_METHOD)) {
        checkAsynchronous();

        bool isValid = function->Params().size() == 1U;
        if (isValid) {
            auto const *const param = function->Params()[0]->AsETSParameterExpression();
            isValid = !param->IsDefault() && !param->IsRestParameter();
        }

        if (!isValid) {
            ThrowSyntaxError(std::string {ir::PREDEFINED_METHOD} + std::string {name.Utf8()} +
                                 std::string {"' should have exactly one required parameter."},
                             position);
        }
    } else if (name.Is(compiler::Signatures::SET_INDEX_METHOD)) {
        checkAsynchronous();

        bool isValid = function->Params().size() == 2U;
        if (isValid) {
            auto const *const param1 = function->Params()[0]->AsETSParameterExpression();
            auto const *const param2 = function->Params()[1]->AsETSParameterExpression();
            isValid = !param1->IsDefault() && !param1->IsRestParameter() && !param2->IsDefault() &&
                      !param2->IsRestParameter();
        }

        if (!isValid) {
            ThrowSyntaxError(std::string {ir::PREDEFINED_METHOD} + std::string {name.Utf8()} +
                                 std::string {"' should have exactly two required parameters."},
                             position);
        }
    } else if (name.Is(compiler::Signatures::ITERATOR_METHOD)) {
        checkAsynchronous();

        if (!function->Params().empty()) {
            ThrowSyntaxError(std::string {ir::PREDEFINED_METHOD} + std::string {name.Utf8()} +
                                 std::string {"' should not have parameters."},
                             position);
        }
    }
}

void ETSParser::CreateImplicitConstructor([[maybe_unused]] ir::MethodDefinition *&ctor,
                                          ArenaVector<ir::AstNode *> &properties,
                                          [[maybe_unused]] ir::ClassDefinitionModifiers modifiers,
                                          const lexer::SourcePosition &startLoc)
{
    if (std::any_of(properties.cbegin(), properties.cend(), [](ir::AstNode *prop) {
            return prop->IsMethodDefinition() && prop->AsMethodDefinition()->IsConstructor();
        })) {
        return;
    }

    if ((modifiers & ir::ClassDefinitionModifiers::ANONYMOUS) != 0) {
        return;
    }

    auto *methodDef = BuildImplicitConstructor(ir::ClassDefinitionModifiers::SET_CTOR_ID, startLoc);
    properties.push_back(methodDef);
}

ir::Expression *ETSParser::ParsePotentialExpressionSequence(ir::Expression *expr, ExpressionParseFlags flags)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA &&
        (flags & ExpressionParseFlags::ACCEPT_COMMA) != 0 && (flags & ExpressionParseFlags::IN_FOR) != 0U) {
        return ParseSequenceExpression(expr, (flags & ExpressionParseFlags::ACCEPT_REST) != 0);
    }

    return expr;
}

bool ETSParser::ParsePotentialNonNullExpression(ir::Expression **expression, const lexer::SourcePosition startLoc)
{
    if (expression == nullptr || Lexer()->GetToken().NewLine()) {
        return true;
    }

    const auto nonNullExpr = AllocNode<ir::TSNonNullExpression>(*expression);
    nonNullExpr->SetRange({startLoc, Lexer()->GetToken().End()});

    *expression = nonNullExpr;

    Lexer()->NextToken();

    return false;
}

bool ETSParser::IsStructKeyword() const
{
    return (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT &&
            Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_STRUCT);
}

void ETSParser::ValidateInstanceOfExpression(ir::Expression *expr)
{
    ValidateGroupedExpression(expr);
    lexer::TokenType tokenType = Lexer()->GetToken().Type();
    if (tokenType == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        auto options = TypeAnnotationParsingOptions::NO_OPTS;

        // Run checks to validate type declarations
        // Should provide helpful messages with incorrect declarations like the following:
        // `instanceof A<String;`
        ParseTypeParameterDeclaration(&options);

        // Display error message even when type declaration is correct
        // `instanceof A<String>;`
        ThrowSyntaxError("Invalid right-hand side in 'instanceof' expression");
    }
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ETSParser::ParseExpression(ExpressionParseFlags flags)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_YIELD &&
        (flags & ExpressionParseFlags::DISALLOW_YIELD) == 0U) {
        ir::YieldExpression *yieldExpr = ParseYieldExpression();

        return ParsePotentialExpressionSequence(yieldExpr, flags);
    }

    ir::Expression *unaryExpressionNode = ParseUnaryOrPrefixUpdateExpression(flags);
    if ((flags & ExpressionParseFlags::INSTANCEOF) != 0) {
        ValidateInstanceOfExpression(unaryExpressionNode);
    }

    ir::Expression *assignmentExpression = ParseAssignmentExpression(unaryExpressionNode, flags);

    if (Lexer()->GetToken().NewLine()) {
        return assignmentExpression;
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA &&
        (flags & ExpressionParseFlags::ACCEPT_COMMA) != 0U && (flags & ExpressionParseFlags::IN_FOR) != 0U) {
        return ParseSequenceExpression(assignmentExpression, (flags & ExpressionParseFlags::ACCEPT_REST) != 0U);
    }

    return assignmentExpression;
}

void ETSParser::ParseTrailingBlock(ir::CallExpression *callExpr)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        callExpr->SetIsTrailingBlockInNewLine(Lexer()->GetToken().NewLine());
        callExpr->SetTrailingBlock(ParseBlockStatement());
    }
}

ir::Expression *ETSParser::ParseCoercedNumberLiteral()
{
    if ((Lexer()->GetToken().Flags() & lexer::TokenFlags::NUMBER_FLOAT) != 0U) {
        auto *number = AllocNode<ir::NumberLiteral>(Lexer()->GetToken().GetNumber());
        number->SetRange(Lexer()->GetToken().Loc());
        auto *floatType = AllocNode<ir::ETSPrimitiveType>(ir::PrimitiveType::FLOAT);
        floatType->SetRange(Lexer()->GetToken().Loc());
        auto *asExpression = AllocNode<ir::TSAsExpression>(number, floatType, true);
        asExpression->SetRange(Lexer()->GetToken().Loc());

        Lexer()->NextToken();
        return asExpression;
    }
    return ParseNumberLiteral();
}

void ETSParser::CheckDeclare()
{
    ASSERT(Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_DECLARE);

    if (InAmbientContext()) {
        ThrowSyntaxError("A 'declare' modifier cannot be used in an already ambient context.");
    }

    GetContext().Status() |= ParserStatus::IN_AMBIENT_CONTEXT;

    Lexer()->NextToken();  // eat 'declare'

    switch (Lexer()->GetToken().KeywordType()) {
        case lexer::TokenType::KEYW_LET:
        case lexer::TokenType::KEYW_CONST:
        case lexer::TokenType::KEYW_FUNCTION:
        case lexer::TokenType::KEYW_CLASS:
        case lexer::TokenType::KEYW_NAMESPACE:
        case lexer::TokenType::KEYW_ENUM:
        case lexer::TokenType::KEYW_TYPE:
        case lexer::TokenType::KEYW_ABSTRACT:
        case lexer::TokenType::KEYW_INTERFACE: {
            return;
        }
        default: {
            ThrowSyntaxError("Unexpected token.");
        }
    }
}

ir::FunctionDeclaration *ETSParser::ParseFunctionDeclaration(bool canBeAnonymous, ir::ModifierFlags modifiers)
{
    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();

    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::KEYW_FUNCTION);
    Lexer()->NextToken();
    auto newStatus = ParserStatus::NEED_RETURN_TYPE | ParserStatus::ALLOW_SUPER;

    if ((modifiers & ir::ModifierFlags::ASYNC) != 0) {
        newStatus |= ParserStatus::ASYNC_FUNCTION;
    }
    if (Lexer()->TryEatTokenType(lexer::TokenType::PUNCTUATOR_MULTIPLY)) {
        newStatus |= ParserStatus::GENERATOR_FUNCTION;
    }

    ir::Identifier *className = nullptr;
    ir::Identifier *identNode = nullptr;
    if (Lexer()->Lookahead() == lexer::LEX_CHAR_DOT) {
        className = ExpectIdentifier();
        if (className != nullptr) {
            newStatus |= ParserStatus::IN_EXTENSION_FUNCTION;
        }
        Lexer()->NextToken();
        identNode = ExpectIdentifier();
    } else if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
        identNode = ExpectIdentifier();
    } else if (!canBeAnonymous) {
        ThrowSyntaxError("Unexpected token, expected identifier after 'function' keyword");
    }
    newStatus |= ParserStatus::FUNCTION_DECLARATION;
    if (identNode != nullptr) {
        CheckRestrictedBinding(identNode->Name(), identNode->Start());
    }
    ir::ScriptFunction *func = ParseFunction(newStatus, className);
    func->SetIdent(identNode);
    auto *funcDecl = AllocNode<ir::FunctionDeclaration>(Allocator(), func);
    if (func->IsOverload() && Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
        Lexer()->NextToken();
    }
    funcDecl->SetRange(func->Range());
    func->AddModifier(modifiers);
    func->SetStart(startLoc);

    if (className != nullptr) {
        func->AddFlag(ir::ScriptFunctionFlags::INSTANCE_EXTENSION_METHOD);
    }

    return funcDecl;
}

std::pair<ir::ModifierFlags, lexer::SourcePosition> ETSParser::ParseMemberModifiers()
{
    auto memberModifiers = ir::ModifierFlags::STATIC | ir::ModifierFlags::PUBLIC;

    if (Lexer()->TryEatTokenType(lexer::TokenType::KEYW_EXPORT)) {
        if (Lexer()->TryEatTokenKeyword(lexer::TokenType::KEYW_DEFAULT)) {
            memberModifiers |= ir::ModifierFlags::DEFAULT_EXPORT;
        } else {
            memberModifiers |= ir::ModifierFlags::EXPORT;
        }
    }

    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_DECLARE) {
        CheckDeclare();
        memberModifiers |= ir::ModifierFlags::DECLARE;
    }
    const auto tokenType = Lexer()->GetToken().KeywordType();
    if (tokenType == lexer::TokenType::KEYW_ASYNC || tokenType == lexer::TokenType::KEYW_NATIVE) {
        bool isAsync = tokenType == lexer::TokenType::KEYW_ASYNC;

        if (isAsync) {
            memberModifiers |= ir::ModifierFlags::ASYNC;
        } else {
            memberModifiers |= ir::ModifierFlags::NATIVE;
        }
        Lexer()->NextToken();

        if (Lexer()->GetToken().Type() != lexer::TokenType::KEYW_FUNCTION) {
            ThrowSyntaxError(
                {isAsync ? "'async'" : "'native'", " flags must be used for functions only at top-level."});
        }
    }
    return std::make_pair(memberModifiers, startLoc);
}

//================================================================================================//
//  ExternalSourceParser class
//================================================================================================//

ExternalSourceParser::ExternalSourceParser(ETSParser *parser, Program *newProgram)
    : parser_(parser),
      savedProgram_(parser_->GetProgram()),
      savedLexer_(parser_->Lexer()),
      savedTopScope_(parser_->GetProgram()->VarBinder()->TopScope())
{
    parser_->SetProgram(newProgram);
    parser_->GetContext().SetProgram(newProgram);
}

ExternalSourceParser::~ExternalSourceParser()
{
    parser_->SetLexer(savedLexer_);
    parser_->SetProgram(savedProgram_);
    parser_->GetContext().SetProgram(savedProgram_);
    parser_->GetProgram()->VarBinder()->ResetTopScope(savedTopScope_);
}

//================================================================================================//
//  InnerSourceParser class
//================================================================================================//

InnerSourceParser::InnerSourceParser(ETSParser *parser)
    : parser_(parser),
      savedLexer_(parser_->Lexer()),
      savedSourceCode_(parser_->GetProgram()->SourceCode()),
      savedSourceFile_(parser_->GetProgram()->SourceFilePath()),
      savedSourceFilePath_(parser_->GetProgram()->SourceFileFolder())
{
}

InnerSourceParser::~InnerSourceParser()
{
    parser_->SetLexer(savedLexer_);
    parser_->GetProgram()->SetSource(savedSourceCode_, savedSourceFile_, savedSourceFilePath_);
}
}  // namespace ark::es2panda::parser
