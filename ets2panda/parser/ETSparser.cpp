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
#include <utility>

#include "util/es2pandaMacros.h"
#include "parser/parserFlags.h"
#include "parser/parserStatusContext.h"
#include "util/helpers.h"
#include "util/language.h"
#include "util/options.h"
#include "utils/arena_containers.h"
#include "varbinder/varbinder.h"
#include "varbinder/ETSBinder.h"
#include "lexer/lexer.h"
#include "lexer/ETSLexer.h"
#include "ir/astNode.h"
#include "ir/base/decorator.h"
#include "ir/base/catchClause.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/spreadElement.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/dummyNode.h"
#include "ir/module/importDeclaration.h"
#include "ir/module/importDefaultSpecifier.h"
#include "ir/module/importSpecifier.h"
#include "ir/module/exportSpecifier.h"
#include "ir/module/exportNamedDeclaration.h"
#include "ir/ets/etsPrimitiveType.h"
#include "ir/ets/etsPackageDeclaration.h"
#include "ir/ets/etsReExportDeclaration.h"
#include "ir/ets/etsWildcardType.h"
#include "ir/ets/etsTuple.h"
#include "ir/ets/etsFunctionType.h"
#include "ir/ets/etsModule.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/ets/etsNullishTypes.h"
#include "ir/ets/etsUnionType.h"
#include "ir/ets/etsImportDeclaration.h"
#include "ir/ets/etsStructDeclaration.h"
#include "ir/module/importNamespaceSpecifier.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "ir/ts/tsTypeParameterInstantiation.h"
#include "ir/ts/tsInterfaceBody.h"
#include "ir/ts/tsImportEqualsDeclaration.h"
#include "ir/ts/tsArrayType.h"
#include "ir/ts/tsQualifiedName.h"
#include "ir/ts/tsTypeReference.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ts/tsInterfaceHeritage.h"
#include "ir/ts/tsFunctionType.h"
#include "ir/ts/tsTypeAliasDeclaration.h"
#include "ir/ts/tsTypeParameterDeclaration.h"
#include "ir/ts/tsThisType.h"
#include "generated/signatures.h"
#include "generated/diagnostic.h"

namespace ark::es2panda::parser {
class FunctionContext;

using namespace std::literals::string_literals;

ETSParser::ETSParser(Program *program, const util::Options &options, util::DiagnosticEngine &diagnosticEngine,
                     ParserStatus status)
    : TypedParser(program, &options, diagnosticEngine, status), globalProgram_(GetProgram())
{
    namespaceNestedRank_ = 0;
    importPathManager_ =
        std::make_unique<util::ImportPathManager>(Allocator(), options, GetProgram(), diagnosticEngine);
}

ETSParser::ETSParser(Program *program, std::nullptr_t, util::DiagnosticEngine &diagnosticEngine)
    : TypedParser(program, nullptr, diagnosticEngine, ParserStatus::NO_OPTS), globalProgram_(GetProgram())
{
    namespaceNestedRank_ = 0;
}

bool ETSParser::IsETSParser() const noexcept
{
    return true;
}

std::unique_ptr<lexer::Lexer> ETSParser::InitLexer(const SourceFile &sourceFile)
{
    GetProgram()->SetSource(sourceFile);
    auto lexer = std::make_unique<lexer::ETSLexer>(&GetContext(), DiagnosticEngine());
    SetLexer(lexer.get());
    return lexer;
}

void ETSParser::ParseProgram(ScriptKind kind)
{
    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();
    Lexer()->NextToken();
    GetProgram()->SetKind(kind);
    GetProgram()->SetRelativeFilePath(importPathManager_->FormRelativePath(GetProgram()->SourceFile()));

    if (GetProgram()->SourceFilePath().Utf8()[0] == '@') {
        // NOTE(user): handle multiple sourceFiles
    }

    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());
    auto decl = ParsePackageDeclaration();
    if (decl != nullptr) {
        statements.emplace_back(decl);
        // If we found a package declaration, then add all files with the same package to the package parse list
        AddPackageSourcesToParseList();
    }

    ir::ETSModule *script;
    if ((GetContext().Status() & parser::ParserStatus::DEPENDENCY_ANALYZER_MODE) == 0) {
        script = ParseETSGlobalScript(startLoc, statements);
    } else {
        script = ParseImportsOnly(startLoc, statements);
    }

    AddExternalSource(ParseSources(true));
    GetProgram()->SetAst(script);
}

ir::ETSModule *ETSParser::ParseETSGlobalScript(lexer::SourcePosition startLoc, ArenaVector<ir::Statement *> &statements)
{
    ETSNolintParser etsnolintParser(this);
    etsnolintParser.CollectETSNolints();

    auto imports = ParseImportDeclarations();
    statements.insert(statements.end(), imports.begin(), imports.end());

    auto topLevelStatements = ParseTopLevelDeclaration();
    statements.insert(statements.end(), topLevelStatements.begin(), topLevelStatements.end());

    etsnolintParser.ApplyETSNolintsToStatements(statements);

    auto ident = AllocNode<ir::Identifier>(compiler::Signatures::ETS_GLOBAL, Allocator());
    auto *etsModule =
        AllocNode<ir::ETSModule>(Allocator(), std::move(statements), ident, ir::ModuleFlag::ETSSCRIPT, GetProgram());
    etsModule->SetRange({startLoc, Lexer()->GetToken().End()});
    return etsModule;
}

ir::ETSModule *ETSParser::ParseImportsOnly(lexer::SourcePosition startLoc, ArenaVector<ir::Statement *> &statements)
{
    ETSNolintParser etsnolintParser(this);
    etsnolintParser.CollectETSNolints();

    auto imports = ParseImportDeclarations();
    statements.insert(statements.end(), imports.begin(), imports.end());
    etsnolintParser.ApplyETSNolintsToStatements(statements);

    auto ident = AllocNode<ir::Identifier>(compiler::Signatures::ETS_GLOBAL, Allocator());
    auto *etsModule =
        AllocNode<ir::ETSModule>(Allocator(), std::move(statements), ident, ir::ModuleFlag::ETSSCRIPT, GetProgram());
    etsModule->SetRange({startLoc, Lexer()->GetToken().End()});
    return etsModule;
}

void ETSParser::AddExternalSource(const std::vector<Program *> &programs)
{
    auto &extSources = globalProgram_->ExternalSources();

    for (auto *newProg : programs) {
        const util::StringView name = newProg->ModuleName();
        if (extSources.count(name) == 0) {
            extSources.try_emplace(name, Allocator()->Adapter());
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

void ETSParser::AddDirectImportsToDirectExternalSources(
    const ArenaVector<util::StringView> &directImportsFromMainSource, parser::Program *const newProg) const
{
    if (std::find_if(directImportsFromMainSource.begin(), directImportsFromMainSource.end(),
                     [newProg](const util::StringView &sv) { return sv == newProg->AbsoluteName(); }) ==
        directImportsFromMainSource.end()) {
        return;
    }

    const util::StringView name = newProg->Ast()->Statements().empty() ? newProg->FileName() : newProg->ModuleName();
    if (GetProgram()->DirectExternalSources().count(name) == 0) {
        GetProgram()->DirectExternalSources().try_emplace(name, Allocator()->Adapter());
    }
    GetProgram()->DirectExternalSources().at(name).emplace_back(newProg);
}

void ETSParser::ParseParseListElement(const util::ImportPathManager::ParseInfo &parseListElem, util::UString *extSrc,
                                      const ArenaVector<util::StringView> &directImportsFromMainSource,
                                      std::vector<Program *> *programs)
{
    const auto &importData = parseListElem.importData;
    auto src = importData.HasSpecifiedDeclPath() ? importData.declPath : importData.resolvedSource;
    SourceFile sf {src, extSrc->View().Utf8(), importData.resolvedSource, false, importData.HasSpecifiedDeclPath()};
    parser::Program *newProg = ParseSource(sf);
    if (!importData.IsImplicitPackageImported() || newProg->IsPackage()) {
        AddDirectImportsToDirectExternalSources(directImportsFromMainSource, newProg);
        // don't insert the separate modules into the programs, when we collect implicit package imports
        programs->emplace_back(newProg);
    }
}

std::vector<Program *> ETSParser::ParseSources(bool firstSource)
{
    std::vector<Program *> programs;

    auto &parseList = importPathManager_->ParseList();

    ArenaVector<util::StringView> directImportsFromMainSource(Allocator()->Adapter());

    if (firstSource) {
        for (auto pl : parseList) {
            if (pl.isParsed) {
                // Handle excluded files, which are already set to be parsed before parsing them
                continue;
            }
            directImportsFromMainSource.emplace_back(pl.importData.resolvedSource);
        }
    }

    auto notParsedElement =
        std::find_if(parseList.begin(), parseList.end(), [](const auto &parseInfo) { return !parseInfo.isParsed; });

    // NOTE (mmartin): Need a more optimal solution here
    // This is needed, as during a parsing of a file, programs can be re-added to the parseList, which needs to be
    // re-parsed. This won't change the size of the list, so with only the 'for loop', there can be unparsed files
    // remained.
    // An example for this, is when a file is added as an implicit package import, but it's erroneous, so we just ignore
    // the file. But when the same file is also added with an explicit import declaration, then we need to re-parse it,
    // and throw the syntax error.
    while (notParsedElement != parseList.end()) {
        // This parse list `paths` can grow in the meantime, so keep this index-based iteration
        // NOLINTNEXTLINE(modernize-loop-convert)
        for (size_t idx = 0; idx < parseList.size(); idx++) {
            // check if already parsed
            if (parseList[idx].isParsed) {
                continue;
            }
            const auto &data = parseList[idx].importData;
            if (data.declPath.empty()) {
                importPathManager_->MarkAsParsed(data.resolvedSource);
                continue;
            }
            ES2PANDA_ASSERT(data.lang != Language::Id::COUNT);
            auto parseCandidate = data.HasSpecifiedDeclPath() ? data.declPath : data.resolvedSource;
            if (GetProgram()->SourceFilePath().Is(parseCandidate)) {
                importPathManager_->MarkAsParsed(data.resolvedSource);
                return programs;
            }

            util::DiagnosticMessageParams diagParams = {std::string(parseCandidate)};
            std::ifstream inputStream {std::string(parseCandidate)};
            if (!inputStream) {
                DiagnosticEngine().LogDiagnostic(diagnostic::OPEN_FAILED, diagParams);
                return programs;  // Error processing.
            }

            std::stringstream ss;
            ss << inputStream.rdbuf();
            std::string externalSource = ss.str();

            auto preservedLang = GetContext().SetLanguage(data.lang);
            auto extSrc = Allocator()->New<util::UString>(externalSource, Allocator());
            importPathManager_->MarkAsParsed(data.resolvedSource);

            ParseParseListElement(parseList[idx], extSrc, directImportsFromMainSource, &programs);

            GetContext().SetLanguage(preservedLang);
        }

        notParsedElement =
            std::find_if(parseList.begin(), parseList.end(), [](const auto &parseInfo) { return !parseInfo.isParsed; });
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

ir::Statement *ETSParser::ParseIdentKeyword()
{
    const auto token = Lexer()->GetToken();
    ES2PANDA_ASSERT(token.Type() == lexer::TokenType::LITERAL_IDENT);
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

ir::ScriptFunction *ETSParser::ParseFunction(ParserStatus newStatus)
{
    FunctionContext functionContext(this, newStatus | ParserStatus::FUNCTION);
    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();
    auto [signature, throwMarker] = ParseFunctionSignature(newStatus);

    ir::AstNode *body = nullptr;
    lexer::SourcePosition endLoc = startLoc;
    bool isOverload = false;
    bool isArrow = (newStatus & ParserStatus::ARROW_FUNCTION) != 0;

    if ((newStatus & ParserStatus::ASYNC_FUNCTION) != 0) {
        functionContext.AddFlag(ir::ScriptFunctionFlags::ASYNC);
    }

    if (isArrow) {
        ExpectToken(lexer::TokenType::PUNCTUATOR_ARROW);
        functionContext.AddFlag(ir::ScriptFunctionFlags::ARROW);
    }

    auto &contextStatus = GetContext().Status();
    contextStatus |= ParserStatus::ALLOW_SUPER;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        std::tie(std::ignore, body, endLoc, isOverload) =
            ParseFunctionBody(signature.Params(), newStatus, contextStatus);
    } else if (isArrow) {
        body = ParseExpression();
        endLoc = body->AsExpression()->End();
        functionContext.AddFlag(ir::ScriptFunctionFlags::EXPRESSION);
    }
    contextStatus ^= ParserStatus::ALLOW_SUPER;

    if ((GetContext().Status() & ParserStatus::FUNCTION_HAS_RETURN_STATEMENT) != 0) {
        functionContext.AddFlag(ir::ScriptFunctionFlags::HAS_RETURN);
        GetContext().Status() ^= ParserStatus::FUNCTION_HAS_RETURN_STATEMENT;
    }
    if ((GetContext().Status() & ParserStatus::FUNCTION_HAS_THROW_STATEMENT) != 0) {
        functionContext.AddFlag(ir::ScriptFunctionFlags::HAS_THROW);
        GetContext().Status() ^= ParserStatus::FUNCTION_HAS_THROW_STATEMENT;
    }

    functionContext.AddFlag(throwMarker);

    bool isDeclare = InAmbientContext();
    if (functionContext.IsAsync() && isDeclare) {
        LogError(diagnostic::ASYNC_IN_AMBIENT_CONTEXT);
    }

    // clang-format off
    ir::ModifierFlags mFlags = isDeclare ? ir::ModifierFlags::DECLARE : ir::ModifierFlags::NONE;
    ir::ScriptFunctionFlags funcFlags =
        isDeclare ? (functionContext.Flags() | ir::ScriptFunctionFlags::EXTERNAL) : functionContext.Flags();
    auto *funcNode = AllocNode<ir::ScriptFunction>(
        Allocator(), ir::ScriptFunction::ScriptFunctionData {body, std::move(signature), funcFlags, mFlags,
                                                             GetContext().GetLanguage()});
    funcNode->SetRange({startLoc, endLoc});
    // clang-format on

    return funcNode;
}

std::tuple<bool, ir::BlockStatement *, lexer::SourcePosition, bool> ETSParser::ParseFunctionBody(
    // CC-OFFNXT(G.FMT.06-CPP) project code style
    [[maybe_unused]] const ArenaVector<ir::Expression *> &params, [[maybe_unused]] ParserStatus newStatus,
    [[maybe_unused]] ParserStatus contextStatus)
{
    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        LogError(diagnostic::EXPECTED_PARAM_GOT_PARAM, {"{", TokenToString(Lexer()->GetToken().Type())});
        return {false, nullptr, Lexer()->GetToken().End(), false};
    }

    ir::BlockStatement *body = ParseBlockStatement();

    return {true, body, body->End(), false};
}

ir::ScriptFunctionFlags ETSParser::ParseFunctionThrowMarker(bool isRethrowsAllowed)
{
    ir::ScriptFunctionFlags throwMarker = ir::ScriptFunctionFlags::NONE;

    if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
        if (Lexer()->TryEatTokenKeyword(lexer::TokenType::KEYW_THROWS)) {
            throwMarker = ir::ScriptFunctionFlags::THROWS;
        } else if (Lexer()->TryEatTokenKeyword(lexer::TokenType::KEYW_RETHROWS)) {
            if (isRethrowsAllowed) {
                throwMarker = ir::ScriptFunctionFlags::RETHROWS;
            } else {
                LogError(diagnostic::ONLY_THROWS_IN_FUN_TYPE);
            }
        }
    }

    return throwMarker;
}

ir::AstNode *ETSParser::ParseInnerTypeDeclaration(ir::ModifierFlags memberModifiers, lexer::LexerPosition savedPos,
                                                  bool isStepToken, bool seenStatic)
{
    if ((GetContext().Status() & ParserStatus::IN_NAMESPACE) == 0) {
        LogError(diagnostic::IMPROPER_NESTING_CLASS);
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
                                                         const lexer::SourcePosition &startLoc, bool isDefault)
{
    if ((memberModifiers & (~(ir::ModifierFlags::ACCESS | ir::ModifierFlags::DECLARE | ir::ModifierFlags::NATIVE))) !=
        0) {
        LogError(diagnostic::INVALID_DECORATOR_CONSTRUCTOR);
    }
    auto *memberName = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    memberModifiers |= ir::ModifierFlags::CONSTRUCTOR;
    Lexer()->NextToken();
    auto *classMethod = ParseClassMethodDefinition(memberName, memberModifiers, isDefault);
    classMethod->SetStart(startLoc);

    return classMethod;
}

ir::Identifier *ETSParser::CreateInvokeIdentifier()
{
    util::StringView tokenName = util::StringView {compiler::Signatures::STATIC_INVOKE_METHOD};
    auto ident = AllocNode<ir::Identifier>(tokenName, Allocator());
    ident->SetRange({Lexer()->GetToken().Start(), Lexer()->GetToken().End()});
    return ident;
}

bool ETSParser::CheckAccessorDeclaration(ir::ModifierFlags memberModifiers)
{
    if (Lexer()->GetToken().KeywordType() != lexer::TokenType::KEYW_GET &&
        Lexer()->GetToken().KeywordType() != lexer::TokenType::KEYW_SET) {
        return false;
    }
    if (Lexer()->Lookahead() == lexer::LEX_CHAR_LEFT_PAREN || Lexer()->Lookahead() == lexer::LEX_CHAR_LESS_THAN) {
        return false;
    }
    ir::ModifierFlags methodModifiersNotAccessorModifiers = ir::ModifierFlags::ASYNC;
    if ((memberModifiers & methodModifiersNotAccessorModifiers) != 0) {
        LogError(diagnostic::MODIFIERS_OF_GET_SET_LIMITED);
    }
    return true;
}

ir::AstNode *ETSParser::ParseInnerRest(const ArenaVector<ir::AstNode *> &properties,
                                       ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags memberModifiers,
                                       const lexer::SourcePosition &startLoc, bool isDefault)
{
    if (CheckAccessorDeclaration(memberModifiers)) {
        return ParseClassGetterSetterMethod(properties, modifiers, memberModifiers, isDefault);
    }

    if ((GetContext().Status() & ParserStatus::IN_NAMESPACE) != 0) {
        auto type = Lexer()->GetToken().Type();
        if (type == lexer::TokenType::KEYW_FUNCTION || type == lexer::TokenType::KEYW_LET ||
            type == lexer::TokenType::KEYW_CONST) {
            Lexer()->NextToken();
        }
    }

    auto parseClassMethod = [&memberModifiers, &startLoc, isDefault, this](ir::Identifier *methodName) {
        auto *classMethod = ParseClassMethodDefinition(methodName, memberModifiers, isDefault);
        classMethod->SetStart(startLoc);
        return classMethod;
    };

    if (InAmbientContext()) {
        auto *property = HandleAmbientDeclaration(memberModifiers, parseClassMethod);
        if (property != nullptr) {
            return property;
        }
    }

    auto *memberName = ExpectIdentifier(false, false, TypeAnnotationParsingOptions::NO_OPTS);  // don't report error
    if (memberName == nullptr) {                                                               // log error here
        LogUnexpectedToken(Lexer()->GetToken());
        const auto &rangeToken = Lexer()->GetToken().Loc();
        Lexer()->NextToken();
        return AllocBrokenStatement(rangeToken);
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS ||
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        return parseClassMethod(memberName);
    }

    ArenaVector<ir::AstNode *> fieldDeclarations(Allocator()->Adapter());
    auto *placeholder = AllocNode<ir::TSInterfaceBody>(std::move(fieldDeclarations));
    ParseClassFieldDefinition(memberName, memberModifiers, placeholder->BodyPtr(), isDefault);
    return placeholder;
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

    LogUnexpectedToken(Lexer()->GetToken());
    return nullptr;
}

ir::Statement *ETSParser::ParseTypeDeclaration(bool allowStatic)
{
    auto savedPos = Lexer()->Save();

    auto modifiers = ir::ClassDefinitionModifiers::ID_REQUIRED | ir::ClassDefinitionModifiers::CLASS_DECL;

    auto tokenType = Lexer()->GetToken().Type();
    switch (tokenType) {
        case lexer::TokenType::KEYW_STATIC:
            if (!allowStatic) {
                LogUnexpectedToken(Lexer()->GetToken());
            }

            Lexer()->NextToken();

            if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_INTERFACE) {
                return ParseInterfaceDeclaration(true);
            }

            if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
                Lexer()->Rewind(savedPos);
                return ParseClassStaticBlock();
            }

            Lexer()->Rewind(savedPos);
            [[fallthrough]];
        case lexer::TokenType::KEYW_ABSTRACT:
        case lexer::TokenType::KEYW_FINAL:
            return ParseTypeDeclarationAbstractFinal(allowStatic, modifiers);
        case lexer::TokenType::KEYW_ENUM:
            return ParseEnumDeclaration(false);
        case lexer::TokenType::KEYW_INTERFACE:
            return ParseInterfaceDeclaration(false);
        case lexer::TokenType::KEYW_CLASS:
            return ParseClassDeclaration(modifiers);
        case lexer::TokenType::KEYW_STRUCT:
            return ParseStructDeclaration(modifiers);
        case lexer::TokenType::LITERAL_IDENT:
            if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_STRUCT) {
                return ParseStructDeclaration(modifiers);
            }
            [[fallthrough]];
        default:
            const auto &tokenNow = Lexer()->GetToken();
            LogUnexpectedToken(tokenNow);
            return AllocBrokenStatement(tokenNow.Loc());
    }
}

ir::TSTypeAliasDeclaration *ETSParser::ParseTypeAliasDeclaration()
{
    ES2PANDA_ASSERT(Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_TYPE);

    lexer::SourcePosition typeStart = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat type keyword

    if (Lexer()->GetToken().IsReservedTypeName() && !util::Helpers::IsStdLib(GetProgram())) {
        LogError(diagnostic::TYPE_ALIAS_INVALID_NAME, {TokenToString(Lexer()->GetToken().KeywordType())});
    }

    ir::Identifier *id = ExpectIdentifier();

    auto *typeAliasDecl = AllocNode<ir::TSTypeAliasDeclaration>(Allocator(), id);

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        auto options =
            TypeAnnotationParsingOptions::REPORT_ERROR | TypeAnnotationParsingOptions::ALLOW_DECLARATION_SITE_VARIANCE;
        ir::TSTypeParameterDeclaration *params = ParseTypeParameterDeclaration(&options);
        typeAliasDecl->SetTypeParameters(params);
        params->SetParent(typeAliasDecl);
    }

    ExpectToken(lexer::TokenType::PUNCTUATOR_SUBSTITUTION);

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::REPORT_ERROR;
    ir::TypeNode *typeAnnotation = ParseTypeAnnotation(&options);
    if (typeAnnotation == nullptr) {
        return nullptr;
    }
    typeAliasDecl->SetTsTypeAnnotation(typeAnnotation);
    typeAnnotation->SetParent(typeAliasDecl);
    typeAliasDecl->SetRange({typeStart, Lexer()->GetToken().End()});
    return typeAliasDecl;
}

std::pair<bool, std::size_t> ETSParser::CheckDefaultParameters(const ir::ScriptFunction *const function)
{
    bool hasOptionalParameters = false;
    bool hasRestParameter = false;
    std::size_t requiredParametersNumber = 0U;

    for (auto *const it : function->Params()) {
        auto const *const param = it->AsETSParameterExpression();

        if (param->IsRestParameter()) {
            hasRestParameter = true;
            continue;
        }

        if (hasRestParameter) {
            LogError(diagnostic::REST_PARAM_LAST, {}, param->Start());
        }

        if (param->IsOptional()) {
            hasOptionalParameters = true;
            continue;
        }

        if (hasOptionalParameters) {
            LogError(diagnostic::REQUIRED_PARAM_AFTER_DEFAULT, {}, param->Start());
        }

        ++requiredParametersNumber;
    }

    if (hasOptionalParameters && hasRestParameter) {
        LogError(diagnostic::REST_AND_DEFAULT_SAME_TIME, {}, function->Start());
    }

    return std::make_pair(hasOptionalParameters, requiredParametersNumber);
}

std::string ETSParser::PrimitiveTypeToName(ir::PrimitiveType type) const
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
            ES2PANDA_UNREACHABLE();
    }
}

std::string ETSParser::GetNameForETSUnionType(const ir::TypeNode *typeAnnotation) const
{
    ES2PANDA_ASSERT(typeAnnotation->IsETSUnionType());
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
        return typeAnnotation->AsETSTypeReference()->Part()->GetIdent()->Name().Mutf8() + typeParamNames;
    }

    if (typeAnnotation->IsETSFunctionType()) {
        std::string lambdaParams = " ";

        for (const auto *const param : typeAnnotation->AsETSFunctionType()->Params()) {
            lambdaParams += param->AsETSParameterExpression()->Name().Mutf8();
            lambdaParams += ":";
            lambdaParams += GetNameForTypeNode(param->AsETSParameterExpression()->TypeAnnotation());
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

    ES2PANDA_UNREACHABLE();
}

void ETSParser::ValidateRestParameter(ir::Expression *param)
{
    if (!param->IsETSParameterExpression()) {
        return;
    }
    if (!param->AsETSParameterExpression()->IsRestParameter()) {
        return;
    }
    GetContext().Status() |= ParserStatus::HAS_COMPLEX_PARAM;
    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        // rest_parameter_04.ets
        LogError(diagnostic::REST_PARAM_NOT_LAST);
        const auto pos = Lexer()->Save();
        Lexer()->NextToken();
        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
            // ...a: int, b: int)
            Lexer()->Rewind(pos);
            Lexer()->GetToken().SetTokenType(lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS);
        }
        // typo happened, just skip the token
        // ...a: int,)
    }
}

bool ETSParser::ValidateBreakLabel([[maybe_unused]] util::StringView label)
{
    // For ETS validate labels in checker via variables
    return true;
}

bool ETSParser::ValidateContinueLabel([[maybe_unused]] util::StringView label)
{
    // For ETS validate labels in checker via variables
    return true;
}

std::tuple<ir::Expression *, ir::TSTypeParameterInstantiation *> ETSParser::ParseTypeReferencePart(
    TypeAnnotationParsingOptions *options)
{
    ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS;

    if (((*options) & TypeAnnotationParsingOptions::POTENTIAL_CLASS_LITERAL) != 0) {
        flags |= ExpressionParseFlags::POTENTIAL_CLASS_LITERAL;
    }

    if (((*options) & TypeAnnotationParsingOptions::POTENTIAL_NEW_ARRAY) != 0) {
        flags |= ExpressionParseFlags::POTENTIAL_NEW_ARRAY;
    }

    auto *typeName = ParseQualifiedName(flags);
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
        *options |= TypeAnnotationParsingOptions::ALLOW_WILDCARD | TypeAnnotationParsingOptions::ANNOTATION_NOT_ALLOW;
        typeParamInst = ParseTypeParameterInstantiation(options);
        *options &=
            ~(TypeAnnotationParsingOptions::ALLOW_WILDCARD | TypeAnnotationParsingOptions::ANNOTATION_NOT_ALLOW);
    }

    return {typeName, typeParamInst};
}

ir::TypeNode *ETSParser::ParseTypeReference(TypeAnnotationParsingOptions *options)
{
    auto startPos = Lexer()->GetToken().Start();
    ir::ETSTypeReferencePart *typeRefPart = nullptr;

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_FORMAT) {
        return ParseTypeFormatPlaceholder();
    }

    while (true) {
        auto partPos = Lexer()->GetToken().Start();
        auto [typeName, typeParams] = ParseTypeReferencePart(options);
        typeRefPart = AllocNode<ir::ETSTypeReferencePart>(typeName, typeParams, typeRefPart, Allocator());
        typeRefPart->SetRange({partPos, Lexer()->GetToken().End()});

        if (!Lexer()->TryEatTokenType(lexer::TokenType::PUNCTUATOR_PERIOD)) {
            break;
        }

        if (((*options) & TypeAnnotationParsingOptions::POTENTIAL_CLASS_LITERAL) != 0 &&
            (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_CLASS || IsStructKeyword())) {
            break;
        }
    }

    auto *typeReference = AllocNode<ir::ETSTypeReference>(typeRefPart, Allocator());
    typeReference->SetRange({startPos, Lexer()->GetToken().End()});
    return typeReference;
}

ir::TypeNode *ETSParser::ParseBaseTypeReference(TypeAnnotationParsingOptions *options)
{
    switch (Lexer()->GetToken().KeywordType()) {
        case lexer::TokenType::KEYW_BOOLEAN:
            return ParsePrimitiveType(options, ir::PrimitiveType::BOOLEAN);
        case lexer::TokenType::KEYW_BYTE:
            return ParsePrimitiveType(options, ir::PrimitiveType::BYTE);
        case lexer::TokenType::KEYW_CHAR:
            return ParsePrimitiveType(options, ir::PrimitiveType::CHAR);
        case lexer::TokenType::KEYW_DOUBLE:
            return ParsePrimitiveType(options, ir::PrimitiveType::DOUBLE);
        case lexer::TokenType::KEYW_FLOAT:
            return ParsePrimitiveType(options, ir::PrimitiveType::FLOAT);
        case lexer::TokenType::KEYW_INT:
            return ParsePrimitiveType(options, ir::PrimitiveType::INT);
        case lexer::TokenType::KEYW_LONG:
            return ParsePrimitiveType(options, ir::PrimitiveType::LONG);
        case lexer::TokenType::KEYW_SHORT:
            return ParsePrimitiveType(options, ir::PrimitiveType::SHORT);
        default:
            return nullptr;
    }
}

ir::TypeNode *ETSParser::ParseLiteralIdent(TypeAnnotationParsingOptions *options)
{
    if (Lexer()->GetToken().IsDefinableTypeName()) {
        return GetTypeAnnotationOfPrimitiveType(Lexer()->GetToken().KeywordType(), options);
    }

    if (Lexer()->TryEatTokenFromKeywordType(lexer::TokenType::KEYW_KEYOF)) {
        auto *typeAnnotation = ParseTypeAnnotationNoPreferParam(options);
        typeAnnotation = AllocNode<ir::ETSKeyofType>(typeAnnotation, Allocator());
        typeAnnotation->SetRange(Lexer()->GetToken().Loc());
        return typeAnnotation;
    }

    return ParseTypeReference(options);
}

void ETSParser::ParseRightParenthesis(TypeAnnotationParsingOptions *options, ir::TypeNode *&typeAnnotation,
                                      lexer::LexerPosition savedPos)
{
    if (!Lexer()->TryEatTokenType(lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS)) {
        if (((*options) & TypeAnnotationParsingOptions::REPORT_ERROR) != 0) {
            LogExpectedToken(lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS);
            Lexer()->NextToken();  // eat ')'
            return;
        }

        Lexer()->Rewind(savedPos);
        typeAnnotation = nullptr;
    }
}

void ETSParser::ReportIfVarDeclaration(VariableParsingFlags flags)
{
    if ((flags & VariableParsingFlags::VAR) != 0) {
        LogUnexpectedToken(lexer::TokenType::KEYW_VAR);
    }
}

ir::Statement *ETSParser::ParseExport(lexer::SourcePosition startLoc, ir::ModifierFlags modifiers)
{
    if (!InAmbientContext() && (GetContext().Status() & ParserStatus::IN_NAMESPACE) != 0) {
        LogError(diagnostic::EXPORT_IN_NAMESPACE);
    }
    ES2PANDA_ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY ||
                    Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE ||
                    Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT);
    ArenaVector<ir::AstNode *> specifiers(Allocator()->Adapter());

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY) {
        ParseNameSpaceSpecifier(&specifiers, true);
    } else if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        auto specs = ParseNamedSpecifiers();

        if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_FROM) {
            specifiers = util::Helpers::ConvertVector<ir::AstNode>(specs.first);
        } else {
            ArenaVector<ir::ExportSpecifier *> exports(Allocator()->Adapter());
            for (auto spec : specs.first) {
                exports.emplace_back(AllocNode<ir::ExportSpecifier>(spec->Local(), spec->Imported()));
            }
            auto result = AllocNode<ir::ExportNamedDeclaration>(Allocator(), static_cast<ir::StringLiteral *>(nullptr),
                                                                std::move(exports));
            result->AddModifier(modifiers);
            return result;
        }
    } else {
        return ParseSingleExport(modifiers);
    }
    if ((modifiers & ir::ModifierFlags::DEFAULT_EXPORT) != 0) {
        LogError(diagnostic::EXPORT_DEFAULT_NO_REEXPORT);
    }
    // re-export directive
    auto *reExportDeclaration = ParseImportPathBuildImport(std::move(specifiers), true, startLoc, ir::ImportKinds::ALL);
    auto reExport = AllocNode<ir::ETSReExportDeclaration>(reExportDeclaration, std::vector<std::string>(),
                                                          GetProgram()->SourceFilePath(), Allocator());
    reExport->AddModifier(modifiers);
    return reExport;
}

ir::ETSPackageDeclaration *ETSParser::ParsePackageDeclaration()
{
    auto startLoc = Lexer()->GetToken().Start();

    if (!Lexer()->TryEatTokenType(lexer::TokenType::KEYW_PACKAGE)) {
        // NOTE(vpukhov): the *unnamed* modules are to be removed entirely
        bool isUnnamed = GetOptions().IsEtsUnnamed() && GetProgram() == globalProgram_;
        util::StringView moduleName =
            isUnnamed ? "" : importPathManager_->FormModuleName(GetProgram()->SourceFile(), startLoc);
        GetProgram()->SetPackageInfo(moduleName, util::ModuleKind::MODULE);
        return nullptr;
    }

    ir::Expression *name = ParseQualifiedName();
    auto *packageDeclaration = AllocNode<ir::ETSPackageDeclaration>(name);
    packageDeclaration->SetRange({startLoc, Lexer()->GetToken().End()});

    ConsumeSemicolon(packageDeclaration);

    auto packageName = name->IsIdentifier() ? name->AsIdentifier()->Name() : name->AsTSQualifiedName()->Name();

    GetProgram()->SetPackageInfo(packageName, util::ModuleKind::PACKAGE);

    return packageDeclaration;
}

ir::ETSImportDeclaration *ETSParser::ParseImportPathBuildImport(ArenaVector<ir::AstNode *> &&specifiers,
                                                                bool requireFrom, lexer::SourcePosition startLoc,
                                                                ir::ImportKinds importKind)
{
    if (Lexer()->GetToken().KeywordType() != lexer::TokenType::KEYW_FROM && requireFrom) {
        LogExpectedToken(lexer::TokenType::KEYW_FROM);
    }
    Lexer()->NextToken();  // eat `from`

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_STRING) {
        LogExpectedToken(lexer::TokenType::LITERAL_STRING);
        // Try to create DUMMY import source as error placeholder
        auto errorLiteral = AllocNode<ir::StringLiteral>(ERROR_LITERAL);
        errorLiteral->SetRange(Lexer()->GetToken().Loc());
        auto *const importDeclaration = AllocNode<ir::ETSImportDeclaration>(
            errorLiteral, util::ImportPathManager::ImportMetadata {}, std::move(specifiers), importKind);
        importDeclaration->SetRange({startLoc, errorLiteral->End()});
        return importDeclaration;
    }

    ES2PANDA_ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_STRING);
    auto pathToResolve = Lexer()->GetToken().Ident();
    auto *importPathStringLiteral = AllocNode<ir::StringLiteral>(pathToResolve);
    importPathStringLiteral->SetRange(Lexer()->GetToken().Loc());
    Lexer()->NextToken();
    auto *const importDeclaration = BuildImportDeclaration(importKind, std::move(specifiers), importPathStringLiteral);
    importDeclaration->SetRange({startLoc, importPathStringLiteral->End()});
    ConsumeSemicolon(importDeclaration);
    return importDeclaration;
}

ir::ETSImportDeclaration *ETSParser::BuildImportDeclaration(ir::ImportKinds importKind,
                                                            ArenaVector<ir::AstNode *> &&specifiers,
                                                            ir::StringLiteral *pathToResolve)
{
    ES2PANDA_ASSERT(GetProgram() == GetContext().GetProgram());
    return AllocNode<ir::ETSImportDeclaration>(pathToResolve,
                                               importPathManager_->GatherImportMetadata(GetContext(), pathToResolve),
                                               std::move(specifiers), importKind);
}

ArenaVector<ir::ETSImportDeclaration *> ETSParser::ParseImportDeclarations()
{
    std::vector<std::string> userPaths;
    ArenaVector<ir::ETSImportDeclaration *> statements(Allocator()->Adapter());

    while (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_IMPORT) {
        auto startLoc = Lexer()->GetToken().Start();
        Lexer()->NextToken();  // eat import

        ir::ImportKinds importKind =
            Lexer()->TryEatTokenKeyword(lexer::TokenType::KEYW_TYPE) ? ir::ImportKinds::TYPES : ir::ImportKinds::ALL;

        ArenaVector<ir::AstNode *> specifiers(Allocator()->Adapter());
        ArenaVector<ir::AstNode *> defaultSpecifiers(Allocator()->Adapter());

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY) {
            if (importKind == ir::ImportKinds::TYPES) {
                LogError(diagnostic::TYPE_IMPORT_MISSING_SELECTIVE_BINDING);
            }
            ParseNameSpaceSpecifier(&specifiers);
        } else if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
            auto specs = ParseNamedSpecifiers();
            specifiers = util::Helpers::ConvertVector<ir::AstNode>(specs.first);
            defaultSpecifiers = util::Helpers::ConvertVector<ir::AstNode>(specs.second);
        } else {
            ParseImportDefaultSpecifier(&specifiers);
        }
        auto pos = Lexer()->Save();
        if (!specifiers.empty()) {
            auto *const importDecl = ParseImportPathBuildImport(std::move(specifiers), true, startLoc, importKind);
            statements.push_back(importDecl->AsETSImportDeclaration());
        }

        if (!defaultSpecifiers.empty()) {
            Lexer()->Rewind(pos);
            auto *const importDeclDefault =
                ParseImportPathBuildImport(std::move(defaultSpecifiers), true, startLoc, importKind);
            if (!importDeclDefault->IsBrokenStatement()) {
                util::Helpers::CheckDefaultImport(statements);
                statements.push_back(importDeclDefault->AsETSImportDeclaration());
            }
        }
    }

    std::sort(statements.begin(), statements.end(), [](const auto *s1, const auto *s2) -> bool {
        return s1->Specifiers()[0]->IsImportNamespaceSpecifier() && !s2->Specifiers()[0]->IsImportNamespaceSpecifier();
    });
    return statements;
}

ir::ExportNamedDeclaration *ETSParser::ParseSingleExport(ir::ModifierFlags modifiers)
{
    lexer::Token token = Lexer()->GetToken();
    auto *exported = AllocNode<ir::Identifier>(token.Ident(), Allocator());
    exported->SetRange(Lexer()->GetToken().Loc());

    Lexer()->NextToken();  // eat exported variable name

    ArenaVector<ir::ExportSpecifier *> exports(Allocator()->Adapter());

    exports.emplace_back(AllocNode<ir::ExportSpecifier>(exported, ParseNamedExport(&token)));
    auto result = AllocNode<ir::ExportNamedDeclaration>(Allocator(), static_cast<ir::StringLiteral *>(nullptr),
                                                        std::move(exports));
    result->AddModifier(modifiers);
    ConsumeSemicolon(result);

    return result;
}

bool ETSParser::IsDefaultImport()
{
    if (Lexer()->TryEatTokenKeyword(lexer::TokenType::KEYW_DEFAULT)) {
        if (Lexer()->TryEatTokenKeyword(lexer::TokenType::KEYW_AS)) {
            return true;
        }
        LogError(diagnostic::UNEXPECTED_TOKEN_AS);
    }
    return false;
}

bool TypedParser::IsPrimitiveType(const lexer::TokenType &tokenType)
{
    switch (tokenType) {
        case lexer::TokenType::KEYW_BIGINT:
        case lexer::TokenType::KEYW_BOOLEAN:
        case lexer::TokenType::KEYW_BYTE:
        case lexer::TokenType::KEYW_CHAR:
        case lexer::TokenType::KEYW_DOUBLE:
        case lexer::TokenType::KEYW_FLOAT:
        case lexer::TokenType::KEYW_INT:
        case lexer::TokenType::KEYW_LONG:
        case lexer::TokenType::KEYW_SHORT:
        case lexer::TokenType::KEYW_VOID:
            return true;
        default:
            return false;
    }
}

void ETSParser::ParseNamedSpecifiesDefaultImport(ArenaVector<ir::ImportDefaultSpecifier *> *resultDefault,
                                                 const std::string &fileName)
{
    auto *imported = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    imported->SetRange(Lexer()->GetToken().Loc());
    Lexer()->NextToken();
    auto *specifier = AllocNode<ir::ImportDefaultSpecifier>(imported);
    specifier->SetRange({imported->Start(), imported->End()});

    util::Helpers::CheckDefaultImportedName(*resultDefault, specifier, fileName);

    resultDefault->emplace_back(specifier);
}

using ImportSpecifierVector = ArenaVector<ir::ImportSpecifier *>;
using ImportDefaultSpecifierVector = ArenaVector<ir::ImportDefaultSpecifier *>;
std::pair<ImportSpecifierVector, ImportDefaultSpecifierVector> ETSParser::ParseNamedSpecifiers()
{
    // NOTE(user): handle qualifiedName in file bindings: qualifiedName '.' '*'
    if (!Lexer()->TryEatTokenType(lexer::TokenType::PUNCTUATOR_LEFT_BRACE)) {
        // For now, this function is called only after checking that
        // current token is lexer::TokenType::PUNCTUATOR_LEFT_BRACE
        // So it is impossible to create a test now.
        LogExpectedToken(lexer::TokenType::PUNCTUATOR_LEFT_BRACE);
        Lexer()->NextToken();
    }

    auto fileName = GetProgram()->SourceFilePath().Mutf8();

    ArenaVector<ir::ImportSpecifier *> result(Allocator()->Adapter());
    ArenaVector<ir::ImportDefaultSpecifier *> resultDefault(Allocator()->Adapter());

    ParseList(
        lexer::TokenType::PUNCTUATOR_RIGHT_BRACE, lexer::NextTokenFlags::KEYWORD_TO_IDENT,
        [this, &result, &resultDefault, &fileName]() {
            if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY) {
                LogError(diagnostic::ASTERIKS_NOT_ALLOWED_IN_SELECTIVE_BINDING);
            }

            if (!IsDefaultImport()) {
                if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
                    // NOTE: needs to be replaced by returning invalid value from `ExpectIdentifier`
                    ExpectToken(lexer::TokenType::LITERAL_IDENT);
                    return false;
                }
                lexer::Token importedToken = Lexer()->GetToken();
                auto *imported = ExpectIdentifier();

                ir::Identifier *local = nullptr;
                if (CheckModuleAsModifier() && Lexer()->TryEatTokenType(lexer::TokenType::KEYW_AS)) {
                    local = ParseNamedImport(&Lexer()->GetToken());
                    Lexer()->NextToken();
                } else {
                    local = ParseNamedImport(&importedToken);
                }

                auto *specifier = AllocNode<ir::ImportSpecifier>(imported, local);
                specifier->SetRange({imported->Start(), local->End()});

                util::Helpers::CheckImportedName(result, specifier, fileName);

                result.emplace_back(specifier);
            } else {
                ParseNamedSpecifiesDefaultImport(&resultDefault, fileName);
            }
            return true;
        },
        nullptr, true);
    return {result, resultDefault};
}

void ETSParser::ParseNameSpaceSpecifier(ArenaVector<ir::AstNode *> *specifiers, bool isReExport)
{
    lexer::SourcePosition namespaceStart = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat `*` character

    if (!CheckModuleAsModifier()) {
        LogError(diagnostic::UNEXPECTED_TOKEN);
    }

    // Note (oeotvos) As a temporary solution we allow the stdlib to use namespace import without an alias, but this
    // should be handled at some point.
    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_FROM && !isReExport &&
        (GetContext().Status() & ParserStatus::IN_DEFAULT_IMPORTS) == 0) {
        LogExpectedToken(lexer::TokenType::KEYW_AS);  // invalid_namespce_import.ets
    }

    auto *local = AllocNode<ir::Identifier>(util::StringView(""), Allocator());
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA ||
        Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_FROM || isReExport) {
        auto *specifier = AllocNode<ir::ImportNamespaceSpecifier>(local);
        specifier->SetRange({namespaceStart, Lexer()->GetToken().End()});
        specifiers->push_back(specifier);
        return;
    }

    ExpectToken(lexer::TokenType::KEYW_AS, true);  // eat `as` literal
    local = ParseNamedImport(&Lexer()->GetToken());

    auto *specifier = AllocNode<ir::ImportNamespaceSpecifier>(local);
    specifier->SetRange({namespaceStart, Lexer()->GetToken().End()});
    specifiers->push_back(specifier);

    Lexer()->NextToken();  // eat local name
}

ir::AstNode *ETSParser::ParseImportDefaultSpecifier(ArenaVector<ir::AstNode *> *specifiers)
{
    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        LogExpectedToken(lexer::TokenType::LITERAL_IDENT);
    }

    auto *imported = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    imported->SetRange(Lexer()->GetToken().Loc());
    Lexer()->NextToken();  // Eat import specifier.

    if (Lexer()->GetToken().KeywordType() != lexer::TokenType::KEYW_FROM) {
        LogExpectedToken(lexer::TokenType::KEYW_FROM);
        Lexer()->NextToken();  // eat 'from'
    }

    auto *specifier = AllocNode<ir::ImportDefaultSpecifier>(imported);
    specifier->SetRange({imported->Start(), imported->End()});
    specifiers->push_back(specifier);

    return nullptr;
}

bool ETSParser::CheckModuleAsModifier()
{
    if ((Lexer()->GetToken().Flags() & lexer::TokenFlags::HAS_ESCAPE) != 0U) {
        LogError(diagnostic::ESCAPE_SEQUENCES_IN_AS);
    }

    return true;
}

ir::AnnotatedExpression *ETSParser::GetAnnotatedExpressionFromParam()
{
    ir::AnnotatedExpression *parameter = nullptr;

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
                LogExpectedToken(lexer::TokenType::LITERAL_IDENT);
            }

            auto *const restIdent = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
            restIdent->SetRange(Lexer()->GetToken().Loc());

            parameter = AllocNode<ir::SpreadElement>(ir::AstNodeType::REST_ELEMENT, Allocator(), restIdent);
            parameter->SetRange({startLoc, Lexer()->GetToken().End()});
            break;
        }

        default: {
            LogError(diagnostic::UNEXPECTED_TOKEN_ID);
            return AllocBrokenExpression(Lexer()->GetToken().Loc());
        }
    }

    Lexer()->NextToken();
    return parameter;
}

ir::Expression *ETSParser::ParseFunctionParameterAnnotations()
{
    Lexer()->NextToken();  // eat '@'

    auto annotations = ParseAnnotations(false);
    auto savePos = Lexer()->GetToken().Start();
    ir::Expression *result = ParseFunctionParameter();
    if (result != nullptr) {
        ApplyAnnotationsToNode(result, std::move(annotations), savePos);
    }
    return result;
}

ir::Expression *ETSParser::ParseFunctionReceiver()
{
    ES2PANDA_ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::KEYW_THIS);
    auto thisLoc = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat 'this';
    if (!Lexer()->TryEatTokenType(lexer::TokenType::PUNCTUATOR_COLON)) {
        LogError(diagnostic::FUN_PARAM_THIS_MISSING_TYPE);
        return AllocBrokenExpression(Lexer()->GetToken().Loc());
    }

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::REPORT_ERROR;
    ir::TypeNode *typeAnnotation = ParseTypeAnnotation(&options);

    if (!GetContext().AllowReceiver()) {
        LogError(diagnostic::UNEXPECTED_THIS, {}, thisLoc);
        return AllocBrokenExpression(thisLoc);
    }

    return CreateParameterThis(typeAnnotation);
}

void ETSParser::SkipInvalidType() const
{
    int openParenthesisCount = 1;
    int openBraceCount = 0;
    while (Lexer()->GetToken().Type() != lexer::TokenType::EOS &&
           !(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA && openBraceCount == 0)) {
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
            openBraceCount++;
        }
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
            openBraceCount--;
        }
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
            openParenthesisCount++;
        }
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
            openParenthesisCount--;
        }
        if (openParenthesisCount == 0) {
            break;
        }
        Lexer()->NextToken();
    }
}

bool ETSParser::IsFixedArrayTypeNode(ir::AstNode *node)
{
    return node->IsETSTypeReference() &&
           node->AsETSTypeReference()->BaseName()->Name() == compiler::Signatures::FIXED_ARRAY_TYPE_NAME;
}

ir::Expression *ETSParser::ParseFunctionParameter()
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_AT) {
        return ParseFunctionParameterAnnotations();
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_THIS) {
        return ParseFunctionReceiver();
    }

    auto *const paramIdent = GetAnnotatedExpressionFromParam();

    bool isOptional = false;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_QUESTION_MARK) {
        isOptional = true;
        if (paramIdent->IsRestElement()) {
            LogError(diagnostic::NO_DEFAULT_FOR_REST);
        }
        Lexer()->NextToken();  // eat '?'
    }

    const bool isArrow = (GetContext().Status() & ParserStatus::ARROW_FUNCTION) != 0;

    if (Lexer()->TryEatTokenType(lexer::TokenType::PUNCTUATOR_COLON)) {
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::REPORT_ERROR;
        ir::TypeNode *typeAnnotation = ParseTypeAnnotation(&options);
        if (typeAnnotation->IsBrokenTypeNode()) {
            // the compiler can't process "declare class A { static foo(x: {key: string}[]):void; }" correctly
            // and resolve "{key: string}" as function body, so skip invalid types
            SkipInvalidType();
        } else if (paramIdent->IsRestElement() && !typeAnnotation->IsTSArrayType() &&
                   !IsFixedArrayTypeNode(typeAnnotation) && !typeAnnotation->IsETSTuple()) {
            LogError(diagnostic::ONLY_ARRAY_OR_TUPLE_FOR_REST);
        }
        typeAnnotation->SetParent(paramIdent);
        paramIdent->SetTsTypeAnnotation(typeAnnotation);
        paramIdent->SetEnd(typeAnnotation->End());
    } else if (!isArrow && !isOptional) {
        LogError(diagnostic::EXPLICIT_PARAM_TYPE);
    }

    return ParseFunctionParameterExpression(paramIdent, isOptional);
}

ir::Expression *ETSParser::CreateParameterThis(ir::TypeNode *typeAnnotation)
{
    auto *paramIdent = AllocNode<ir::Identifier>(varbinder::TypedBinder::MANDATORY_PARAM_THIS, Allocator());
    paramIdent->SetRange(Lexer()->GetToken().Loc());

    typeAnnotation->SetParent(paramIdent);
    paramIdent->SetTsTypeAnnotation(typeAnnotation);

    auto *paramExpression = AllocNode<ir::ETSParameterExpression>(paramIdent, false, Allocator());
    paramExpression->SetRange({paramIdent->Start(), paramIdent->End()});

    return paramExpression;
}

ir::AnnotatedExpression *ETSParser::ParseVariableDeclaratorKey([[maybe_unused]] VariableParsingFlags flags)
{
    ir::Identifier *init = ExpectIdentifier();
    ir::TypeNode *typeAnnotation = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_QUESTION_MARK) {
        if ((flags & VariableParsingFlags::FOR_OF) != 0U) {
            LogError(diagnostic::OPTIONAL_VAR_IN_FOR_OF);
        }
        Lexer()->NextToken();  // eat '?'
        init->AddModifier(ir::ModifierFlags::OPTIONAL);
    }

    if (auto const tokenType = Lexer()->GetToken().Type(); tokenType == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::REPORT_ERROR;
        typeAnnotation = ParseTypeAnnotation(&options);
    } else if (tokenType != lexer::TokenType::PUNCTUATOR_SUBSTITUTION && (flags & VariableParsingFlags::FOR_OF) == 0U) {
        LogError(diagnostic::MISSING_INIT_OR_TYPE);
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
        LogError(diagnostic::FOR_AWAIT_OF_VAR_NOT_INIT);
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

    if (init->AsIdentifier()->TypeAnnotation() == nullptr && (flags & VariableParsingFlags::FOR_OF) == 0U) {
        LogError(diagnostic::MISSING_INIT_OR_TYPE);
    }

    lexer::SourcePosition endLoc = init->End();
    auto declarator = AllocNode<ir::VariableDeclarator>(GetFlag(flags), init);
    declarator->SetRange({startLoc, endLoc});

    // NOTE (psiket)  Transfer the OPTIONAL flag from the init to the declarator?
    return declarator;
}

ir::Expression *ETSParser::ParseCatchParam()
{
    ExpectToken(lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
    ir::AnnotatedExpression *param = nullptr;

    bool checkRestrictedBinding = true;
    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        // tryCatchMissingParam.ets
        LogError(diagnostic::UNEXPECTED_TOKEN_ID);
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
            checkRestrictedBinding = false;
        } else {
            Lexer()->GetToken().SetTokenType(lexer::TokenType::LITERAL_IDENT);
            Lexer()->GetToken().SetTokenStr(ERROR_LITERAL);
        }
    }
    if (!checkRestrictedBinding) {
        ExpectToken(lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS);
        return nullptr;
    }

    CheckRestrictedBinding();
    param = ExpectIdentifier();
    ParseCatchParamTypeAnnotation(param);

    ExpectToken(lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS);
    return param;
}

void ETSParser::ParseCatchParamTypeAnnotation([[maybe_unused]] ir::AnnotatedExpression *param)
{
    if (Lexer()->TryEatTokenType(lexer::TokenType::PUNCTUATOR_COLON)) {
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::REPORT_ERROR;
        if (auto *typeAnnotation = ParseTypeAnnotation(&options); typeAnnotation != nullptr) {
            typeAnnotation->SetParent(param);
            param->SetTsTypeAnnotation(typeAnnotation);
        }
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        LogError(diagnostic::CATCH_CLAUSE_VAR_HAS_INIT);
    }
}

ir::Statement *ETSParser::ParseImportDeclaration([[maybe_unused]] StatementParsingFlags flags)
{
    if ((flags & StatementParsingFlags::GLOBAL) == 0) {
        LogError(diagnostic::IMPORT_TOP_LEVEL);
    }

    char32_t nextChar = Lexer()->Lookahead();
    if (nextChar == lexer::LEX_CHAR_LEFT_PAREN || nextChar == lexer::LEX_CHAR_DOT) {
        return ParseExpressionStatement();
    }

    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat import

    ArenaVector<ir::AstNode *> specifiers(Allocator()->Adapter());

    ir::ETSImportDeclaration *importDeclaration {};
    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_STRING) {
        ir::AstNode *astNode = ParseImportSpecifiers(&specifiers);
        if (astNode != nullptr) {
            ES2PANDA_ASSERT(astNode->IsTSImportEqualsDeclaration());
            astNode->SetRange({startLoc, Lexer()->GetToken().End()});
            ConsumeSemicolon(astNode->AsTSImportEqualsDeclaration());
            return astNode->AsTSImportEqualsDeclaration();
        }
        importDeclaration = ParseImportPathBuildImport(std::move(specifiers), true, startLoc, ir::ImportKinds::ALL);
    } else {
        importDeclaration = ParseImportPathBuildImport(std::move(specifiers), false, startLoc, ir::ImportKinds::ALL);
    }

    return importDeclaration;
}

ir::Statement *ETSParser::ParseExportDeclaration([[maybe_unused]] StatementParsingFlags flags)
{
    LogUnexpectedToken(lexer::TokenType::KEYW_EXPORT);
    return AllocBrokenStatement(Lexer()->GetToken().Start());
}

ir::Expression *ETSParser::ParseExpressionOrTypeAnnotation(lexer::TokenType type,
                                                           [[maybe_unused]] ExpressionParseFlags flags)
{
    if (type == lexer::TokenType::KEYW_INSTANCEOF) {
        TypeAnnotationParsingOptions options =
            TypeAnnotationParsingOptions::REPORT_ERROR | TypeAnnotationParsingOptions::ANNOTATION_NOT_ALLOW;

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

    // unexpected_token_49,ets, 50, 51
    if (!Lexer()->GetToken().NewLine() && Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        LogExpectedToken(lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
    }

    if (Lexer()->GetToken().NewLine()) {
        return true;
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

ir::ModifierFlags ETSParser::ParseTypeVarianceModifier(TypeAnnotationParsingOptions *const options)
{
    if ((*options & TypeAnnotationParsingOptions::ALLOW_WILDCARD) == 0 &&
        (*options & TypeAnnotationParsingOptions::ALLOW_DECLARATION_SITE_VARIANCE) == 0) {
        LogError(diagnostic::VARIANCE_NOD_ALLOWED);
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

ir::AstNode *ETSParser::ParseAmbientSignature(const lexer::SourcePosition &startPos)
{
    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        // ambient_indexer_9.ets
        LogUnexpectedToken(Lexer()->GetToken());
        auto pos = Lexer()->Save();
        Lexer()->NextToken();
        while (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
            // just skip usls tokens, we have an identifier after
            Lexer()->Rewind(pos);
            Lexer()->NextToken();
            pos = Lexer()->Save();
        }
        if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
            // if next token is not an ident, so current token should be an identifier
            // and we set it as literal ident
            Lexer()->GetToken().SetTokenType(lexer::TokenType::LITERAL_IDENT);
            Lexer()->GetToken().SetTokenStr(ERROR_LITERAL);
        }
    }
    auto const indexName = Lexer()->GetToken().Ident();

    if (Lexer()->NextToken(); Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
        // ambient_indexer_8.ets
        LogError(diagnostic::INDEX_TYPE_EXPECTED);

        Lexer()->GetToken().SetTokenType(lexer::TokenType::PUNCTUATOR_COLON);
    }

    // eat ":"
    if (Lexer()->NextToken(); Lexer()->GetToken().KeywordType() != lexer::TokenType::KEYW_NUMBER) {
        // ambient_indexer_3.ets
        LogError(diagnostic::INDEX_TYPE_NOT_NUMBER);

        Lexer()->GetToken().SetTokenType(lexer::TokenType::KEYW_NUMBER);
    }

    // eat indexType
    if (Lexer()->NextToken(); Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
        // ambient_indexer_7.ets
        LogError(diagnostic::EXPECTED_BRACKETS_IN_INDEX);

        Lexer()->GetToken().SetTokenType(lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET);
    }

    // eat "]"
    if (Lexer()->NextToken(); Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
        // ambient_indexer_4.ets
        LogError(diagnostic::INDEX_MISSING_TYPE);

        Lexer()->GetToken().SetTokenType(lexer::TokenType::PUNCTUATOR_COLON);
    }

    // eat ":"
    if (Lexer()->NextToken(); Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        // ambient_indexer_5.ets
        LogError(diagnostic::INDEX_MISSING_IDENTIFIER);

        Lexer()->GetToken().SetTokenType(lexer::TokenType::LITERAL_IDENT);
        Lexer()->GetToken().SetTokenStr(ERROR_LITERAL);
    }
    auto const returnType = AllocNode<ir::ETSTypeReferencePart>(
        AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator()), Allocator());

    auto dummyNode = AllocNode<ir::DummyNode>(compiler::Signatures::AMBIENT_INDEXER, indexName, returnType,
                                              ir::DummyNodeFlag::INDEXER);
    dummyNode->SetRange({startPos, Lexer()->GetToken().End()});
    Lexer()->NextToken();  // eat return type
    return dummyNode;
}

ir::TSTypeParameter *ETSParser::ParseTypeParameter([[maybe_unused]] TypeAnnotationParsingOptions *options)
{
    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();
    ArenaVector<ir::AnnotationUsage *> annotations {Allocator()->Adapter()};
    if (Lexer()->TryEatTokenType(lexer::TokenType::PUNCTUATOR_AT)) {
        annotations = ParseAnnotations(false);
    }

    const auto varianceModifier = [this, options] {
        switch (Lexer()->GetToken().KeywordType()) {
            case lexer::TokenType::KEYW_IN:
            case lexer::TokenType::KEYW_OUT:
                return ParseTypeVarianceModifier(options);
            default:
                return ir::ModifierFlags::NONE;
        }
    }();

    if (Lexer()->TryEatTokenType(lexer::TokenType::PUNCTUATOR_AT)) {
        auto moreAnnos = ParseAnnotations(false);
        for (auto *anno : moreAnnos) {
            annotations.push_back(anno);
        }
    }
    auto saveLoc = Lexer()->GetToken().Start();
    auto *paramIdent = ExpectIdentifier(false, false, *options);

    ir::TypeNode *constraint = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_EXTENDS) {
        Lexer()->NextToken();
        TypeAnnotationParsingOptions newOptions =
            TypeAnnotationParsingOptions::REPORT_ERROR | TypeAnnotationParsingOptions::IGNORE_FUNCTION_TYPE;
        constraint = ParseTypeAnnotation(&newOptions);
    }

    ir::TypeNode *defaultType = nullptr;

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        Lexer()->NextToken();  // eat '='
        defaultType = ParseTypeAnnotation(options);
    }

    auto *typeParam =
        AllocNode<ir::TSTypeParameter>(paramIdent, constraint, defaultType, varianceModifier, Allocator());

    ApplyAnnotationsToNode(typeParam, std::move(annotations), saveLoc);
    typeParam->SetRange({startLoc, Lexer()->GetToken().End()});
    return typeParam;
}

ir::Identifier *ETSParser::ParseClassIdent([[maybe_unused]] ir::ClassDefinitionModifiers modifiers)
{
    return ExpectIdentifier(false, true);
}

bool ETSParser::IsStructKeyword() const
{
    return (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT &&
            Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_STRUCT);
}

void ETSParser::ParseTrailingBlock(ir::CallExpression *callExpr)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        SavedParserContext svCtx(this, ParserStatus::PARSE_TRAILING_BLOCK);
        callExpr->SetIsTrailingBlockInNewLine(Lexer()->GetToken().NewLine());
        callExpr->SetTrailingBlock(ParseBlockStatement());
    }
}

void ETSParser::CheckDeclare()
{
    ES2PANDA_ASSERT(Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_DECLARE);

    if (InAmbientContext()) {
        LogError(diagnostic::DECALRE_IN_AMBIENT_CONTEXT);
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
        case lexer::TokenType::KEYW_ABSTRACT:
        case lexer::TokenType::KEYW_FINAL:
        case lexer::TokenType::KEYW_INTERFACE:
        case lexer::TokenType::KEYW_TYPE:
        case lexer::TokenType::KEYW_ASYNC:
        case lexer::TokenType::KEYW_STRUCT: {
            return;
        }
        default: {
            if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_AT) {
                return;
            }
            LogUnexpectedToken(Lexer()->GetToken());
        }
    }
}

ir::FunctionDeclaration *ETSParser::ParseFunctionDeclaration(bool canBeAnonymous, ir::ModifierFlags modifiers)
{
    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();

    ES2PANDA_ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::KEYW_FUNCTION);
    Lexer()->NextToken();
    auto newStatus = ParserStatus::NEED_RETURN_TYPE | ParserStatus::ALLOW_SUPER;

    if ((modifiers & ir::ModifierFlags::ASYNC) != 0) {
        newStatus |= ParserStatus::ASYNC_FUNCTION;
    }

    if (Lexer()->TryEatTokenType(lexer::TokenType::PUNCTUATOR_MULTIPLY)) {
        newStatus |= ParserStatus::GENERATOR_FUNCTION;
    }

    ir::Identifier *funcIdentNode = nullptr;

    if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
        // Parse regular function. Example: `function foo() {}`:
        funcIdentNode = ExpectIdentifier();
    } else if (!canBeAnonymous) {
        LogError(diagnostic::UNEXPECTED_TOKEN_ID);
        funcIdentNode = AllocBrokenExpression(Lexer()->GetToken().Loc());
    }

    if (funcIdentNode != nullptr) {
        CheckRestrictedBinding(funcIdentNode->Name(), funcIdentNode->Start());
    }

    ir::ScriptFunction *func =
        ParseFunction(newStatus | ParserStatus::FUNCTION_DECLARATION | ParserStatus::ALLOW_RECEIVER);
    if (funcIdentNode != nullptr) {  // Error processing.
        func->SetIdent(funcIdentNode);
    }

    auto *funcDecl = AllocNode<ir::FunctionDeclaration>(Allocator(), func);
    if (func->IsOverload() && Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
        Lexer()->NextToken();
    }

    funcDecl->SetRange(func->Range());
    func->AddModifier(modifiers);
    func->SetStart(startLoc);
    return funcDecl;
}

ir::FunctionDeclaration *ETSParser::ParseAccessorWithReceiver(ir::ModifierFlags modifiers)
{
    ES2PANDA_ASSERT(Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_GET ||
                    Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_SET);

    bool isGetter = Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_GET;
    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();

    Lexer()->NextToken();
    auto newStatus = ParserStatus::ALLOW_SUPER | ParserStatus::FUNCTION_DECLARATION | ParserStatus::ALLOW_RECEIVER |
                     ParserStatus::EXTENSION_ACCESSOR;

    ir::Identifier *funcIdentNode = ExpectIdentifier();
    CheckRestrictedBinding(funcIdentNode->Name(), funcIdentNode->Start());

    ir::ScriptFunction *func =
        isGetter ? ParseFunction(newStatus | ParserStatus::NEED_RETURN_TYPE) : ParseFunction(newStatus);
    size_t paramCount = func->Params().size();
    size_t getterValidParamCount = 1;
    size_t setterValidParamCount = 2;
    if (isGetter) {
        func->AddFlag(ir::ScriptFunctionFlags::GETTER);
        if (getterValidParamCount != paramCount) {
            LogError(diagnostic::EXTENSION_GETTER_WRONG_PARAM, {}, startLoc);
        }
    } else {
        func->AddFlag(ir::ScriptFunctionFlags::SETTER);
        if (setterValidParamCount != paramCount) {
            LogError(diagnostic::EXTENSION_SETTER_WRONG_PARAM, {}, startLoc);
        }
        if (func->ReturnTypeAnnotation() != nullptr) {
            LogError(diagnostic::SETTER_NO_RETURN_TYPE, {}, startLoc);
        }
    }

    func->SetIdent(funcIdentNode);

    auto *funcDecl = AllocNode<ir::FunctionDeclaration>(Allocator(), func);
    funcDecl->SetRange(func->Range());
    func->AddModifier(modifiers);
    func->SetStart(startLoc);
    return funcDecl;
}

void ETSParser::AddPackageSourcesToParseList()
{
    importPathManager_->AddImplicitPackageImportToParseList(GetProgram()->SourceFile().GetAbsoluteParentFolder(),
                                                            Lexer()->GetToken().Start());

    // Global program file is always in the same folder that we scanned, but we don't need to parse it twice
    importPathManager_->MarkAsParsed(globalProgram_->SourceFile().GetAbsolutePath());
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
      savedSourceFilePath_(parser_->GetProgram()->SourceFileFolder()),
      savedRelativeFilePath_(parser_->GetProgram()->RelativeFilePath())
{
}

InnerSourceParser::~InnerSourceParser()
{
    parser_->SetLexer(savedLexer_);
    parser_->GetProgram()->SetSource(savedSourceCode_, savedSourceFile_, savedSourceFilePath_);
    parser_->GetProgram()->SetRelativeFilePath(savedRelativeFilePath_);
}
}  // namespace ark::es2panda::parser
