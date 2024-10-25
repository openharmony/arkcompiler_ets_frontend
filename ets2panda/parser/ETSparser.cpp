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
#include "ir/astNode.h"
#include "ir/base/decorator.h"
#include "ir/base/catchClause.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/spreadElement.h"
#include "ir/statements/namespaceDeclaration.h"
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
#include "ir/ets/etsScript.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/ets/etsNullishTypes.h"
#include "ir/ets/etsUnionType.h"
#include "ir/ets/etsImportSource.h"
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

namespace ark::es2panda::parser {
class FunctionContext;

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
        // If we found a package declaration, then add all files with the same package to the package parse list
        AddPackageSourcesToParseList();
    }

    auto script = ParseETSGlobalScript(startLoc, statements);

    AddExternalSource(ParseSources(true));
    GetProgram()->SetAst(script);
    GetProgram()->SetDeclarationModuleInfo();
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
    auto &extSources = globalProgram_->ExternalSources();

    for (auto *newProg : programs) {
        const util::StringView moduleName = newProg->ModuleName();
        if (extSources.count(moduleName) == 0) {
            extSources.try_emplace(moduleName, Allocator()->Adapter());
        }

        extSources.at(moduleName).emplace_back(newProg);
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

void ETSParser::TryParseSource(const util::ImportPathManager::ParseInfo &parseListIdx, util::UString *extSrc,
                               const ArenaVector<util::StringView> &directImportsFromMainSource,
                               std::vector<Program *> &programs)
{
    try {
        parser::Program *newProg =
            ParseSource({parseListIdx.sourcePath.Utf8(), extSrc->View().Utf8(), parseListIdx.sourcePath.Utf8(), false});

        if (!parseListIdx.isImplicitPackageImported || newProg->IsPackageModule()) {
            AddDirectImportsToDirectExternalSources(directImportsFromMainSource, newProg);
            // don't insert the separate modules into the programs, when we collect implicit package imports
            programs.emplace_back(newProg);
        }
    } catch (const Error &) {
        // Here file is not a valid STS source. Ignore and continue if it's implicit package import, else throw
        // the syntax error as usual

        if (!parseListIdx.isImplicitPackageImported) {
            throw;
        }

        util::Helpers::LogWarning("Error during parse of file '", parseListIdx.sourcePath,
                                  "' in compiled package. File will be omitted.");
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
            directImportsFromMainSource.emplace_back(pl.sourcePath);
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
            std::ifstream inputStream(parseList[idx].sourcePath.Mutf8());
            const auto data = importPathManager_->GetImportData(parseList[idx].sourcePath, Extension());
            if (!data.hasDecl) {
                importPathManager_->MarkAsParsed(parseList[idx].sourcePath);
                continue;
            }

            if (GetProgram()->SourceFilePath().Is(parseList[idx].sourcePath.Mutf8())) {
                return programs;
            }

            if (inputStream.fail()) {
                ThrowSyntaxError({"Failed to open file: ", parseList[idx].sourcePath.Mutf8()});
            }

            std::stringstream ss;
            ss << inputStream.rdbuf();
            auto externalSource = ss.str();

            auto currentLang = GetContext().SetLanguage(data.lang);
            auto extSrc = Allocator()->New<util::UString>(externalSource, Allocator());
            importPathManager_->MarkAsParsed(parseList[idx].sourcePath);

            // In case of implicit package import, if we find a malformed STS file in the package's directory, instead
            // of aborting compilation we just ignore the file

            // NOTE (mmartin): after the multiple syntax error handling in the parser is implemented, this try-catch
            // must be changed, as exception throwing will be removed

            TryParseSource(parseList[idx], extSrc, directImportsFromMainSource, programs);

            GetContext().SetLanguage(currentLang);
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
    GetProgram()->SetDeclarationModuleInfo();
    return program;
}

ir::Statement *ETSParser::ParseIdentKeyword()
{
    const auto token = Lexer()->GetToken();
    ASSERT(token.Type() == lexer::TokenType::LITERAL_IDENT);
    switch (token.KeywordType()) {
        case lexer::TokenType::KEYW_STRUCT: {
            // Remove this ThrowSyntaxError when struct is implemented in #12726
            ThrowSyntaxError("Struct types are not supported yet!");
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

    bool isDeclare = InAmbientContext();
    if (functionContext.IsAsync() && isDeclare) {
        ThrowSyntaxError("The modifier async cannot be used in an ambient context.");
    }

    // clang-format off
    ir::ModifierFlags mFlags = isDeclare ? ir::ModifierFlags::DECLARE : ir::ModifierFlags::NONE;
    ir::ScriptFunctionFlags funcFlags =
        isDeclare ? (functionContext.Flags() | ir::ScriptFunctionFlags::EXTERNAL) : functionContext.Flags();
    auto *funcNode = AllocNode<ir::ScriptFunction>(
        Allocator(), ir::ScriptFunction::ScriptFunctionData {body, std::move(signature), funcFlags, mFlags, isDeclare,
                                                             GetContext().GetLanguage()});
    funcNode->SetRange({startLoc, endLoc});
    // clang-format on

    return funcNode;
}

std::tuple<bool, ir::BlockStatement *, lexer::SourcePosition, bool> ETSParser::ParseFunctionBody(
    [[maybe_unused]] const ArenaVector<ir::Expression *> &params, [[maybe_unused]] ParserStatus newStatus,
    [[maybe_unused]] ParserStatus contextStatus)
{
    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        LogSyntaxError({"Expected token '{', got '", TokenToString(Lexer()->GetToken().Type()), "'"});
        return {false, nullptr, Lexer()->GetToken().End(), false};
    }

    ir::BlockStatement *body = ParseBlockStatement();

    return {true, body, body->End(), false};
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
    if ((memberModifiers & (~(ir::ModifierFlags::ACCESS | ir::ModifierFlags::DECLARE))) != 0) {
        ThrowSyntaxError(
            {"The modifier for a constructor should be limited to access modifiers(private, internal, protected, "
             "public)."});
    }
    auto *memberName = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    memberModifiers |= ir::ModifierFlags::CONSTRUCTOR;
    Lexer()->NextToken();
    auto *classMethod = ParseClassMethodDefinition(memberName, memberModifiers);
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

void ETSParser::CheckAccessorDeclaration(ir::ModifierFlags memberModifiers)
{
    ir::ModifierFlags methodModifiersNotAccessorModifiers = ir::ModifierFlags::NATIVE | ir::ModifierFlags::ASYNC;
    if ((memberModifiers & methodModifiersNotAccessorModifiers) != 0) {
        ThrowSyntaxError("Modifiers of getter and setter are limited to ('abstract', 'static', 'final', 'override').");
    }
}

ir::AstNode *ETSParser::ParseInnerRest(const ArenaVector<ir::AstNode *> &properties,
                                       ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags memberModifiers,
                                       const lexer::SourcePosition &startLoc)
{
    if (Lexer()->Lookahead() != lexer::LEX_CHAR_LEFT_PAREN && Lexer()->Lookahead() != lexer::LEX_CHAR_LESS_THAN &&
        (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_GET ||
         Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_SET)) {
        CheckAccessorDeclaration(memberModifiers);
        return ParseClassGetterSetterMethod(properties, modifiers, memberModifiers);
    }

    if ((GetContext().Status() & ParserStatus::IN_NAMESPACE) != 0) {
        auto type = Lexer()->GetToken().Type();
        if (type == lexer::TokenType::KEYW_FUNCTION || type == lexer::TokenType::KEYW_LET ||
            type == lexer::TokenType::KEYW_CONST) {
            Lexer()->NextToken();
        }
    }

    auto parseClassMethod = [&memberModifiers, &startLoc, this](ir::Identifier *methodName) {
        auto *classMethod = ParseClassMethodDefinition(methodName, memberModifiers, nullptr);
        classMethod->SetStart(startLoc);
        return classMethod;
    };

    if (InAmbientContext()) {
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS &&
            (GetContext().Status() & ParserStatus::IN_CLASS_BODY) != 0U) {
            // Special case for processing of special '(param: type): returnType` identifier using in ambient context
            auto ident = CreateInvokeIdentifier();
            memberModifiers |= ir::ModifierFlags::STATIC;
            return parseClassMethod(ident);
        }
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
            auto const savePos = Lexer()->Save();
            Lexer()->NextToken();
            if (Lexer()->GetToken().Ident().Is("Symbol")) {
                Lexer()->Rewind(savePos);
            } else {
                return ParseAmbientSignature();
            }
        }
    }

    auto *memberName = ExpectIdentifier();
    if (memberName == nullptr) {  // Error processing.
        return nullptr;
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS ||
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        return parseClassMethod(memberName);
    }

    ArenaVector<ir::AstNode *> fieldDeclarations(Allocator()->Adapter());
    auto *placeholder = AllocNode<ir::TSInterfaceBody>(std::move(fieldDeclarations));
    ParseClassFieldDefinition(memberName, memberModifiers, placeholder->BodyPtr());
    return placeholder;
}

ir::AnnotationDeclaration *ETSParser::ParseAnnotationDeclaration(ir::ModifierFlags flags)
{
    const lexer::SourcePosition startLoc = Lexer()->GetToken().Start();
    // The default modifier of the annotation is public abstract
    flags |= ir::ModifierFlags::ABSTRACT | ir::ModifierFlags::PUBLIC | ir::ModifierFlags::ANNOTATION_DECLARATION;
    flags &= ~ir::ModifierFlags::STATIC;
    if (InAmbientContext()) {
        flags |= ir::ModifierFlags::DECLARE;
    }

    Lexer()->NextToken();  // eat 'interface'
    auto *ident = ExpectIdentifier(false, true);

    ExpectToken(lexer::TokenType::PUNCTUATOR_LEFT_BRACE, false);
    auto properties = ParseAnnotationProperties(flags);

    lexer::SourcePosition endLoc = Lexer()->GetToken().End();

    auto *annotationDecl = AllocNode<ir::AnnotationDeclaration>(ident, std::move(properties));
    annotationDecl->SetRange({startLoc, endLoc});
    annotationDecl->AddModifier(flags);
    return annotationDecl;
}

static bool IsMemberAccessModifiers(lexer::TokenType type)
{
    return type == lexer::TokenType::KEYW_STATIC || type == lexer::TokenType::KEYW_ASYNC ||
           type == lexer::TokenType::KEYW_PUBLIC || type == lexer::TokenType::KEYW_PROTECTED ||
           type == lexer::TokenType::KEYW_PRIVATE || type == lexer::TokenType::KEYW_DECLARE ||
           type == lexer::TokenType::KEYW_READONLY || type == lexer::TokenType::KEYW_ABSTRACT ||
           type == lexer::TokenType::KEYW_CONST || type == lexer::TokenType::KEYW_FINAL ||
           type == lexer::TokenType::KEYW_NATIVE;
}

ArenaVector<ir::AstNode *> ETSParser::ParseAnnotationProperties(ir::ModifierFlags memberModifiers)
{
    Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
    ArenaVector<ir::AstNode *> properties(Allocator()->Adapter());

    while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        if ((memberModifiers & ir::ModifierFlags::ANNOTATION_DECLARATION) != 0U &&
            Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
            Lexer()->NextToken();  // eat ';'
            continue;
        }
        // check no modifiers
        if (IsMemberAccessModifiers(Lexer()->GetToken().Type())) {
            ThrowSyntaxError("Annotation property can not have access modifiers", Lexer()->GetToken().Start());
        }
        auto *fieldName = ExpectIdentifier();
        if (fieldName == nullptr) {
            ThrowSyntaxError("Unexpected token.");
        }
        bool needTypeAnnotation = (memberModifiers & ir::ModifierFlags::ANNOTATION_USAGE) == 0U;
        ir::AstNode *property = ParseAnnotationProperty(fieldName, memberModifiers, needTypeAnnotation);
        properties.push_back(property);

        if ((memberModifiers & ir::ModifierFlags::ANNOTATION_USAGE) != 0U &&
            Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
            ExpectToken(lexer::TokenType::PUNCTUATOR_COMMA);  // eat ','
        }
    }

    Lexer()->NextToken();  // eat "}"
    return properties;
}

bool ETSParser::ValidAnnotationValue(ir::Expression *initializer)
{
    if (initializer->IsArrayExpression()) {
        for (auto *element : initializer->AsArrayExpression()->Elements()) {
            if (!ValidAnnotationValue(element)) {
                return false;
            }
        }
        return true;
    }
    return initializer->IsStringLiteral() || initializer->IsNumberLiteral() || initializer->IsMemberExpression() ||
           initializer->IsBooleanLiteral();
}

ir::AstNode *ETSParser::ParseAnnotationProperty(ir::Identifier *fieldName, ir::ModifierFlags memberModifiers,
                                                bool needTypeAnnotation)
{
    lexer::SourcePosition endLoc = fieldName->End();
    // check no methods
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS ||
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        ThrowSyntaxError("Annotation can not have method as property", Lexer()->GetToken().Start());
    }

    ir::TypeNode *typeAnnotation = nullptr;
    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::REPORT_ERROR;
    if (needTypeAnnotation && Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        typeAnnotation = ParseTypeAnnotation(&options);
        endLoc = typeAnnotation->End();
    }

    if (typeAnnotation == nullptr && (memberModifiers & ir::ModifierFlags::ANNOTATION_DECLARATION) != 0) {
        ThrowSyntaxError("Missing type annotation for property '" + fieldName->Name().Mutf8() + "'.",
                         Lexer()->GetToken().Start());
    }

    ir::Expression *initializer = nullptr;
    lexer::SourcePosition savePos;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION ||
        (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON)) {
        Lexer()->NextToken();  // eat '=' or ':'
        savePos = Lexer()->GetToken().Start();
        initializer = ParseExpression();
    }

    if (initializer == nullptr && (memberModifiers & ir::ModifierFlags::ANNOTATION_USAGE) != 0) {
        ThrowSyntaxError("Invalid argument passed to '" + fieldName->Name().Mutf8() + "'", Lexer()->GetToken().Start());
    }

    if (initializer != nullptr && !ValidAnnotationValue(initializer)) {
        ThrowSyntaxError("Invalid value for annotation field, expected a constant literal.", savePos);
    }

    memberModifiers |= ir::ModifierFlags::PUBLIC;
    memberModifiers |= ir::ModifierFlags::ABSTRACT;
    auto *field =
        AllocNode<ir::ClassProperty>(fieldName, initializer, typeAnnotation, memberModifiers, Allocator(), false);
    field->SetRange({fieldName->Start(), initializer != nullptr ? initializer->End() : endLoc});
    return field;
}

ArenaVector<ir::AnnotationUsage *> ETSParser::ParseAnnotations(ir::ModifierFlags &flags, bool isTopLevelSt)
{
    ArenaVector<ir::AnnotationUsage *> annotations(Allocator()->Adapter());
    bool hasMoreAnnotations = true;
    while (hasMoreAnnotations) {
        if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_INTERFACE) {
            if (!annotations.empty()) {
                ThrowSyntaxError("Annotations cannot be applied to an annotation declaration.");
            }

            if (!isTopLevelSt) {
                ThrowSyntaxError("Annotations can only be declared at the top level.");
            }
            flags |= ir::ModifierFlags::ANNOTATION_DECLARATION;
            return annotations;
        }

        annotations.emplace_back(ParseAnnotationUsage());
        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_AT) {
            hasMoreAnnotations = false;
        } else {
            Lexer()->NextToken();
        }
    }
    flags |= ir::ModifierFlags::ANNOTATION_USAGE;
    return annotations;
}

ir::AnnotationUsage *ETSParser::ParseAnnotationUsage()
{
    const lexer::SourcePosition startLoc = Lexer()->GetToken().Start();
    auto ident = ExpectIdentifier();
    ident->SetAnnotataionUsage();
    auto flags = ir::ModifierFlags::ANNOTATION_USAGE;
    ArenaVector<ir::AstNode *> properties(Allocator()->Adapter());

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        Lexer()->NextToken();  // eat '('
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
            properties = ParseAnnotationProperties(flags);
        } else if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
            // handle single field annotation
            auto *singleParamName = AllocNode<ir::Identifier>(compiler::Signatures::ANNOTATION_KEY_VALUE, Allocator());
            singleParamName->SetRange({Lexer()->GetToken().Start(), Lexer()->GetToken().End()});

            const auto savePos = Lexer()->GetToken().Start();
            auto *initializer = ParseExpression();
            if (initializer != nullptr && !ValidAnnotationValue(initializer)) {
                ThrowSyntaxError("Invalid value for annotation field, expected a constant literal.", savePos);
            }

            auto *singleParam = AllocNode<ir::ClassProperty>(singleParamName, initializer, nullptr,
                                                             ir::ModifierFlags::ANNOTATION_USAGE, Allocator(), false);
            singleParam->SetRange(
                {singleParamName->Start(), initializer != nullptr ? initializer->End() : singleParamName->End()});
            properties.push_back(singleParam);
        }
        ExpectToken(lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS, true);  // eat ')'
    }

    auto *annotationUsage = AllocNode<ir::AnnotationUsage>(ident, std::move(properties));
    annotationUsage->AddModifier(flags);
    annotationUsage->SetRange({startLoc, Lexer()->GetToken().End()});
    return annotationUsage;
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
            auto *ns = ParseNamespaceDeclaration(ir::ModifierFlags::DECLARE | ir::ModifierFlags::EXPORT);
            GetContext().Status() &= ~ParserStatus::IN_NAMESPACE;
            return ns;
        }
        case lexer::TokenType::KEYW_CLASS: {
            return ParseClassDeclaration(modifiers);
        }
        case lexer::TokenType::LITERAL_IDENT: {
            if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_STRUCT) {
                return ParseStructDeclaration(modifiers);
            }
            [[fallthrough]];
        }
        default: {
            ThrowUnexpectedToken(Lexer()->GetToken().Type());
        }
    }
}

ir::TSTypeAliasDeclaration *ETSParser::ParseTypeAliasDeclaration()
{
    ASSERT(Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_TYPE);

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
            TypeAnnotationParsingOptions::REPORT_ERROR | TypeAnnotationParsingOptions::ALLOW_DECLARATION_SITE_VARIANCE;
        ir::TSTypeParameterDeclaration *params = ParseTypeParameterDeclaration(&options);
        typeAliasDecl->SetTypeParameters(params);
        params->SetParent(typeAliasDecl);
    }

    if (!Lexer()->TryEatTokenType(lexer::TokenType::PUNCTUATOR_SUBSTITUTION)) {
        ThrowSyntaxError("'=' expected");
    }

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::REPORT_ERROR;
    ir::TypeNode *typeAnnotation = ParseTypeAnnotation(&options);
    if (typeAnnotation != nullptr) {  // Error processing.
        typeAliasDecl->SetTsTypeAnnotation(typeAnnotation);
        typeAnnotation->SetParent(typeAliasDecl);
    }

    typeAliasDecl->SetRange({typeStart, Lexer()->GetToken().End()});
    return typeAliasDecl;
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

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_FORMAT) {
        return ParseTypeFormatPlaceholder();
    }

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

std::optional<lexer::SourcePosition> ETSParser::GetDefaultParamPosition(ArenaVector<ir::Expression *> params)
{
    for (auto &param : params) {
        if (param->IsETSParameterExpression() && param->AsETSParameterExpression()->IsDefault()) {
            return param->AsETSParameterExpression()->Initializer()->Start();
        }
    }
    return {};
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
        if (((*options) & TypeAnnotationParsingOptions::REPORT_ERROR) != 0) {
            ThrowExpectedToken(lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS);
        }

        Lexer()->Rewind(savedPos);
        typeAnnotation = nullptr;
    } else {
        Lexer()->NextToken();  // eat ')'
    }
}

void ETSParser::ThrowIfVarDeclaration(VariableParsingFlags flags)
{
    if ((flags & VariableParsingFlags::VAR) != 0) {
        ThrowUnexpectedToken(lexer::TokenType::KEYW_VAR);
    }
}

ir::Statement *ETSParser::ParseExport(lexer::SourcePosition startLoc, ir::ModifierFlags modifiers)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY ||
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

    // re-export directive
    ir::ImportSource *reExportSource = ParseSourceFromClause(true);

    lexer::SourcePosition endLoc = reExportSource->Source()->End();
    auto *reExportDeclaration = AllocNode<ir::ETSImportDeclaration>(reExportSource, std::move(specifiers));
    reExportDeclaration->SetRange({startLoc, endLoc});

    ConsumeSemicolon(reExportDeclaration);

    auto reExport = AllocNode<ir::ETSReExportDeclaration>(reExportDeclaration, std::vector<std::string>(),
                                                          GetProgram()->SourceFilePath(), Allocator());
    reExport->AddModifier(modifiers);
    return reExport;
}

ir::ETSPackageDeclaration *ETSParser::ParsePackageDeclaration()
{
    auto startLoc = Lexer()->GetToken().Start();

    if (Lexer()->GetToken().Type() != lexer::TokenType::KEYW_PACKAGE) {
        // NOTE(rsipka): Unclear behavior/code. Currently, all entry programs omit the module name if it is not a
        // package module and the '--ets-module' option is not specified during compilation
        GetProgram()->SetModuleInfo(GetProgram()->FileName(), false, GetProgram()->IsEntryPoint() && !IsETSModule());
        return nullptr;
    }

    Lexer()->NextToken();

    ir::Expression *name = ParseQualifiedName();

    auto *packageDeclaration = AllocNode<ir::ETSPackageDeclaration>(name);
    packageDeclaration->SetRange({startLoc, Lexer()->GetToken().End()});

    ConsumeSemicolon(packageDeclaration);

    auto packageName =
        name->IsIdentifier() ? name->AsIdentifier()->Name() : name->AsTSQualifiedName()->ToString(Allocator());

    GetProgram()->SetModuleInfo(packageName, true);

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
    if (globalProgram_->AbsoluteName() != resolvedImportPath) {
        importPathManager_->AddToParseList(resolvedImportPath,
                                           (GetContext().Status() & ParserStatus::IN_DEFAULT_IMPORTS) != 0U
                                               ? util::ImportFlags::DEFAULT_IMPORT
                                               : util::ImportFlags::NONE);
    } else if (!IsETSModule()) {
        ThrowSyntaxError("Please compile `" + globalProgram_->FileName().Mutf8() + "." +
                         globalProgram_->SourceFile().GetExtension().Mutf8() +
                         "` with `--ets-module` option. It is being imported by another file.");
    }

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

        ir::ImportKinds importKind =
            Lexer()->TryEatTokenKeyword(lexer::TokenType::KEYW_TYPE) ? ir::ImportKinds::TYPE : ir::ImportKinds::VALUE;

        ArenaVector<ir::AstNode *> specifiers(Allocator()->Adapter());
        ArenaVector<ir::AstNode *> defaultSpecifiers(Allocator()->Adapter());

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY) {
            if (importKind == ir::ImportKinds::TYPE) {
                ThrowSyntaxError("Type import requires selective binding to define the required imported elements.");
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
            ir::ImportSource *importSource = ParseSourceFromClause(true);

            lexer::SourcePosition endLoc = importSource->Source()->End();
            auto *importDeclaration =
                AllocNode<ir::ETSImportDeclaration>(importSource, std::move(specifiers), importKind);
            importDeclaration->SetRange({startLoc, endLoc});

            ConsumeSemicolon(importDeclaration);
            statements.push_back(importDeclaration);
        }

        if (!defaultSpecifiers.empty()) {
            Lexer()->Rewind(pos);
            ir::ImportSource *importSourceDefault = ParseSourceFromClause(true);

            lexer::SourcePosition endLocDef = importSourceDefault->Source()->End();
            auto *importDeclarationDefault =
                AllocNode<ir::ETSImportDeclaration>(importSourceDefault, std::move(defaultSpecifiers), importKind);
            importDeclarationDefault->SetRange({startLoc, endLocDef});

            ConsumeSemicolon(importDeclarationDefault);
            util::Helpers::CheckDefaultImport(statements);
            statements.push_back(importDeclarationDefault);
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

    exports.emplace_back(AllocNode<ir::ExportSpecifier>(exported, ParseNamedExport(token)));
    auto result = AllocNode<ir::ExportNamedDeclaration>(Allocator(), static_cast<ir::StringLiteral *>(nullptr),
                                                        std::move(exports));
    result->AddModifier(modifiers);
    ConsumeSemicolon(result);

    return result;
}

bool ETSParser::IsDefaultImport()
{
    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_DEFAULT) {
        Lexer()->NextToken();
        if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_AS) {
            Lexer()->NextToken();
            return true;
        }
        ThrowSyntaxError("Unexpected token. 'as' keyword is expected.");
    }
    return false;
}

using ImportSpecifierVector = ArenaVector<ir::ImportSpecifier *>;
using ImportDefaultSpecifierVector = ArenaVector<ir::ImportDefaultSpecifier *>;
std::pair<ImportSpecifierVector, ImportDefaultSpecifierVector> ETSParser::ParseNamedSpecifiers()
{
    // NOTE(user): handle qualifiedName in file bindings: qualifiedName '.' '*'
    if (!Lexer()->TryEatTokenType(lexer::TokenType::PUNCTUATOR_LEFT_BRACE)) {
        ThrowExpectedToken(lexer::TokenType::PUNCTUATOR_LEFT_BRACE);
    }

    auto fileName = GetProgram()->SourceFilePath().Mutf8();

    ArenaVector<ir::ImportSpecifier *> result(Allocator()->Adapter());
    ArenaVector<ir::ImportDefaultSpecifier *> resultDefault(Allocator()->Adapter());

    while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY) {
            ThrowSyntaxError("The '*' token is not allowed as a selective binding (between braces)");
        }

        if (!IsDefaultImport()) {
            if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
                ThrowSyntaxError("Unexpected token");
            }

            lexer::Token importedToken = Lexer()->GetToken();
            auto *imported = AllocNode<ir::Identifier>(importedToken.Ident(), Allocator());
            ir::Identifier *local = nullptr;
            imported->SetRange(Lexer()->GetToken().Loc());

            Lexer()->NextToken();

            if (CheckModuleAsModifier() && Lexer()->TryEatTokenType(lexer::TokenType::KEYW_AS)) {
                local = ParseNamedImport(Lexer()->GetToken());
                Lexer()->NextToken();
            } else {
                local = ParseNamedImport(importedToken);
            }

            auto *specifier = AllocNode<ir::ImportSpecifier>(imported, local);
            specifier->SetRange({imported->Start(), local->End()});

            util::Helpers::CheckImportedName(result, specifier, fileName);

            result.emplace_back(specifier);
        } else {
            auto *imported = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
            imported->SetRange(Lexer()->GetToken().Loc());
            Lexer()->NextToken();
            auto *specifier = AllocNode<ir::ImportDefaultSpecifier>(imported);
            specifier->SetRange({imported->Start(), imported->End()});

            util::Helpers::CheckDefaultImportedName(resultDefault, specifier, fileName);

            resultDefault.emplace_back(specifier);
        }
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
            Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat comma
        }
    }
    Lexer()->NextToken();  // eat '}'
    std::pair<ArenaVector<ir::ImportSpecifier *>, ArenaVector<ir::ImportDefaultSpecifier *>> resultSpecifiers(
        result, resultDefault);

    return resultSpecifiers;
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
        auto *specifier = AllocNode<ir::ImportNamespaceSpecifier>(local);
        specifier->SetRange({namespaceStart, Lexer()->GetToken().End()});
        specifiers->push_back(specifier);
        return;
    }

    ExpectToken(lexer::TokenType::KEYW_AS, true);  // eat `as` literal
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
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::REPORT_ERROR;
        ir::TypeNode *typeAnnotation = ParseTypeAnnotation(&options);
        if (typeAnnotation == nullptr) {  // Error processing.
            return nullptr;
        }

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
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::REPORT_ERROR;
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
    if (initializer == nullptr) {  // Error processing.
        return nullptr;
    }

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
        static_cast<uint32_t>(flags & VariableParsingFlags::ACCEPT_CONST_NO_INIT) == 0U && !InAmbientContext()) {
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

        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::REPORT_ERROR;
        if (auto *typeAnnotation = ParseTypeAnnotation(&options); typeAnnotation != nullptr) {
            typeAnnotation->SetParent(param);
            param->SetTsTypeAnnotation(typeAnnotation);
        }
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        ThrowSyntaxError("Catch clause variable cannot have an initializer");
    }
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

ir::Expression *ETSParser::ParseExpressionOrTypeAnnotation(lexer::TokenType type,
                                                           [[maybe_unused]] ExpressionParseFlags flags)
{
    if (type == lexer::TokenType::KEYW_INSTANCEOF) {
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::REPORT_ERROR;

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

ir::AstNode *ETSParser::ParseAmbientSignature()
{
    auto const startPos = Lexer()->GetToken().Start();

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Unexpected token at", Lexer()->GetToken().Start());
    }
    auto const indexName = Lexer()->GetToken().Ident();

    Lexer()->NextToken();
    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
        ThrowSyntaxError("Index type expected in index signature", Lexer()->GetToken().Start());
    }

    Lexer()->NextToken();  // eat ":"
    if (Lexer()->GetToken().KeywordType() != lexer::TokenType::KEYW_NUMBER) {
        ThrowSyntaxError("Index type must be number in index signature", Lexer()->GetToken().Start());
    }

    Lexer()->NextToken();  // eat indexType
    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
        ThrowSyntaxError("] expected in index signature", Lexer()->GetToken().Start());
    }

    Lexer()->NextToken();  // eat "]"
    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
        ThrowSyntaxError("An index signature must have a type annotation.", Lexer()->GetToken().Start());
    }

    Lexer()->NextToken();  // eat ":"
    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Return type of index signature from exported class or interface need to be identifier",
                         Lexer()->GetToken().Start());
    }
    auto const returnType =
        AllocNode<ir::ETSTypeReferencePart>(AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator()));

    auto dummyNode = AllocNode<ir::DummyNode>(compiler::Signatures::AMBIENT_INDEXER, indexName, returnType,
                                              ir::DummyNodeFlag::INDEXER);
    dummyNode->SetRange({startPos, Lexer()->GetToken().End()});
    Lexer()->NextToken();  // eat return type
    return dummyNode;
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
        TypeAnnotationParsingOptions newOptions =
            TypeAnnotationParsingOptions::REPORT_ERROR | TypeAnnotationParsingOptions::IGNORE_FUNCTION_TYPE;
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
        case lexer::TokenType::KEYW_FINAL:
        case lexer::TokenType::KEYW_INTERFACE:
        case lexer::TokenType::KEYW_ASYNC: {
            return;
        }
        default: {
            if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_AT) {
                return;
            }
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
        LogSyntaxError("Unexpected token, expected identifier after 'function' keyword");
    }
    newStatus |= ParserStatus::FUNCTION_DECLARATION;
    if (identNode != nullptr) {
        CheckRestrictedBinding(identNode->Name(), identNode->Start());
    }

    ir::ScriptFunction *func = ParseFunction(newStatus, className);
    if (identNode != nullptr) {  // Error processing.
        func->SetIdent(identNode);
    }

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

void ETSParser::AddPackageSourcesToParseList()
{
    importPathManager_->AddToParseList(GetProgram()->SourceFileFolder(), util::ImportFlags::IMPLICIT_PACKAGE_IMPORT);

    // Global program file is always in the same folder that we scanned, but we don't need to parse it twice
    importPathManager_->MarkAsParsed(globalProgram_->SourceFilePath());
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
