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

#include "ETSparser.h"

#include "parser/parserFlags.h"
#include "util/arktsconfig.h"
#include "util/helpers.h"
#include "util/language.h"
#include "binder/privateBinding.h"
#include "binder/scope.h"
#include "binder/ETSBinder.h"
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
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/sequenceExpression.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/thisExpression.h"
#include "ir/expressions/superExpression.h"
#include "ir/expressions/newExpression.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/updateExpression.h"
#include "ir/expressions/arrowFunctionExpression.h"
#include "ir/expressions/unaryExpression.h"
#include "ir/expressions/yieldExpression.h"
#include "ir/expressions/awaitExpression.h"
#include "ir/expressions/literals/bigIntLiteral.h"
#include "ir/expressions/literals/booleanLiteral.h"
#include "ir/expressions/literals/charLiteral.h"
#include "ir/expressions/literals/nullLiteral.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/expressions/templateLiteral.h"
#include "ir/expressions/objectExpression.h"
#include "ir/module/importDeclaration.h"
#include "ir/module/importDefaultSpecifier.h"
#include "ir/module/importSpecifier.h"
#include "ir/statements/assertStatement.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/emptyStatement.h"
#include "ir/statements/ifStatement.h"
#include "ir/statements/labelledStatement.h"
#include "ir/statements/switchStatement.h"
#include "ir/statements/throwStatement.h"
#include "ir/statements/tryStatement.h"
#include "ir/statements/whileStatement.h"
#include "ir/statements/doWhileStatement.h"
#include "ir/statements/breakStatement.h"
#include "ir/statements/continueStatement.h"
#include "ir/statements/debuggerStatement.h"
#include "ir/ets/etsLaunchExpression.h"
#include "ir/ets/etsClassLiteral.h"
#include "ir/ets/etsPrimitiveType.h"
#include "ir/ets/etsPackageDeclaration.h"
#include "ir/ets/etsWildcardType.h"
#include "ir/ets/etsNewArrayInstanceExpression.h"
#include "ir/ets/etsFunctionType.h"
#include "ir/ets/etsNewClassInstanceExpression.h"
#include "ir/ets/etsNewMultiDimArrayInstanceExpression.h"
#include "ir/ets/etsScript.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/ets/etsImportSource.h"
#include "ir/ets/etsImportDeclaration.h"
#include "ir/ets/etsStructDeclaration.h"
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
#include "libpandabase/os/file.h"
#include "libpandabase/utils/json_parser.h"
#include "generated/signatures.h"

#if defined PANDA_TARGET_MOBILE
#define USE_UNIX_SYSCALL
#endif

#ifdef USE_UNIX_SYSCALL
#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>
#else
#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif
#endif

namespace panda::es2panda::parser {
using namespace std::literals::string_literals;

std::unique_ptr<lexer::Lexer> ETSParser::InitLexer(const SourceFile &source_file)
{
    GetProgram()->SetSource(source_file);
    auto lexer = std::make_unique<lexer::ETSLexer>(&GetContext());
    SetLexer(lexer.get());
    return lexer;
}

void ETSParser::ParseProgram(ScriptKind kind)
{
    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();
    Lexer()->NextToken();
    GetProgram()->SetKind(kind);

    if (GetProgram()->SourceFile().Utf8()[0] == '@') {
        // TODO(user): handle multiple sourceFiles
    }

    auto statements = PrepareGlobalClass();
    ParseDefaultSources();

    ParseETSGlobalScript(start_loc, statements);
}

void ETSParser::ParseETSGlobalScript(lexer::SourcePosition start_loc, ArenaVector<ir::Statement *> &statements)
{
    auto paths = ParseImportDeclarations(statements);

    // remove external sources from paths because already parsed them
    paths.erase(remove_if(begin(paths), end(paths),
                          [this](auto x) {
                              return find(begin(parsed_sources_), end(parsed_sources_), x) != end(parsed_sources_);
                          }),
                end(paths));

    parsed_sources_.insert(parsed_sources_.end(), paths.begin(), paths.end());

    ParseSources(paths, false);
    ParseTopLevelDeclaration(statements);

    auto *ets_script = AllocNode<ir::ETSScript>(Allocator(), Binder()->GetScope(), std::move(statements), GetProgram());
    Binder()->GetScope()->BindNode(ets_script);
    ets_script->SetRange({start_loc, Lexer()->GetToken().End()});
    GetProgram()->SetAst(ets_script);
}

void ETSParser::CreateGlobalClass()
{
    auto *ident = AllocNode<ir::Identifier>(compiler::Signatures::ETS_GLOBAL, Allocator());
    auto [decl, var] = Binder()->NewVarDecl<binder::ClassDecl>(ident->Start(), ident->Name());
    ident->SetVariable(var);

    auto class_ctx = binder::LexicalScope<binder::ClassScope>(Binder());
    auto *class_def =
        AllocNode<ir::ClassDefinition>(Allocator(), class_ctx.GetScope(), ident, ir::ClassDefinitionModifiers::GLOBAL,
                                       ir::ModifierFlags::ABSTRACT, Language(Language::Id::ETS));
    GetProgram()->SetGlobalClass(class_def);

    auto *class_decl = AllocNode<ir::ClassDeclaration>(class_def, Allocator());
    class_def->Scope()->BindNode(class_decl);
    decl->BindNode(class_decl);
}

ArenaVector<ir::Statement *> ETSParser::PrepareGlobalClass()
{
    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());
    ParsePackageDeclaration(statements);
    CreateGlobalClass();

    return statements;
}

ArenaVector<ir::Statement *> ETSParser::PrepareExternalGlobalClass([[maybe_unused]] const SourceFile &source_file)
{
    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());
    ParsePackageDeclaration(statements);

    if (statements.empty()) {
        GetProgram()->SetGlobalClass(global_program_->GlobalClass());
    }

    auto &ext_sources = global_program_->ExternalSources();
    const util::StringView name = GetProgram()->SourceFilePath();

    auto res = ext_sources.end();
    if (!statements.empty()) {
        res = ext_sources.find(name);
    } else {
        const util::UString source_file_path(
            GetProgram()->SourceFilePath().Mutf8() + GetProgram()->GetPackageName().Mutf8(), Allocator());
        GetProgram()->SetSource(GetProgram()->SourceCode(), GetProgram()->SourceFile(), source_file_path.View());
    }

    if (res == ext_sources.end()) {
        Binder()->InitTopScope();
        CreateGlobalClass();
        auto ins_res = ext_sources.emplace(GetProgram()->SourceFilePath(), Allocator()->Adapter());
        ins_res.first->second.push_back(GetProgram());
    } else {
        res->second.push_back(GetProgram());
        auto *ext_prog = res->second.front();
        GetProgram()->SetGlobalClass(ext_prog->GlobalClass());
        // TODO(user): check nullptr cases and handle recursive imports
        if (ext_prog->Ast() != nullptr) {
            Binder()->ResetTopScope(ext_prog->GlobalScope());
        }
    }

    return statements;
}

static bool IsCompitableExtension(const std::string &extension)
{
    return extension == ".ets" || extension == ".ts";
}

void ETSParser::CollectDefaultSources()
{
    std::vector<std::string> paths;
    std::vector<std::string> stdlib = {"std/core", "std/math",       "std/containers",
                                       "std/time", "std/interop/js", "escompat"};

#ifdef USE_UNIX_SYSCALL
    for (auto const &path : stdlib) {
        auto resolved_path = ResolveImportPath(path);
        DIR *dir = opendir(resolved_path.c_str());

        if (dir == nullptr) {
            ThrowSyntaxError({"Cannot open folder: ", resolved_path});
        }

        struct dirent *entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_type != DT_REG) {
                continue;
            }

            std::string file_name = entry->d_name;
            std::string::size_type pos = file_name.find_last_of('.');

            if (pos == std::string::npos || !IsCompitableExtension(file_name.substr(pos))) {
                continue;
            }

            std::string file_path = path + "/" + entry->d_name;

            if (file_name == "Object.ets") {
                parsed_sources_.emplace(parsed_sources_.begin(), file_path);
            } else {
                parsed_sources_.emplace_back(file_path);
            }
        }

        closedir(dir);
    }
#else
    for (auto const &path : stdlib) {
        for (auto const &entry : fs::directory_iterator(ResolveImportPath(path))) {
            if (!fs::is_regular_file(entry) || !IsCompitableExtension(entry.path().extension().string())) {
                continue;
            }

            std::string base_name = path;
            std::size_t pos = entry.path().string().find_last_of(panda::os::file::File::GetPathDelim());

            base_name.append(entry.path().string().substr(pos, entry.path().string().size()));

            if (entry.path().filename().string() == "Object.ets") {
                parsed_sources_.emplace(parsed_sources_.begin(), base_name);
            } else {
                parsed_sources_.emplace_back(base_name);
            }
        }
    }
#endif
}

ETSParser::ImportData ETSParser::GetImportData(const std::string &path)
{
    auto &dynamic_paths = ArkTSConfig()->DynamicPaths();
    auto key = panda::os::NormalizePath(path);

    auto it = dynamic_paths.find(key);
    if (it == dynamic_paths.cend()) {
        key = panda::os::RemoveExtension(key);
    }

    while (it == dynamic_paths.cend() && !key.empty()) {
        it = dynamic_paths.find(key);
        if (it != dynamic_paths.cend()) {
            break;
        }
        key = panda::os::GetParentDir(key);
    }

    if (it != dynamic_paths.cend()) {
        return {it->second.GetLanguage(), key, it->second.HasDecl()};
    }
    return {ToLanguage(Extension()), path, true};
}

std::string ETSParser::ResolveImportPath(const std::string &path)
{
    char path_delimiter = panda::os::file::File::GetPathDelim().at(0);
    if (util::Helpers::IsRelativePath(path)) {
        if (GetProgram()->ResolvedFilePath().Mutf8().empty()) {
            return GetProgram()->SourceFilePath().Mutf8() + path_delimiter + path;
        }
        return GetProgram()->ResolvedFilePath().Mutf8() + path_delimiter + path;
    }

    std::string base_url;
    // Resolve delimeter character to basePath.
    if (path.find('/') == 0) {
        base_url = ArkTSConfig()->BaseUrl();

        base_url.append(path, 0, path.length());
        return base_url;
    }

    auto &dynamic_paths = ArkTSConfig()->DynamicPaths();
    auto it = dynamic_paths.find(path);
    if (it != dynamic_paths.cend() && !it->second.HasDecl()) {
        return path;
    }

    // Resolve the root part of the path.
    // E.g. root part of std/math is std.
    std::string::size_type pos = path.find('/');
    bool contains_delim = (pos != std::string::npos);
    std::string root_part = contains_delim ? path.substr(0, pos) : path;

    if (root_part == "std" && !GetOptions().std_lib.empty()) {  // Get std path from CLI if provided
        base_url = GetOptions().std_lib + "/std";
    } else if (root_part == "escompat" && !GetOptions().std_lib.empty()) {  // Get escompat path from CLI if provided
        base_url = GetOptions().std_lib + "/escompat";
    } else {
        auto resolved_path = ArkTSConfig()->ResolvePath(path);
        if (resolved_path.empty()) {
            ThrowSyntaxError({"Can't find prefix for '", path, "' in ", ArkTSConfig()->ConfigPath()});
        }
        return resolved_path;
    }

    if (contains_delim) {
        base_url.append(1, path_delimiter);
        base_url.append(path, root_part.length() + 1, path.length());
    }

    return base_url;
}

std::tuple<std::vector<std::string>, bool> ETSParser::CollectUserSources(const std::string &path)
{
    std::vector<std::string> user_paths;

    const std::string resolved_path = ResolveImportPath(path);
    const auto data = GetImportData(resolved_path);

    if (!data.has_decl) {
        return {user_paths, false};
    }

    if (!panda::os::file::File::IsDirectory(resolved_path)) {
        if (!panda::os::file::File::IsRegularFile(resolved_path)) {
            std::string import_extension = ".ets";

            if (!panda::os::file::File::IsRegularFile(resolved_path + import_extension)) {
                import_extension = ".ts";

                if (!panda::os::file::File::IsRegularFile(resolved_path + import_extension)) {
                    ThrowSyntaxError("Incorrect path: " + resolved_path);
                }
            }

            user_paths.emplace_back(path + import_extension);
            return {user_paths, true};
        }

        user_paths.emplace_back(path);
        return {user_paths, false};
    }

#ifdef USE_UNIX_SYSCALL
    DIR *dir = opendir(resolved_path.c_str());

    if (dir == nullptr) {
        ThrowSyntaxError({"Cannot open folder: ", resolved_path});
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_REG) {
            continue;
        }

        std::string file_name = entry->d_name;
        std::string::size_type pos = file_name.find_last_of('.');

        if (pos == std::string::npos || !IsCompitableExtension(file_name.substr(pos))) {
            continue;
        }

        std::string file_path = path + "/" + entry->d_name;

        if (file_name == "Object.ets") {
            user_paths.emplace(user_paths.begin(), file_path);
        } else {
            user_paths.emplace_back(file_path);
        }
    }

    closedir(dir);
#else
    for (auto const &entry : fs::directory_iterator(resolved_path)) {
        if (!fs::is_regular_file(entry) || !IsCompitableExtension(entry.path().extension().string())) {
            continue;
        }

        std::string base_name = path;
        std::size_t pos = entry.path().string().find_last_of(panda::os::file::File::GetPathDelim());

        base_name.append(entry.path().string().substr(pos, entry.path().string().size()));
        user_paths.emplace_back(base_name);
    }
#endif
    return {user_paths, false};
}

void ETSParser::ParseSources(const std::vector<std::string> &paths, bool is_external)
{
    GetContext().Status() |= is_external ? ParserStatus::IN_EXTERNAL : ParserStatus::IN_IMPORT;

    const std::size_t path_count = paths.size();
    for (std::size_t idx = 0; idx < path_count; idx++) {
        std::string resolved_path = ResolveImportPath(paths[idx]);
        const auto data = GetImportData(resolved_path);

        if (!data.has_decl) {
            continue;
        }

        std::ifstream input_stream(resolved_path.c_str());

        if (GetProgram()->SourceFile().Is(resolved_path)) {
            break;
        }

        if (input_stream.fail()) {
            ThrowSyntaxError({"Failed to open file: ", resolved_path.c_str()});
        }

        std::stringstream ss;
        ss << input_stream.rdbuf();
        auto external_source = ss.str();

        auto current_lang = GetContext().SetLanguage(data.lang);
        ParseSource({paths[idx].c_str(), external_source.c_str(), resolved_path.c_str(), false});
        GetContext().SetLanguage(current_lang);
    }

    GetContext().Status() &= is_external ? ~ParserStatus::IN_EXTERNAL : ~ParserStatus::IN_IMPORT;
}

void ETSParser::ParseDefaultSources()
{
    auto isp = InnerSourceParser(this);
    SourceFile source(binder::ETSBinder::DEFAULT_IMPORT_SOURCE_FILE, binder::ETSBinder::DEFAULT_IMPORT_SOURCE);
    auto lexer = InitLexer(source);
    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());

    Lexer()->NextToken();

    GetContext().Status() |= ParserStatus::IN_DEFAULT_IMPORTS;

    ParseImportDeclarations(statements);
    GetContext().Status() &= ~ParserStatus::IN_DEFAULT_IMPORTS;

    CollectDefaultSources();

    ParseSources(parsed_sources_, true);
}

void ETSParser::ParseSource(const SourceFile &source_file)
{
    auto *program = Allocator()->New<parser::Program>(Allocator(), Binder());
    auto esp = ExternalSourceParser(this, program);
    auto lexer = InitLexer(source_file);

    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();
    Lexer()->NextToken();

    auto statements = PrepareExternalGlobalClass(source_file);
    ParseETSGlobalScript(start_loc, statements);
}

ir::ScriptFunction *ETSParser::AddInitMethod(ArenaVector<ir::AstNode *> &global_properties)
{
    if (GetProgram()->Kind() == ScriptKind::STDLIB) {
        return nullptr;
    }

    // Lambda to create empty function node with signature: func(): void
    auto const create_function =
        [this](std::string_view const function_name, ir::ScriptFunctionFlags function_flags,
               ir::ModifierFlags const function_modifiers) -> std::pair<ir::ScriptFunction *, ir::MethodDefinition *> {
        auto *init_ident = AllocNode<ir::Identifier>(function_name, Allocator());
        ir::ScriptFunction *init_func;

        {
            binder::FunctionParamScope *func_param_scope;
            ArenaVector<ir::Expression *> params(Allocator()->Adapter());
            {
                FunctionParameterContext func_param_context(&GetContext(), Binder());
                func_param_scope = func_param_context.LexicalScope().GetScope();
            }
            auto param_ctx = binder::LexicalScope<binder::FunctionParamScope>::Enter(Binder(), func_param_scope, false);
            auto function_ctx = binder::LexicalScope<binder::FunctionScope>(Binder());
            auto *function_scope = function_ctx.GetScope();
            function_scope->BindParamScope(func_param_scope);
            func_param_scope->BindFunctionScope(function_scope);

            ArenaVector<ir::Statement *> statements(Allocator()->Adapter());
            auto *init_body = AllocNode<ir::BlockStatement>(Allocator(), function_scope, std::move(statements));
            function_scope->BindNode(init_body);

            init_func = AllocNode<ir::ScriptFunction>(function_scope, std::move(params), nullptr, init_body, nullptr,
                                                      function_flags, false, GetContext().GetLanguge());
            function_scope->BindNode(init_func);
            func_param_scope->BindNode(init_func);
        }

        init_func->SetIdent(init_ident);
        init_func->AddModifier(function_modifiers);

        auto *func_expr = AllocNode<ir::FunctionExpression>(init_func);

        auto *init_method = AllocNode<ir::MethodDefinition>(ir::MethodDefinitionKind::METHOD, init_ident, func_expr,
                                                            function_modifiers, Allocator(), false);

        return std::make_pair(init_func, init_method);
    };

    auto class_ctx = binder::LexicalScope<binder::ClassScope>::Enter(Binder(), GetProgram()->GlobalClassScope());

    // Create public method for module re-initialization. The assignments and statements are sequentially called inside.
    auto [init_func, init_method] = create_function(compiler::Signatures::INIT_METHOD, ir::ScriptFunctionFlags::NONE,
                                                    ir::ModifierFlags::STATIC | ir::ModifierFlags::PUBLIC);
    CreateClassFunctionDeclaration(init_method);
    global_properties.emplace_back(init_method);

    return init_func;
}

ArenaVector<ir::AstNode *> ETSParser::ParseTopLevelStatements(ArenaVector<ir::Statement *> &statements)
{
    ArenaVector<ir::AstNode *> global_properties(Allocator()->Adapter());
    bool default_export = false;

    using ParserFunctionPtr = std::function<ir::Statement *(ETSParser *)>;
    auto const parse_type = [this, &statements](std::size_t const current_pos,
                                                ParserFunctionPtr const &parser_function) -> void {
        ir::Statement *node = nullptr;

        {
            auto class_ctx =
                binder::LexicalScope<binder::ClassScope>::Enter(Binder(), GetProgram()->GlobalClassScope());
            node = parser_function(this);
            if (node != nullptr) {
                if (current_pos != std::numeric_limits<std::size_t>::max()) {
                    node->AddModifier(ir::ModifierFlags::EXPORT);
                }
                statements.push_back(node);
            }
        }

        if (node != nullptr) {
            AddGlobalDeclaration(node);
        }
    };

    // Add special '_$init$_' method that will hold all the top-level variable initializations (as assignments) and
    // statements. By default it will be called in the global class static constructor but also it can be called
    // directly from outside using public '_$init$_' method call in global scope.
    // TBD: now only a single-file modules are supported. Such a technique can be implemented in packages directly.
    ir::ScriptFunction *init_function = nullptr;
    if (GetProgram()->GetPackageName().Empty()) {
        init_function = AddInitMethod(global_properties);
    }

    while (Lexer()->GetToken().Type() != lexer::TokenType::EOS) {
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
            Lexer()->NextToken();
            continue;
        }

        auto current_pos = std::numeric_limits<size_t>::max();
        if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_EXPORT) {
            Lexer()->NextToken();
            current_pos = global_properties.size();

            if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_DEFAULT) {
                default_export = true;
                Lexer()->NextToken();
            }
        }

        lexer::SourcePosition start_loc = Lexer()->GetToken().Start();

        auto member_modifiers = ir::ModifierFlags::STATIC | ir::ModifierFlags::PUBLIC;

        if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_DECLARE) {
            CheckDeclare();
            member_modifiers |= ir::ModifierFlags::DECLARE;
        }

        switch (auto const token_type = Lexer()->GetToken().Type(); token_type) {
            case lexer::TokenType::KEYW_CONST: {
                member_modifiers |= ir::ModifierFlags::CONST;
                [[fallthrough]];
            }
            case lexer::TokenType::KEYW_LET: {
                Lexer()->NextToken();
                auto *member_name = ExpectIdentifier();
                auto class_ctx =
                    binder::LexicalScope<binder::ClassScope>::Enter(Binder(), GetProgram()->GlobalClassScope());
                ParseClassFieldDefiniton(member_name, member_modifiers, &global_properties, init_function);
                break;
            }
            case lexer::TokenType::KEYW_ASYNC:
            case lexer::TokenType::KEYW_NATIVE: {
                bool is_async = token_type == lexer::TokenType::KEYW_ASYNC;

                if (is_async) {
                    member_modifiers |= ir::ModifierFlags::ASYNC;
                } else {
                    member_modifiers |= ir::ModifierFlags::NATIVE;
                }

                Lexer()->NextToken();

                if (Lexer()->GetToken().Type() != lexer::TokenType::KEYW_FUNCTION) {
                    ThrowSyntaxError(
                        {is_async ? "'async'" : "'native'", " flags must be used for functions at top-level."});
                }
                [[fallthrough]];
            }
            case lexer::TokenType::KEYW_FUNCTION: {
                Lexer()->NextToken();
                auto *member_name = ExpectIdentifier();
                auto class_ctx =
                    binder::LexicalScope<binder::ClassScope>::Enter(Binder(), GetProgram()->GlobalClassScope());
                auto *class_method = ParseClassMethodDefinition(member_name, member_modifiers);
                class_method->SetStart(start_loc);
                if (!class_method->Function()->IsOverload()) {
                    global_properties.push_back(class_method);
                }
                break;
            }
            case lexer::TokenType::KEYW_STATIC:
                [[fallthrough]];
            case lexer::TokenType::KEYW_ABSTRACT:
                [[fallthrough]];
            case lexer::TokenType::KEYW_FINAL:
                [[fallthrough]];
            case lexer::TokenType::KEYW_ENUM:
                [[fallthrough]];
            case lexer::TokenType::KEYW_INTERFACE:
                [[fallthrough]];
            case lexer::TokenType::KEYW_CLASS: {
                // NOLINTNEXTLINE(modernize-avoid-bind)
                parse_type(current_pos, std::bind(&ETSParser::ParseTypeDeclaration, std::placeholders::_1, false));
                break;
            }
            case lexer::TokenType::KEYW_TYPE: {
                parse_type(current_pos, &ETSParser::ParseTypeAliasDeclaration);
                break;
            }
            default: {
                // If struct is a soft keyword, handle it here, otherwise it's an identifier.
                if (IsStructKeyword()) {
                    parse_type(current_pos, [](ETSParser *obj) { return obj->ParseTypeDeclaration(false); });
                    break;
                }

                if (init_function != nullptr) {
                    auto class_ctx =
                        binder::LexicalScope<binder::ClassScope>::Enter(Binder(), GetProgram()->GlobalClassScope());
                    if (auto *const statement = ParseTopLevelStatement(); statement != nullptr) {
                        statement->SetParent(init_function->Body());
                        init_function->Body()->AsBlockStatement()->Statements().emplace_back(statement);
                    }
                    break;
                }

                ThrowUnexpectedToken(token_type);
            }
        }

        GetContext().Status() &= ~ParserStatus::IN_AMBIENT_CONTEXT;

        while (current_pos < global_properties.size()) {
            if (default_export) {
                if (Binder()->AsETSBinder()->DefaultExport() != nullptr ||
                    global_properties.size() - current_pos != 1) {
                    ThrowSyntaxError("Only one default export is allowed in a module");
                }

                auto current_export = global_properties[current_pos++];
                current_export->AddModifier(ir::ModifierFlags::DEFAULT_EXPORT);
                Binder()->AsETSBinder()->SetDefaultExport(current_export);
                default_export = false;
            } else {
                global_properties[current_pos++]->AddModifier(ir::ModifierFlags::EXPORT);
            }
        }
    }

    return global_properties;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Statement *ETSParser::ParseTopLevelStatement(StatementParsingFlags flags)
{
    switch (auto const token_type = Lexer()->GetToken().Type(); token_type) {
        case lexer::TokenType::PUNCTUATOR_LEFT_BRACE: {
            return ParseBlockStatement();
        }
        case lexer::TokenType::PUNCTUATOR_SEMI_COLON: {
            return ParseEmptyStatement();
        }
        case lexer::TokenType::KEYW_ASSERT: {
            return ParseAssertStatement();
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
        case lexer::TokenType::KEYW_SWITCH: {
            return ParseSwitchStatement();
        }
        case lexer::TokenType::KEYW_DEBUGGER: {
            return ParseDebuggerStatement();
        }
        case lexer::TokenType::LITERAL_IDENT: {
            if (Lexer()->Lookahead() == lexer::LEX_CHAR_COLON) {
                const auto pos = Lexer()->Save();
                Lexer()->NextToken();
                return ParseLabelledStatement(pos);
            }

            return ParseExpressionStatement(flags);
        }
        // These cases never can occur here!
        case lexer::TokenType::KEYW_EXPORT:
            [[fallthrough]];
        case lexer::TokenType::KEYW_IMPORT:
            [[fallthrough]];
        case lexer::TokenType::KEYW_RETURN: {
            ThrowUnexpectedToken(token_type);
        }
        // Note: let's leave the default processing case separately, because it can be changed in the future.
        default: {
            ThrowUnexpectedToken(token_type);
            // return ParseExpressionStatement(flags);
        }
    }
}

void ETSParser::AddGlobalDeclaration(ir::AstNode *node)
{
    switch (node->Type()) {
        case ir::AstNodeType::CLASS_DECLARATION: {
            auto *ident = node->AsClassDeclaration()->Definition()->Ident();
            Binder()->TopScope()->InsertBinding(ident->Name(), ident->Variable());
            if ((GetContext().Status() & ParserStatus::IN_EXTERNAL) != 0) {  // IN_EXTERNAL
                ident->Variable()->AddFlag(binder::VariableFlags::BUILTIN_TYPE);
            }
            break;
        }
        case ir::AstNodeType::STRUCT_DECLARATION: {
            auto *ident = node->AsETSStructDeclaration()->Definition()->Ident();
            Binder()->TopScope()->InsertBinding(ident->Name(), ident->Variable());
            if ((GetContext().Status() & ParserStatus::IN_EXTERNAL) != 0) {  // IN_EXTERNAL
                ident->Variable()->AddFlag(binder::VariableFlags::BUILTIN_TYPE);
            }
            break;
        }
        case ir::AstNodeType::TS_INTERFACE_DECLARATION: {
            auto *ident = node->AsTSInterfaceDeclaration()->Id();
            Binder()->TopScope()->InsertBinding(ident->Name(), ident->Variable());
            if ((GetContext().Status() & ParserStatus::IN_EXTERNAL) != 0) {
                ident->Variable()->AddFlag(binder::VariableFlags::BUILTIN_TYPE);
            }
            break;
        }
        case ir::AstNodeType::TS_ENUM_DECLARATION: {
            auto *ident = node->AsTSEnumDeclaration()->Key();
            Binder()->TopScope()->InsertBinding(ident->Name(), ident->Variable());
            break;
        }
        case ir::AstNodeType::TS_TYPE_ALIAS_DECLARATION: {
            auto *ident = node->AsTSTypeAliasDeclaration()->Id();
            Binder()->TopScope()->InsertBinding(ident->Name(), ident->Variable());
            break;
        }
        default: {
            break;
        }
    }
}

void ETSParser::ParseTopLevelDeclaration(ArenaVector<ir::Statement *> &statements)
{
    lexer::SourcePosition class_body_start_loc = Lexer()->GetToken().Start();
    auto global_properties = ParseTopLevelStatements(statements);

    auto *class_def = GetProgram()->GlobalClass();

    if (class_def->IsGlobalInitialized()) {
        class_def->AddProperties(std::move(global_properties));
        Lexer()->NextToken();
        return;
    }

    CreateCCtor(GetProgram()->GlobalClassScope()->StaticMethodScope(), global_properties, class_body_start_loc,
                GetProgram()->Kind() != ScriptKind::STDLIB);
    class_def->AddProperties(std::move(global_properties));
    auto *class_decl = class_def->Parent()->AsClassDeclaration();
    class_def->SetGlobalInitialized();
    class_def->SetRange(class_def->Range());

    statements.push_back(class_decl);
    Lexer()->NextToken();
}

// NOLINTNEXTLINE(google-default-arguments)
void ETSParser::CreateCCtor(binder::LocalScope *class_scope, ArenaVector<ir::AstNode *> &properties,
                            const lexer::SourcePosition &loc, const bool in_global_class)
{
    bool has_static_field = false;
    for (const auto *prop : properties) {
        if (prop->IsClassStaticBlock()) {
            return;
        }

        if (!prop->IsClassProperty()) {
            continue;
        }

        const auto *field = prop->AsClassProperty();

        if (field->IsStatic()) {
            has_static_field = true;
        }
    }

    if (!has_static_field && !in_global_class) {
        return;
    }

    auto class_ctx = binder::LexicalScope<binder::LocalScope>::Enter(Binder(), class_scope);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());

    auto *param_scope = Binder()->Allocator()->New<binder::FunctionParamScope>(Allocator(), Binder()->GetScope());
    auto *scope = Binder()->Allocator()->New<binder::FunctionScope>(Allocator(), param_scope);

    auto *id = AllocNode<ir::Identifier>(compiler::Signatures::CCTOR, Allocator());

    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());

    // Add the call to special '_$init$_' method containing all the top-level variable initializations (as assignments)
    // and statements to the end of static constructor of the global class.
    if (in_global_class) {
        if (auto const it = std::find_if(properties.begin(), properties.end(),
                                         [](ir::AstNode const *const item) {
                                             return item->IsMethodDefinition() &&
                                                    item->AsMethodDefinition()->Id()->Name() ==
                                                        compiler::Signatures::INIT_METHOD;
                                         });
            it != properties.end()) {
            if (!(*it)->AsMethodDefinition()->Function()->Body()->AsBlockStatement()->Statements().empty()) {
                auto *const callee = AllocNode<ir::Identifier>(compiler::Signatures::INIT_METHOD, Allocator());
                callee->SetReference();

                auto *const call_expr = AllocNode<ir::CallExpression>(
                    callee, ArenaVector<ir::Expression *>(Allocator()->Adapter()), nullptr, false, false);

                statements.emplace_back(AllocNode<ir::ExpressionStatement>(call_expr));
            }
        }
    }

    auto *body = AllocNode<ir::BlockStatement>(Allocator(), scope, std::move(statements));
    auto *func = AllocNode<ir::ScriptFunction>(scope, std::move(params), nullptr, body, nullptr,
                                               ir::ScriptFunctionFlags::STATIC_BLOCK | ir::ScriptFunctionFlags::HIDDEN,
                                               ir::ModifierFlags::STATIC, false, GetContext().GetLanguge());
    scope->BindNode(func);
    func->SetIdent(id);
    param_scope->BindNode(func);
    scope->BindParamScope(param_scope);
    param_scope->BindFunctionScope(scope);

    auto *func_expr = AllocNode<ir::FunctionExpression>(func);
    auto *static_block = AllocNode<ir::ClassStaticBlock>(func_expr, Allocator());
    static_block->AddModifier(ir::ModifierFlags::STATIC);
    static_block->SetRange({loc, loc});
    auto [_, var] = Binder()->NewVarDecl<binder::FunctionDecl>(loc, Allocator(), id->Name(), static_block);
    (void)_;
    var->AddFlag(binder::VariableFlags::METHOD);
    id->SetVariable(var);
    properties.push_back(static_block);
}

static bool IsClassModifier(lexer::TokenType type)
{
    return type == lexer::TokenType::KEYW_STATIC || type == lexer::TokenType::KEYW_ABSTRACT ||
           type == lexer::TokenType::KEYW_FINAL;
}

ir::ModifierFlags ETSParser::ParseClassModifiers()
{
    ir::ModifierFlags flags = ir::ModifierFlags::NONE;

    while (IsClassModifier(Lexer()->GetToken().KeywordType())) {
        ir::ModifierFlags current_flag = ir::ModifierFlags::NONE;

        lexer::TokenFlags token_flags = Lexer()->GetToken().Flags();
        if ((token_flags & lexer::TokenFlags::HAS_ESCAPE) != 0) {
            ThrowSyntaxError("Keyword must not contain escaped characters");
        }

        switch (Lexer()->GetToken().KeywordType()) {
            case lexer::TokenType::KEYW_STATIC: {
                current_flag = ir::ModifierFlags::STATIC;
                break;
            }
            case lexer::TokenType::KEYW_FINAL: {
                current_flag = ir::ModifierFlags::FINAL;
                break;
            }
            case lexer::TokenType::KEYW_ABSTRACT: {
                current_flag = ir::ModifierFlags::ABSTRACT;
                break;
            }
            default: {
                UNREACHABLE();
            }
        }

        if ((flags & current_flag) != 0) {
            ThrowSyntaxError("Duplicated modifier is not allowed");
        }

        Lexer()->NextToken();
        flags |= current_flag;
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
        char32_t next_cp = Lexer()->Lookahead();
        if (!(next_cp != lexer::LEX_CHAR_EQUALS && next_cp != lexer::LEX_CHAR_COLON &&
              next_cp != lexer::LEX_CHAR_LEFT_PAREN)) {
            return {ir::ModifierFlags::NONE, false};
        }

        lexer::TokenFlags token_flags = Lexer()->GetToken().Flags();
        if ((token_flags & lexer::TokenFlags::HAS_ESCAPE) != 0) {
            ThrowSyntaxError("Keyword must not contain escaped characters");
        }

        ir::ModifierFlags access_flag = ir::ModifierFlags::NONE;

        switch (Lexer()->GetToken().KeywordType()) {
            case lexer::TokenType::KEYW_PUBLIC: {
                access_flag = ir::ModifierFlags::PUBLIC;
                break;
            }
            case lexer::TokenType::KEYW_PRIVATE: {
                access_flag = ir::ModifierFlags::PRIVATE;
                break;
            }
            case lexer::TokenType::KEYW_PROTECTED: {
                access_flag = ir::ModifierFlags::PROTECTED;
                break;
            }
            case lexer::TokenType::KEYW_INTERNAL: {
                Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
                if (Lexer()->GetToken().KeywordType() != lexer::TokenType::KEYW_PROTECTED) {
                    access_flag = ir::ModifierFlags::INTERNAL;
                    return {access_flag, true};
                }
                access_flag = ir::ModifierFlags::INTERNAL_PROTECTED;
                break;
            }
            default: {
                UNREACHABLE();
            }
        }

        Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
        return {access_flag, true};
    }

    return {ir::ModifierFlags::PUBLIC, false};
}

static bool IsClassFieldModifier(lexer::TokenType type)
{
    return type == lexer::TokenType::KEYW_STATIC || type == lexer::TokenType::KEYW_READONLY;
}

ir::ModifierFlags ETSParser::ParseClassFieldModifiers(bool seen_static)
{
    ir::ModifierFlags flags = seen_static ? ir::ModifierFlags::STATIC : ir::ModifierFlags::NONE;

    while (IsClassFieldModifier(Lexer()->GetToken().KeywordType())) {
        char32_t next_cp = Lexer()->Lookahead();
        if (!(next_cp != lexer::LEX_CHAR_EQUALS && next_cp != lexer::LEX_CHAR_COLON)) {
            return flags;
        }

        ir::ModifierFlags current_flag = ir::ModifierFlags::NONE;

        lexer::TokenFlags token_flags = Lexer()->GetToken().Flags();
        if ((token_flags & lexer::TokenFlags::HAS_ESCAPE) != 0) {
            ThrowSyntaxError("Keyword must not contain escaped characters");
        }

        switch (Lexer()->GetToken().KeywordType()) {
            case lexer::TokenType::KEYW_STATIC: {
                current_flag = ir::ModifierFlags::STATIC;
                break;
            }
            case lexer::TokenType::KEYW_READONLY: {
                // TODO(OCs): Use ir::ModifierFlags::READONLY once compiler is ready for it.
                current_flag = ir::ModifierFlags::CONST;
                break;
            }
            default: {
                UNREACHABLE();
            }
        }

        if ((flags & current_flag) != 0) {
            ThrowSyntaxError("Duplicated modifier is not allowed");
        }

        Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
        flags |= current_flag;
    }

    return flags;
}

static bool IsClassMethodModifier(lexer::TokenType type)
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

ir::ModifierFlags ETSParser::ParseClassMethodModifiers(bool seen_static)
{
    ir::ModifierFlags flags = seen_static ? ir::ModifierFlags::STATIC : ir::ModifierFlags::NONE;

    while (IsClassMethodModifier(Lexer()->GetToken().KeywordType())) {
        char32_t next_cp = Lexer()->Lookahead();
        if (!(next_cp != lexer::LEX_CHAR_LEFT_PAREN)) {
            return flags;
        }

        ir::ModifierFlags current_flag = ir::ModifierFlags::NONE;

        lexer::TokenFlags token_flags = Lexer()->GetToken().Flags();
        if ((token_flags & lexer::TokenFlags::HAS_ESCAPE) != 0) {
            ThrowSyntaxError("Keyword must not contain escaped characters");
        }

        switch (Lexer()->GetToken().KeywordType()) {
            case lexer::TokenType::KEYW_STATIC: {
                current_flag = ir::ModifierFlags::STATIC;
                break;
            }
            case lexer::TokenType::KEYW_FINAL: {
                current_flag = ir::ModifierFlags::FINAL;
                break;
            }
            case lexer::TokenType::KEYW_NATIVE: {
                current_flag = ir::ModifierFlags::NATIVE;
                break;
            }
            case lexer::TokenType::KEYW_ASYNC: {
                current_flag = ir::ModifierFlags::ASYNC;
                break;
            }
            case lexer::TokenType::KEYW_OVERRIDE: {
                current_flag = ir::ModifierFlags::OVERRIDE;
                break;
            }
            case lexer::TokenType::KEYW_ABSTRACT: {
                current_flag = ir::ModifierFlags::ABSTRACT;
                break;
            }
            case lexer::TokenType::KEYW_DECLARE: {
                current_flag = ir::ModifierFlags::DECLARE;
                break;
            }
            default: {
                UNREACHABLE();
            }
        }

        if ((flags & current_flag) != 0) {
            ThrowSyntaxError("Duplicated modifier is not allowed");
        }

        Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
        flags |= current_flag;
        if ((flags & ir::ModifierFlags::ASYNC) != 0 && (flags & ir::ModifierFlags::NATIVE) != 0) {
            ThrowSyntaxError("Native method cannot be async");
        }
    }

    return flags;
}

// NOLINTNEXTLINE(google-default-arguments)
void ETSParser::ParseClassFieldDefiniton(ir::Identifier *field_name, ir::ModifierFlags modifiers,
                                         ArenaVector<ir::AstNode *> *declarations, ir::ScriptFunction *init_function)
{
    ir::TypeNode *type_annotation = nullptr;
    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        type_annotation = ParseTypeAnnotation(&options);
    }

    ir::Expression *initializer = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        Lexer()->NextToken();  // eat '='
        initializer = ParseInitializer();
    } else if (type_annotation == nullptr) {
        ThrowSyntaxError("Field type annotation expected");
    }

    // Add initialization of top-level (global) variables to a special '_$init$_' function so that it could be
    // performed multiple times.
    if (init_function != nullptr && (modifiers & ir::ModifierFlags::CONST) == 0U && initializer != nullptr &&
        !initializer->IsArrowFunctionExpression()) {
        ASSERT(Binder()->GetScope()->Parent()->IsGlobalScope());
        if (auto *const func_body = init_function->Body(); func_body != nullptr && func_body->IsBlockStatement()) {
            auto *ident = AllocNode<ir::Identifier>(field_name->Name(), Allocator());
            ident->SetReference();
            ident->SetRange(field_name->Range());

            auto *assignment_expression =
                AllocNode<ir::AssignmentExpression>(ident, initializer, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
            assignment_expression->SetParent(func_body);
            func_body->AsBlockStatement()->Statements().emplace_back(
                AllocNode<ir::ExpressionStatement>(assignment_expression));

            if (type_annotation != nullptr && !type_annotation->IsETSFunctionType()) {
                initializer = nullptr;
            }
        }
    }

    bool is_declare = (modifiers & ir::ModifierFlags::DECLARE) != 0;

    if (is_declare && initializer != nullptr) {
        ThrowSyntaxError("Initializers are not allowed in ambient contexts.");
    }

    auto *field = AllocNode<ir::ClassProperty>(field_name, initializer, type_annotation, modifiers, Allocator(), false);

    if ((modifiers & ir::ModifierFlags::CONST) != 0) {
        ASSERT(Binder()->GetScope()->Parent() != nullptr);
        if (initializer == nullptr && Binder()->GetScope()->Parent()->IsGlobalScope() && !is_declare) {
            ThrowSyntaxError("Missing initializer in const declaration");
        }
        Binder()->AddDecl<binder::ConstDecl>(field_name->Start(), field_name->Name(), field);
    } else {
        Binder()->AddDecl<binder::LetDecl>(field_name->Start(), field_name->Name(), field);
    }

    declarations->push_back(field);

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
        Lexer()->NextToken();
        ir::Identifier *next_name = ExpectIdentifier();
        ParseClassFieldDefiniton(next_name, modifiers, declarations);
    }
}

ir::MethodDefinition *ETSParser::ParseClassMethodDefinition(ir::Identifier *method_name, ir::ModifierFlags modifiers)
{
    auto *cur_scope = Binder()->GetScope();
    auto res = cur_scope->Find(method_name->Name(), binder::ResolveBindingOptions::ALL);
    if (res.variable != nullptr && !res.variable->Declaration()->IsFunctionDecl() && res.scope == cur_scope) {
        Binder()->ThrowRedeclaration(method_name->Start(), res.name);
    }

    auto new_status = ParserStatus::NEED_RETURN_TYPE | ParserStatus::ALLOW_SUPER;
    auto method_kind = ir::MethodDefinitionKind::METHOD;
    auto script_function_flag = ir::ScriptFunctionFlags::METHOD;

    if ((modifiers & ir::ModifierFlags::CONSTRUCTOR) != 0) {
        new_status = ParserStatus::CONSTRUCTOR_FUNCTION | ParserStatus::ALLOW_SUPER | ParserStatus::ALLOW_SUPER_CALL;
        method_kind = ir::MethodDefinitionKind::CONSTRUCTOR;
        script_function_flag |= ir::ScriptFunctionFlags::CONSTRUCTOR;
    }

    if ((modifiers & ir::ModifierFlags::ASYNC) != 0) {
        new_status |= ParserStatus::ASYNC_FUNCTION;
    }

    ir::ScriptFunction *func = ParseFunction(new_status);
    func->SetIdent(method_name);
    auto *func_expr = AllocNode<ir::FunctionExpression>(func);
    func_expr->SetRange(func->Range());
    func->AddModifier(modifiers);
    auto *method = AllocNode<ir::MethodDefinition>(method_kind, method_name, func_expr, modifiers, Allocator(), false);
    method->SetRange(func_expr->Range());

    CreateClassFunctionDeclaration(method);
    AddProxyOverloadToMethodWithDefaultParams(method);

    return method;
}

ir::ScriptFunction *ETSParser::ParseFunction(ParserStatus new_status)
{
    FunctionContext function_context(this, new_status | ParserStatus::FUNCTION);
    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();
    auto [typeParamDecl, params, returnTypeAnnotation, funcParamScope, throw_marker] =
        ParseFunctionSignature(new_status);

    auto param_ctx = binder::LexicalScope<binder::FunctionParamScope>::Enter(Binder(), funcParamScope, false);
    auto function_ctx = binder::LexicalScope<binder::FunctionScope>(Binder());
    auto *function_scope = function_ctx.GetScope();
    function_scope->BindParamScope(funcParamScope);
    funcParamScope->BindFunctionScope(function_scope);
    ir::AstNode *body = nullptr;
    lexer::SourcePosition end_loc = start_loc;
    bool is_overload = false;
    bool is_arrow = (new_status & ParserStatus::ARROW_FUNCTION) != 0;

    if ((new_status & ParserStatus::ASYNC_FUNCTION) != 0) {
        function_context.AddFlag(ir::ScriptFunctionFlags::ASYNC);
    }

    if (is_arrow) {
        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_ARROW) {
            ThrowSyntaxError("'=>' expected");
        }

        function_context.AddFlag(ir::ScriptFunctionFlags::ARROW);
        Lexer()->NextToken();
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        std::tie(std::ignore, body, end_loc, is_overload) =
            ParseFunctionBody(params, new_status, GetContext().Status(), function_scope);
    } else if (is_arrow) {
        body = ParseExpression();
        end_loc = body->AsExpression()->End();
        function_context.AddFlag(ir::ScriptFunctionFlags::EXPRESSION);
    }

    function_context.AddFlag(throw_marker);

    auto *func_node =
        AllocNode<ir::ScriptFunction>(function_scope, std::move(params), typeParamDecl, body, returnTypeAnnotation,
                                      function_context.Flags(), false, GetContext().GetLanguge());
    function_scope->BindNode(func_node);
    funcParamScope->BindNode(func_node);
    func_node->SetRange({start_loc, end_loc});

    return func_node;
}

ir::MethodDefinition *ETSParser::ParseClassMethod(ClassElementDescriptor *desc,
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

std::tuple<bool, ir::BlockStatement *, lexer::SourcePosition, bool> ETSParser::ParseFunctionBody(
    [[maybe_unused]] const ArenaVector<ir::Expression *> &params, [[maybe_unused]] ParserStatus new_status,
    [[maybe_unused]] ParserStatus context_status, binder::FunctionScope *func_scope)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE);

    ir::BlockStatement *body = ParseBlockStatement(func_scope);

    return {true, body, body->End(), false};
}

ir::TypeNode *ETSParser::ParseFunctionReturnType([[maybe_unused]] ParserStatus status)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        if ((status & ParserStatus::CONSTRUCTOR_FUNCTION) != 0U) {
            ThrowSyntaxError("Type annotation isn't allowed for constructor.");
        }
        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options =
            TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::CAN_BE_TS_TYPE_PREDICATE;
        return ParseTypeAnnotation(&options);
    }

    return nullptr;
}

ir::ScriptFunctionFlags ETSParser::ParseFunctionThrowMarker(bool is_rethrows_allowed)
{
    ir::ScriptFunctionFlags throw_marker = ir::ScriptFunctionFlags::NONE;

    if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
        if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_THROWS) {
            Lexer()->NextToken();  // eat 'throws'
            throw_marker = ir::ScriptFunctionFlags::THROWS;
        } else if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_RETHROWS) {
            if (is_rethrows_allowed) {
                Lexer()->NextToken();  // eat 'rethrows'
                throw_marker = ir::ScriptFunctionFlags::RETHROWS;
            } else {
                ThrowSyntaxError("Only 'throws' can be used with function types");
            }
        }
    }

    return throw_marker;
}

void ETSParser::ValidateLabeledStatement(lexer::TokenType type)
{
    if (type != lexer::TokenType::KEYW_DO && type != lexer::TokenType::KEYW_WHILE &&
        type != lexer::TokenType::KEYW_FOR && type != lexer::TokenType::KEYW_SWITCH) {
        ThrowSyntaxError("Label must be followed by a loop statement", Lexer()->GetToken().Start());
    }
}

// NOLINTNEXTLINE(google-default-arguments)
ir::AstNode *ETSParser::ParseClassElement([[maybe_unused]] const ArenaVector<ir::AstNode *> &properties,
                                          [[maybe_unused]] ir::ClassDefinitionModifiers modifiers,
                                          [[maybe_unused]] ir::ModifierFlags flags)
{
    auto start_loc = Lexer()->GetToken().Start();
    auto saved_pos = Lexer()->Save();  // NOLINT(clang-analyzer-deadcode.DeadStores)

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_STATIC &&
        Lexer()->Lookahead() == lexer::LEX_CHAR_LEFT_BRACE) {
        return ParseClassStaticBlock();
    }

    auto [memberModifiers, stepToken] = ParseClassMemberAccessModifiers();

    if (InAmbientContext()) {
        memberModifiers |= ir::ModifierFlags::DECLARE;
    }

    bool seen_static = false;
    char32_t next_cp = Lexer()->Lookahead();

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_STATIC && next_cp != lexer::LEX_CHAR_EQUALS &&
        next_cp != lexer::LEX_CHAR_COLON && next_cp != lexer::LEX_CHAR_LEFT_PAREN &&
        next_cp != lexer::LEX_CHAR_LESS_THAN) {
        Lexer()->NextToken();
        memberModifiers |= ir::ModifierFlags::STATIC;
        seen_static = true;
    }

    if (IsClassFieldModifier(Lexer()->GetToken().KeywordType())) {
        memberModifiers |= ParseClassFieldModifiers(seen_static);
    } else if (IsClassMethodModifier(Lexer()->GetToken().Type())) {
        memberModifiers |= ParseClassMethodModifiers(seen_static);
    }

    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::KEYW_INTERFACE:
        case lexer::TokenType::KEYW_CLASS:
        case lexer::TokenType::KEYW_ENUM: {
            ThrowSyntaxError(
                "Local type declaration (class, struct, interface and enum) support is not yet implemented.");
            // remove saved_pos nolint

            Lexer()->Rewind(saved_pos);
            if (stepToken) {
                Lexer()->NextToken();
            }

            Lexer()->GetToken().SetTokenType(Lexer()->GetToken().KeywordType());
            ir::AstNode *type_decl = ParseTypeDeclaration(true);
            memberModifiers &= (ir::ModifierFlags::PUBLIC | ir::ModifierFlags::PROTECTED | ir::ModifierFlags::PRIVATE |
                                ir::ModifierFlags::INTERNAL);
            type_decl->AddModifier(memberModifiers);

            if (!seen_static) {
                if (type_decl->IsClassDeclaration()) {
                    type_decl->AsClassDeclaration()->Definition()->AsClassDefinition()->SetInnerModifier();
                } else if (type_decl->IsETSStructDeclaration()) {
                    type_decl->AsETSStructDeclaration()->Definition()->AsClassDefinition()->SetInnerModifier();
                }
            }

            return type_decl;
        }
        case lexer::TokenType::KEYW_CONSTRUCTOR: {
            if ((memberModifiers & ir::ModifierFlags::ASYNC) != 0) {
                ThrowSyntaxError({"Constructor should not be async."});
            }
            auto *member_name = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
            memberModifiers |= ir::ModifierFlags::CONSTRUCTOR;
            Lexer()->NextToken();
            auto *class_method = ParseClassMethodDefinition(member_name, memberModifiers);
            class_method->SetStart(start_loc);

            return class_method;
        }
        default: {
            break;
        }
    }

    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::KEYW_PUBLIC:
        case lexer::TokenType::KEYW_PRIVATE:
        case lexer::TokenType::KEYW_PROTECTED: {
            ThrowSyntaxError("Access modifier must precede field and method modifiers.");
            break;
        }
        default:
            break;
    }

    if (Lexer()->Lookahead() != lexer::LEX_CHAR_LEFT_PAREN && Lexer()->Lookahead() != lexer::LEX_CHAR_LESS_THAN &&
        (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_GET ||
         Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_SET)) {
        return ParseClassGetterSetterMethod(properties, modifiers, memberModifiers);
    }

    auto *member_name = ExpectIdentifier();

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS ||
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        auto *class_method = ParseClassMethodDefinition(member_name, memberModifiers);
        class_method->SetStart(start_loc);
        return class_method;
    }

    ArenaVector<ir::AstNode *> field_declarations(Allocator()->Adapter());
    auto *placeholder = AllocNode<ir::TSInterfaceBody>(std::move(field_declarations));
    ParseClassFieldDefiniton(member_name, memberModifiers, placeholder->BodyPtr());
    return placeholder;
}

ir::MethodDefinition *ETSParser::ParseClassGetterSetterMethod(const ArenaVector<ir::AstNode *> &properties,
                                                              const ir::ClassDefinitionModifiers modifiers,
                                                              const ir::ModifierFlags member_modifiers)
{
    ClassElementDescriptor desc(Allocator());
    desc.method_kind = Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_GET ? ir::MethodDefinitionKind::GET
                                                                                       : ir::MethodDefinitionKind::SET;
    Lexer()->NextToken();  // eat get/set
    auto *method_name = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    if (desc.method_kind == ir::MethodDefinitionKind::GET) {
        method_name->SetAccessor();
    } else {
        method_name->SetMutator();
    }

    Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);

    desc.new_status = ParserStatus::ALLOW_SUPER;
    desc.has_super_class = (modifiers & ir::ClassDefinitionModifiers::HAS_SUPER) != 0U;
    desc.prop_start = Lexer()->GetToken().Start();
    desc.modifiers = member_modifiers;

    lexer::SourcePosition prop_end = method_name->End();
    ir::MethodDefinition *method = ParseClassMethod(&desc, properties, method_name, &prop_end);
    method->Function()->SetIdent(method_name);
    method->Function()->AddModifier(desc.modifiers);
    method->SetRange({desc.prop_start, prop_end});
    if (desc.method_kind == ir::MethodDefinitionKind::GET) {
        method->Function()->AddFlag(ir::ScriptFunctionFlags::GETTER);
    } else {
        method->Function()->AddFlag(ir::ScriptFunctionFlags::SETTER);
    }

    CreateClassFunctionDeclaration(method);

    return method;
}

ir::Statement *ETSParser::ParseTypeDeclaration(bool allow_static)
{
    auto saved_pos = Lexer()->Save();

    auto modifiers = ir::ClassDefinitionModifiers::ID_REQUIRED | ir::ClassDefinitionModifiers::CLASS_DECL;

    auto token_type = Lexer()->GetToken().Type();
    switch (token_type) {
        case lexer::TokenType::KEYW_STATIC: {
            if (!allow_static) {
                ThrowUnexpectedToken(Lexer()->GetToken().Type());
            }

            Lexer()->NextToken();

            if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_INTERFACE) {
                return ParseInterfaceDeclaration(true);
            }

            Lexer()->Rewind(saved_pos);
            [[fallthrough]];
        }
        case lexer::TokenType::KEYW_ABSTRACT:
        case lexer::TokenType::KEYW_FINAL: {
            auto flags = ParseClassModifiers();
            if (allow_static && (flags & ir::ModifierFlags::STATIC) == 0U) {
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
        case lexer::TokenType::KEYW_ENUM: {
            return ParseEnumDeclaration(false);
        }
        case lexer::TokenType::KEYW_INTERFACE: {
            return ParseInterfaceDeclaration(false);
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
        case lexer::TokenType::LITERAL_STRING:
        case lexer::TokenType::LITERAL_FALSE:
        case lexer::TokenType::LITERAL_TRUE:
        case lexer::TokenType::LITERAL_CHAR: {
            std::string err_msg("Cannot used in global scope '");

            std::string text = token_type == lexer::TokenType::LITERAL_CHAR
                                   ? util::Helpers::UTF16toUTF8(Lexer()->GetToken().Utf16())
                                   : Lexer()->GetToken().Ident().Mutf8();

            if ((Lexer()->GetToken().Flags() & lexer::TokenFlags::HAS_ESCAPE) == 0) {
                err_msg.append(text);
            } else {
                err_msg.append(util::Helpers::CreateEscapedString(text));
            }

            err_msg.append("'");
            ThrowSyntaxError(err_msg.c_str());
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

    lexer::SourcePosition type_start = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat type keyword

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Identifier expected");
    }

    if (Lexer()->GetToken().IsReservedTypeName()) {
        std::string err_msg("Type alias name cannot be '");
        err_msg.append(TokenToString(Lexer()->GetToken().KeywordType()));
        err_msg.append("'");
        ThrowSyntaxError(err_msg.c_str());
    }

    const util::StringView ident = Lexer()->GetToken().Ident();
    auto *id = AllocNode<ir::Identifier>(ident, Allocator());
    id->SetRange(Lexer()->GetToken().Loc());

    auto *type_alias_decl = AllocNode<ir::TSTypeAliasDeclaration>(Allocator(), id);
    Binder()->AddDecl<binder::TypeAliasDecl>(Lexer()->GetToken().Start(), ident, type_alias_decl);

    Lexer()->NextToken();  // eat alias name

    auto type_params_ctx = binder::LexicalScope<binder::LocalScope>(Binder());
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        auto options =
            TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::ALLOW_DECLARATION_SITE_VARIANCE;
        ir::TSTypeParameterDeclaration *params = ParseTypeParameterDeclaration(&options);
        type_alias_decl->AddTypeParameters(params);
        params->SetParent(type_alias_decl);
    }

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        ThrowSyntaxError("'=' expected");
    }

    Lexer()->NextToken();  // eat '='

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
    ir::TypeNode *type_annotation = ParseTypeAnnotation(&options);
    type_alias_decl->SetTsTypeAnnotation(type_annotation);
    type_alias_decl->SetRange({type_start, Lexer()->GetToken().End()});
    type_annotation->SetParent(type_alias_decl);

    return type_alias_decl;
}

ir::TSInterfaceDeclaration *ETSParser::ParseInterfaceBody(ir::Identifier *name, bool is_static)
{
    GetContext().Status() |= ParserStatus::ALLOW_THIS_TYPE;

    auto type_params_ctx = binder::LexicalScope<binder::LocalScope>(Binder());
    ir::TSTypeParameterDeclaration *type_param_decl = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        auto options =
            TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::ALLOW_DECLARATION_SITE_VARIANCE;
        type_param_decl = ParseTypeParameterDeclaration(&options);
    }

    ArenaVector<ir::TSInterfaceHeritage *> extends(Allocator()->Adapter());
    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_EXTENDS) {
        extends = ParseInterfaceExtendsClause();
    }

    auto local_scope = binder::LexicalScope<binder::ClassScope>(Binder());
    lexer::SourcePosition body_start = Lexer()->GetToken().Start();
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
    body->SetRange({body_start, Lexer()->GetToken().End()});

    auto *interface_decl =
        AllocNode<ir::TSInterfaceDeclaration>(Allocator(), local_scope.GetScope(), name, type_param_decl, body,
                                              std::move(extends), is_static, GetContext().GetLanguge());

    Lexer()->NextToken();
    GetContext().Status() &= ~ParserStatus::ALLOW_THIS_TYPE;

    return interface_decl;
}

ir::Statement *ETSParser::ParseInterfaceDeclaration(bool is_static)
{
    if ((GetContext().Status() & parser::ParserStatus::FUNCTION) != 0U) {
        ThrowSyntaxError("Local interface declaration support is not yet implemented.");
    }

    lexer::SourcePosition interface_start = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat interface keyword

    auto *id = ExpectIdentifier();
    util::StringView ident = FormInterfaceOrEnumDeclarationIdBinding(id);

    auto *decl_node = ParseInterfaceBody(id, is_static);

    auto *decl = Binder()->AddDecl<binder::InterfaceDecl>(Lexer()->GetToken().Start(), Allocator(), ident, decl_node);
    decl->AsInterfaceDecl()->Add(decl_node);
    decl_node->SetRange({interface_start, Lexer()->GetToken().End()});
    return decl_node;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Statement *ETSParser::ParseEnumDeclaration(bool is_const, bool is_static)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::KEYW_ENUM);

    if ((GetContext().Status() & parser::ParserStatus::FUNCTION) != 0U) {
        ThrowSyntaxError("Local enum declaration support is not yet implemented.");
    }

    lexer::SourcePosition enum_start = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat enum keyword

    auto *key = ExpectIdentifier();
    util::StringView ident = FormInterfaceOrEnumDeclarationIdBinding(key);

    auto *decl_node = ParseEnumMembers(key, enum_start, is_const, is_static);
    auto *decl = Binder()->AddDecl<binder::EnumLiteralDecl>(Lexer()->GetToken().Start(), ident, decl_node, is_const);
    decl->BindScope(decl_node->Scope());

    return decl_node;
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
    auto *launch_expression = AllocNode<ir::ETSLaunchExpression>(call);
    launch_expression->SetRange({start, call->End()});

    return launch_expression;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::ClassDefinition *ETSParser::ParseClassDefinition(ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags flags)
{
    Lexer()->NextToken();

    ir::Identifier *ident_node = ParseClassIdent(modifiers);

    auto type_params_ctx = binder::LexicalScope<binder::LocalScope>(Binder());
    ir::TSTypeParameterDeclaration *type_param_decl = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        auto options =
            TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::ALLOW_DECLARATION_SITE_VARIANCE;
        type_param_decl = ParseTypeParameterDeclaration(&options);
    }

    auto class_ctx = binder::LexicalScope<binder::ClassScope>(Binder());

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
    CreateCCtor(class_ctx.GetScope()->StaticMethodScope(), properties, bodyRange.start);

    auto *class_scope = class_ctx.GetScope();
    auto *class_definition = AllocNode<ir::ClassDefinition>(
        class_scope, util::StringView(), ident_node, type_param_decl, superTypeParams, std::move(implements), ctor,
        superClass, std::move(properties), modifiers, flags, GetContext().GetLanguge());

    class_definition->SetRange(bodyRange);
    class_scope->BindNode(class_definition);

    GetContext().Status() &= ~ParserStatus::ALLOW_SUPER;

    return class_definition;
}

static bool IsInterfaceMethodModifier(lexer::TokenType type)
{
    return type == lexer::TokenType::KEYW_STATIC || type == lexer::TokenType::KEYW_PRIVATE;
}

ir::ModifierFlags ETSParser::ParseInterfaceMethodModifiers()
{
    ir::ModifierFlags flags = ir::ModifierFlags::NONE;

    while (IsInterfaceMethodModifier(Lexer()->GetToken().Type())) {
        ir::ModifierFlags current_flag = ir::ModifierFlags::NONE;

        switch (Lexer()->GetToken().Type()) {
            case lexer::TokenType::KEYW_STATIC: {
                current_flag = ir::ModifierFlags::STATIC;
                break;
            }
            case lexer::TokenType::KEYW_PRIVATE: {
                current_flag = ir::ModifierFlags::PRIVATE;
                break;
            }
            default: {
                UNREACHABLE();
            }
        }

        char32_t next_cp = Lexer()->Lookahead();
        if (next_cp == lexer::LEX_CHAR_COLON || next_cp == lexer::LEX_CHAR_LEFT_PAREN ||
            next_cp == lexer::LEX_CHAR_EQUALS) {
            break;
        }

        if ((flags & current_flag) != 0) {
            ThrowSyntaxError("Duplicated modifier is not allowed");
        }

        Lexer()->NextToken();
        flags |= current_flag;
    }

    return flags;
}

ir::ClassProperty *ETSParser::ParseInterfaceField(const lexer::SourcePosition &start_loc)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT);
    auto *name = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    name->SetRange(Lexer()->GetToken().Loc());
    Lexer()->NextToken();

    ir::TypeNode *type_annotation = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        type_annotation = ParseTypeAnnotation(&options);
    }

    bool is_declare = InAmbientContext();

    ir::Expression *initializer = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        Lexer()->NextToken();  // eat '='
        initializer = ParseInitializer();
    } else if (!is_declare) {
        ThrowExpectedToken(lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    }

    if (is_declare && initializer != nullptr) {
        ThrowSyntaxError("Initializers are not allowed in ambient contexts.");
    }

    ir::ModifierFlags field_modifiers = ir::ModifierFlags::PUBLIC | ir::ModifierFlags::STATIC;

    if (is_declare) {
        field_modifiers |= ir::ModifierFlags::DECLARE;
    }

    auto *field = AllocNode<ir::ClassProperty>(name, initializer, type_annotation, field_modifiers, Allocator(), false);
    field->SetEnd(Lexer()->GetToken().End());

    auto *decl = Binder()->AddDecl<binder::ConstDecl>(start_loc, field->Id()->Name(), field);
    decl->BindNode(field);

    return field;
}

ir::MethodDefinition *ETSParser::ParseInterfaceMethod(ir::ModifierFlags flags)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT);
    auto *name = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    name->SetRange(Lexer()->GetToken().Loc());
    Lexer()->NextToken();

    FunctionContext function_context(this, ParserStatus::FUNCTION);

    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();

    auto [typeParamDecl, params, returnTypeAnnotation, funcParamScope, throw_marker] =
        ParseFunctionSignature(ParserStatus::NEED_RETURN_TYPE);

    auto param_ctx = binder::LexicalScope<binder::FunctionParamScope>::Enter(Binder(), funcParamScope, false);
    auto function_ctx = binder::LexicalScope<binder::FunctionScope>(Binder());
    auto *function_scope = function_ctx.GetScope();
    function_scope->BindParamScope(funcParamScope);
    funcParamScope->BindFunctionScope(function_scope);

    ir::BlockStatement *body = nullptr;

    bool is_declare = InAmbientContext();
    if (is_declare) {
        flags |= ir::ModifierFlags::DECLARE;
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        body = ParseBlockStatement(function_scope);
    } else if ((flags & (ir::ModifierFlags::PRIVATE | ir::ModifierFlags::STATIC)) != 0 && !is_declare) {
        ThrowSyntaxError("Private or static interface methods must have body", start_loc);
    } else if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
        Lexer()->NextToken();
    } else {
        ThrowUnexpectedToken(Lexer()->GetToken().Type());
    }

    function_context.AddFlag(throw_marker);

    auto *func =
        AllocNode<ir::ScriptFunction>(function_scope, std::move(params), typeParamDecl, body, returnTypeAnnotation,
                                      function_context.Flags(), flags, true, GetContext().GetLanguge());

    if ((flags & ir::ModifierFlags::STATIC) == 0 && body == nullptr) {
        func->AddModifier(ir::ModifierFlags::ABSTRACT);
    }

    function_scope->BindNode(func);
    funcParamScope->BindNode(func);
    func->SetRange({start_loc, body != nullptr ? body->End() : returnTypeAnnotation->End()});

    auto *func_expr = AllocNode<ir::FunctionExpression>(func);
    func_expr->SetRange(func->Range());
    func->AddFlag(ir::ScriptFunctionFlags::METHOD);

    func->SetIdent(name);
    auto *method =
        AllocNode<ir::MethodDefinition>(ir::MethodDefinitionKind::METHOD, name, func_expr, flags, Allocator(), false);
    method->SetRange(func_expr->Range());
    return method;
}

void ETSParser::CreateClassFunctionDeclaration(ir::MethodDefinition *method)
{
    ASSERT(Binder()->GetScope()->IsClassScope());
    auto *const cls_scope = Binder()->GetScope()->AsClassScope();
    auto *const method_name = method->Id();

    if (cls_scope->FindLocal(method_name->Name(), binder::ResolveBindingOptions::VARIABLES |
                                                      binder::ResolveBindingOptions::DECLARATION) != nullptr) {
        Binder()->ThrowRedeclaration(method_name->Start(), method_name->Name());
    }

    binder::LocalScope *target_scope {};
    if (method->IsStatic() || method->IsConstructor()) {
        target_scope = cls_scope->StaticMethodScope();
    } else {
        target_scope = cls_scope->InstanceMethodScope();
    }

    auto *found = target_scope->FindLocal(method_name->Name());

    if (found == nullptr) {
        auto class_ctx = binder::LexicalScope<binder::LocalScope>::Enter(Binder(), target_scope);
        auto [_, var] =
            Binder()->NewVarDecl<binder::FunctionDecl>(method_name->Start(), Allocator(), method_name->Name(), method);
        (void)_;
        var->SetScope(cls_scope);
        var->AddFlag(binder::VariableFlags::METHOD);
        method_name->SetVariable(var);
        return;
    }

    if (method_name->Name().Is(compiler::Signatures::MAIN) && cls_scope->Parent()->IsGlobalScope()) {
        ThrowSyntaxError("Main overload is not enabled", method_name->Start());
    }

    auto *current_node = found->Declaration()->Node();

    if (current_node->AsMethodDefinition()->Function()->IsDefaultParamProxy()) {
        return;
    }

    current_node->AsMethodDefinition()->AddOverload(method);
    method_name->SetVariable(found);
    method->SetParent(current_node);
    method->Function()->AddFlag(ir::ScriptFunctionFlags::OVERLOAD);
}

void ETSParser::AddProxyOverloadToMethodWithDefaultParams(ir::MethodDefinition *method)
{
    if (method->IsConstructor()) {
        return;  // TODO(szd): Fix constructors not working with default params
    }

    const auto *const function = method->Function();

    bool has_default_parameter = false;
    bool has_rest_parameter = false;

    for (auto *const it : function->Params()) {
        auto const *const param = it->AsETSParameterExpression();
        if (param->IsRestParameter()) {
            has_rest_parameter = true;
            continue;
        }

        if (has_rest_parameter) {
            ThrowSyntaxError("Rest parameter should be the last one.", param->Start());
        }

        if (param->IsDefault()) {
            has_default_parameter = true;
            continue;
        }

        if (has_default_parameter) {
            ThrowSyntaxError("Required parameter follows default parameter(s).", param->Start());
        }
    }

    if (!has_default_parameter) {
        return;
    }

    if (has_rest_parameter) {
        ThrowSyntaxError("Both optional and rest parameters are not allowed in function's parameter list.",
                         function->Start());
    }

    auto *const cls_scope = Binder()->GetScope()->AsClassScope();
    binder::LocalScope *target_scope =
        method->IsStatic() ? cls_scope->StaticMethodScope() : cls_scope->InstanceMethodScope();
    auto *const found = target_scope->FindLocal(method->Id()->Name());

    std::string proxy_method = function->Id()->Name().Mutf8() + "_proxy(";

    for (const auto *const it : function->Params()) {
        auto const *const param = it->AsETSParameterExpression();
        proxy_method += param->Ident()->Name().Mutf8() + ": " + GetNameForTypeNode(param->TypeAnnotation()) + ", ";
    }

    std::string return_type = method->Function()->ReturnTypeAnnotation() != nullptr
                                  ? GetNameForTypeNode(method->Function()->ReturnTypeAnnotation())
                                  : "void";
    proxy_method += "proxy_int:int): " + return_type + " { ";

    auto const parameters_number = function->Params().size();
    for (size_t i = 0U; i < parameters_number; i++) {
        if (auto const *const param = function->Params()[i]->AsETSParameterExpression(); param->IsDefault()) {
            std::string proxy_if = "if (((proxy_int >> " + std::to_string(i) + ") & 0x1) == 1) { " +
                                   param->Ident()->Name().Mutf8() + " = " + param->LexerSaved().Mutf8() + " }";
            proxy_method += proxy_if;
        }
    }

    proxy_method += (return_type == "void") ? "" : cls_scope->Parent()->IsGlobalScope() ? "return " : "return this.";

    proxy_method += function->Id()->Name().Mutf8() + "(";
    for (const auto *const it : function->Params()) {
        proxy_method += it->AsETSParameterExpression()->Ident()->Name().Mutf8() + ", ";
    }
    proxy_method.pop_back();
    proxy_method.pop_back();
    proxy_method += ") }";

    auto class_ctx = binder::LexicalScope<binder::ClassScope>::Enter(Binder(), GetProgram()->GlobalClassScope());

    auto *const proxy_method_def = CreateMethodDefinition(method->Modifiers(), proxy_method, "<default_methods>.ets");
    proxy_method_def->Function()->SetDefaultParamProxy();

    auto *const current_node = found->Declaration()->Node();
    current_node->AsMethodDefinition()->AddOverload(proxy_method_def);
    proxy_method_def->Id()->SetVariable(found);
    proxy_method_def->SetParent(current_node);
    proxy_method_def->Function()->AddFlag(ir::ScriptFunctionFlags::OVERLOAD);
}

std::string ETSParser::GetNameForTypeNode(const ir::TypeNode *const type_annotation)
{
    const std::string optional_nullable = type_annotation->IsNullable() ? "|null" : "";

    if (type_annotation->IsETSPrimitiveType()) {
        switch (type_annotation->AsETSPrimitiveType()->GetPrimitiveType()) {
            case ir::PrimitiveType::BYTE:
                return "byte" + optional_nullable;
            case ir::PrimitiveType::INT:
                return "int" + optional_nullable;
            case ir::PrimitiveType::LONG:
                return "long" + optional_nullable;
            case ir::PrimitiveType::SHORT:
                return "short" + optional_nullable;
            case ir::PrimitiveType::FLOAT:
                return "float" + optional_nullable;
            case ir::PrimitiveType::DOUBLE:
                return "double" + optional_nullable;
            case ir::PrimitiveType::BOOLEAN:
                return "boolean" + optional_nullable;
            case ir::PrimitiveType::CHAR:
                return "char" + optional_nullable;
            case ir::PrimitiveType::VOID:
                return "void" + optional_nullable;
        }
    }

    if (type_annotation->IsETSTypeReference()) {
        return type_annotation->AsETSTypeReference()->Part()->Name()->AsIdentifier()->Name().Mutf8() +
               optional_nullable;
    }

    if (type_annotation->IsETSFunctionType()) {
        std::string lambda_params = " ";

        for (const auto *const param : type_annotation->AsETSFunctionType()->Params()) {
            lambda_params += param->AsETSParameterExpression()->Ident()->Name().Mutf8();
            lambda_params += ":";
            lambda_params += GetNameForTypeNode(param->AsETSParameterExpression()->Ident()->TypeAnnotation());
            lambda_params += ",";
        }

        lambda_params.pop_back();
        const std::string return_type_name = GetNameForTypeNode(type_annotation->AsETSFunctionType()->ReturnType());

        return "((" + lambda_params + ") => " + return_type_name + ")" + optional_nullable;
    }

    if (type_annotation->IsTSArrayType()) {
        // Note! array is required for the rest parameter.
        return GetNameForTypeNode(type_annotation->AsTSArrayType()->ElementType()) + "[]";
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
    auto start_loc = Lexer()->GetToken().Start();
    ir::ModifierFlags method_flags = ParseInterfaceMethodModifiers();

    if (method_flags != ir::ModifierFlags::NONE) {
        if ((method_flags & ir::ModifierFlags::PRIVATE) == 0) {
            method_flags |= ir::ModifierFlags::PUBLIC;
        }

        auto *method = ParseInterfaceMethod(method_flags);
        method->SetStart(start_loc);
        CreateClassFunctionDeclaration(method);
        return method;
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
        char32_t next_cp = Lexer()->Lookahead();

        if (next_cp == lexer::LEX_CHAR_LEFT_PAREN || next_cp == lexer::LEX_CHAR_LESS_THAN) {
            auto *method = ParseInterfaceMethod(ir::ModifierFlags::PUBLIC);
            method->SetStart(start_loc);
            CreateClassFunctionDeclaration(method);
            return method;
        }

        auto *field = ParseInterfaceField(start_loc);
        field->SetStart(start_loc);
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

    auto *type_name = ParseQualifiedName(flags);
    if (type_name == nullptr) {
        return {nullptr, nullptr};
    }

    if (((*options) & TypeAnnotationParsingOptions::POTENTIAL_CLASS_LITERAL) != 0 &&
        (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_CLASS || IsStructKeyword())) {
        return {type_name, nullptr};
    }

    ir::TSTypeParameterInstantiation *type_param_inst = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SHIFT ||
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SHIFT) {
            Lexer()->BackwardToken(lexer::TokenType::PUNCTUATOR_LESS_THAN, 1);
        }
        *options |= TypeAnnotationParsingOptions::ALLOW_WILDCARD;
        type_param_inst = ParseTypeParameterInstantiation(options);
        *options &= ~TypeAnnotationParsingOptions::ALLOW_WILDCARD;
    }

    return {type_name, type_param_inst};
}

ir::TypeNode *ETSParser::ParseTypeReference(TypeAnnotationParsingOptions *options)
{
    auto start_pos = Lexer()->GetToken().Start();
    ir::ETSTypeReferencePart *type_ref_part = nullptr;

    while (true) {
        auto part_pos = Lexer()->GetToken().Start();
        auto [typeName, typeParams] = ParseTypeReferencePart(options);
        if (typeName == nullptr) {
            return nullptr;
        }

        type_ref_part = AllocNode<ir::ETSTypeReferencePart>(typeName, typeParams, type_ref_part);
        type_ref_part->SetRange({part_pos, Lexer()->GetToken().End()});

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_PERIOD) {
            break;
        }

        Lexer()->NextToken();

        if (((*options) & TypeAnnotationParsingOptions::POTENTIAL_CLASS_LITERAL) != 0 &&
            (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_CLASS || IsStructKeyword())) {
            break;
        }
    }

    auto *type_reference = AllocNode<ir::ETSTypeReference>(type_ref_part);
    type_reference->SetRange({start_pos, Lexer()->GetToken().End()});
    return type_reference;
}

ir::TypeNode *ETSParser::ParseBaseTypeReference(TypeAnnotationParsingOptions *options)
{
    ir::TypeNode *type_annotation = nullptr;

    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::KEYW_BOOLEAN: {
            type_annotation = ParsePrimitiveType(options, ir::PrimitiveType::BOOLEAN);
            break;
        }
        case lexer::TokenType::KEYW_BYTE: {
            type_annotation = ParsePrimitiveType(options, ir::PrimitiveType::BYTE);
            break;
        }
        case lexer::TokenType::KEYW_CHAR: {
            type_annotation = ParsePrimitiveType(options, ir::PrimitiveType::CHAR);
            break;
        }
        case lexer::TokenType::KEYW_DOUBLE: {
            type_annotation = ParsePrimitiveType(options, ir::PrimitiveType::DOUBLE);
            break;
        }
        case lexer::TokenType::KEYW_FLOAT: {
            type_annotation = ParsePrimitiveType(options, ir::PrimitiveType::FLOAT);
            break;
        }
        case lexer::TokenType::KEYW_INT: {
            type_annotation = ParsePrimitiveType(options, ir::PrimitiveType::INT);
            break;
        }
        case lexer::TokenType::KEYW_LONG: {
            type_annotation = ParsePrimitiveType(options, ir::PrimitiveType::LONG);
            break;
        }
        case lexer::TokenType::KEYW_SHORT: {
            type_annotation = ParsePrimitiveType(options, ir::PrimitiveType::SHORT);
            break;
        }

        default: {
            break;
        }
    }

    return type_annotation;
}

ir::TypeNode *ETSParser::ParsePrimitiveType(TypeAnnotationParsingOptions *options, ir::PrimitiveType type)
{
    if (((*options) & TypeAnnotationParsingOptions::DISALLOW_PRIMARY_TYPE) != 0) {
        ThrowSyntaxError("Primitive type is not allowed here.");
    }

    auto *type_annotation = AllocNode<ir::ETSPrimitiveType>(type);
    type_annotation->SetRange(Lexer()->GetToken().Loc());
    Lexer()->NextToken();
    return type_annotation;
}

ir::TSIntersectionType *ETSParser::ParseIntersectionType(ir::Expression *type)
{
    auto start_loc = type->Start();
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

    lexer::SourcePosition end_loc = types.back()->End();
    auto *intersection_type = AllocNode<ir::TSIntersectionType>(std::move(types));
    intersection_type->SetRange({start_loc, end_loc});
    return intersection_type;
}

ir::TypeNode *ETSParser::ParseWildcardType(TypeAnnotationParsingOptions *options)
{
    const auto variance_start_loc = Lexer()->GetToken().Start();
    const auto variance_end_loc = Lexer()->GetToken().End();
    const auto variance_modifier = ParseTypeVarianceModifier(options);

    auto *type_reference = [this, &variance_modifier, options]() -> ir::ETSTypeReference * {
        if (variance_modifier == ir::ModifierFlags::OUT &&
            (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_GREATER_THAN ||
             Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA)) {
            // unbounded 'out'
            return nullptr;
        }
        return ParseTypeReference(options)->AsETSTypeReference();
    }();

    auto *wildcard_type = AllocNode<ir::ETSWildcardType>(type_reference, variance_modifier);
    wildcard_type->SetRange({variance_start_loc, type_reference == nullptr ? variance_end_loc : type_reference->End()});

    return wildcard_type;
}

ir::TypeNode *ETSParser::ParseFunctionType()
{
    auto start_loc = Lexer()->GetToken().Start();
    auto type_params_ctx = binder::LexicalScope<binder::LocalScope>(Binder());
    FunctionParameterContext func_param_context(&GetContext(), Binder());
    auto *func_param_scope = func_param_context.LexicalScope().GetScope();
    auto params = ParseFunctionParams();

    auto *const return_type_annotation = [this]() -> ir::TypeNode * {
        ExpectToken(lexer::TokenType::PUNCTUATOR_ARROW);
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        return ParseTypeAnnotation(&options);
    }();

    ir::ScriptFunctionFlags throw_marker = ParseFunctionThrowMarker(false);

    auto *func_type = AllocNode<ir::ETSFunctionType>(func_param_scope, std::move(params), nullptr,
                                                     return_type_annotation, throw_marker);
    const auto end_loc = return_type_annotation->End();
    func_type->SetRange({start_loc, end_loc});
    func_param_scope->BindNode(func_type);

    return func_type;
}

ir::TypeNode *ETSParser::ParseTypeAnnotation(TypeAnnotationParsingOptions *options)
{
    ir::TypeNode *type_annotation = nullptr;
    bool throw_error = ((*options) & TypeAnnotationParsingOptions::THROW_ERROR) != 0;

    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::LITERAL_IDENT: {
            if (const auto keyword = Lexer()->GetToken().KeywordType();
                keyword == lexer::TokenType::KEYW_IN || keyword == lexer::TokenType::KEYW_OUT) {
                type_annotation = ParseWildcardType(options);
            } else {
                type_annotation = ParseTypeReference(options);
            }

            if (((*options) & TypeAnnotationParsingOptions::POTENTIAL_CLASS_LITERAL) != 0 &&
                (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_CLASS || IsStructKeyword())) {
                return type_annotation;
            }
            break;
        }
        case lexer::TokenType::KEYW_BOOLEAN: {
            type_annotation = ParsePrimitiveType(options, ir::PrimitiveType::BOOLEAN);
            break;
        }
        case lexer::TokenType::KEYW_BYTE: {
            type_annotation = ParsePrimitiveType(options, ir::PrimitiveType::BYTE);
            break;
        }
        case lexer::TokenType::KEYW_CHAR: {
            type_annotation = ParsePrimitiveType(options, ir::PrimitiveType::CHAR);
            break;
        }
        case lexer::TokenType::KEYW_DOUBLE: {
            type_annotation = ParsePrimitiveType(options, ir::PrimitiveType::DOUBLE);
            break;
        }
        case lexer::TokenType::KEYW_FLOAT: {
            type_annotation = ParsePrimitiveType(options, ir::PrimitiveType::FLOAT);
            break;
        }
        case lexer::TokenType::KEYW_INT: {
            type_annotation = ParsePrimitiveType(options, ir::PrimitiveType::INT);
            break;
        }
        case lexer::TokenType::KEYW_LONG: {
            type_annotation = ParsePrimitiveType(options, ir::PrimitiveType::LONG);
            break;
        }
        case lexer::TokenType::KEYW_SHORT: {
            type_annotation = ParsePrimitiveType(options, ir::PrimitiveType::SHORT);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS: {
            auto start_loc = Lexer()->GetToken().Start();
            lexer::LexerPosition saved_pos = Lexer()->Save();
            Lexer()->NextToken();  // eat '('

            if (((*options) & TypeAnnotationParsingOptions::IGNORE_FUNCTION_TYPE) == 0 &&
                (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS ||
                 Lexer()->Lookahead() == lexer::LEX_CHAR_COLON)) {
                type_annotation = ParseFunctionType();
                type_annotation->SetStart(start_loc);
                return type_annotation;
            }

            type_annotation = ParseTypeAnnotation(options);
            type_annotation->SetStart(start_loc);

            if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
                if (throw_error) {
                    ThrowExpectedToken(lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS);
                }

                Lexer()->Rewind(saved_pos);
                type_annotation = nullptr;
            } else {
                Lexer()->NextToken();  // eat ')'
            }

            break;
        }
        default: {
            break;
        }
    }

    if (type_annotation == nullptr) {
        if (throw_error) {
            ThrowSyntaxError("Invalid Type");
        }

        return nullptr;
    }

    const lexer::SourcePosition &start_pos = Lexer()->GetToken().Start();

    if (((*options) & TypeAnnotationParsingOptions::ALLOW_INTERSECTION) != 0 &&
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_BITWISE_AND) {
        if (type_annotation->IsETSPrimitiveType()) {
            ThrowSyntaxError("Invalid intersection type.");
        }

        return ParseIntersectionType(type_annotation);
    }

    while (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
        Lexer()->NextToken();  // eat '['

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
            if (throw_error) {
                ThrowExpectedToken(lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET);
            }

            return nullptr;
        }

        Lexer()->NextToken();  // eat ']'
        type_annotation = AllocNode<ir::TSArrayType>(type_annotation);
        type_annotation->SetRange({start_pos, Lexer()->GetToken().End()});
    }

    while (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_BITWISE_OR) {
        Lexer()->NextToken();  // eat '|'

        if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_NULL) {
            if (throw_error) {
                ThrowExpectedToken(lexer::TokenType::LITERAL_NULL);
            }

            return nullptr;
        }
        Lexer()->NextToken();  // eat 'null'

        type_annotation->AddModifier(ir::ModifierFlags::NULLABLE);
    }

    return type_annotation;
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

ir::Statement *ETSParser::ParseFunctionStatement([[maybe_unused]] const StatementParsingFlags flags)
{
    ASSERT((flags & StatementParsingFlags::GLOBAL) == 0);
    ThrowSyntaxError("Nested functions are not allowed");
}

void ETSParser::ParsePackageDeclaration(ArenaVector<ir::Statement *> &statements)
{
    auto start_loc = Lexer()->GetToken().Start();

    if (Lexer()->GetToken().Type() != lexer::TokenType::KEYW_PACKAGE) {
        if (!IsETSModule() && GetProgram()->IsEntryPoint()) {
            return;
        }

        auto base_name = GetProgram()->SourceFile().Utf8();
        base_name = base_name.substr(base_name.find_last_of(panda::os::file::File::GetPathDelim()) + 1);
        const size_t idx = base_name.find_last_of('.');
        if (idx != std::string::npos) {
            base_name = base_name.substr(0, idx);
        }

        GetProgram()->SetPackageName(base_name);

        return;
    }

    Lexer()->NextToken();

    ir::Expression *name = ParseQualifiedName();

    auto *package_declaration = AllocNode<ir::ETSPackageDeclaration>(name);
    package_declaration->SetRange({start_loc, Lexer()->GetToken().End()});

    ConsumeSemicolon(package_declaration);
    statements.push_back(package_declaration);

    if (name->IsIdentifier()) {
        GetProgram()->SetPackageName(name->AsIdentifier()->Name());
    } else {
        GetProgram()->SetPackageName(name->AsTSQualifiedName()->ToString(Allocator()));
    }
}

std::tuple<ir::ImportSource *, std::vector<std::string>> ETSParser::ParseFromClause(bool require_from)
{
    if (Lexer()->GetToken().KeywordType() != lexer::TokenType::KEYW_FROM) {
        if (require_from) {
            ThrowSyntaxError("Unexpected token.");
        }
    } else {
        Lexer()->NextToken();  // eat `from`
    }

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_STRING) {
        ThrowSyntaxError("Unexpected token.");
    }

    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_STRING);
    std::vector<std::string> user_paths;
    bool is_module = false;
    auto import_path = Lexer()->GetToken().Ident();
    auto resolved_import_path = ResolveImportPath(import_path.Mutf8());

    ir::StringLiteral *resolved_source;
    if (*import_path.Bytes() == '/') {
        resolved_source = AllocNode<ir::StringLiteral>(util::UString(resolved_import_path, Allocator()).View());
    } else {
        resolved_source = AllocNode<ir::StringLiteral>(import_path);
    }

    auto import_data = GetImportData(resolved_import_path);

    if ((GetContext().Status() & ParserStatus::IN_DEFAULT_IMPORTS) == 0) {
        std::tie(user_paths, is_module) = CollectUserSources(import_path.Mutf8());
    }

    ir::StringLiteral *module = nullptr;
    if (is_module) {
        auto pos = import_path.Mutf8().find_last_of(panda::os::file::File::GetPathDelim());

        util::UString base_name(import_path.Mutf8().substr(0, pos), Allocator());
        if (base_name.View().Is(".") || base_name.View().Is("..")) {
            base_name.Append(panda::os::file::File::GetPathDelim());
        }

        module = AllocNode<ir::StringLiteral>(util::UString(import_path.Mutf8().substr(pos + 1), Allocator()).View());
        import_path = base_name.View();
    }

    auto *source = AllocNode<ir::StringLiteral>(import_path);
    source->SetRange(Lexer()->GetToken().Loc());

    Lexer()->NextToken();

    auto *import_source =
        Allocator()->New<ir::ImportSource>(source, resolved_source, import_data.lang, import_data.has_decl, module);
    return {import_source, user_paths};
}

std::vector<std::string> ETSParser::ParseImportDeclarations(ArenaVector<ir::Statement *> &statements)
{
    std::vector<std::string> all_user_paths;
    std::vector<std::string> user_paths;
    ArenaVector<ir::ETSImportDeclaration *> imports(Allocator()->Adapter());

    while (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_IMPORT) {
        auto start_loc = Lexer()->GetToken().Start();
        Lexer()->NextToken();  // eat import

        ArenaVector<ir::AstNode *> specifiers(Allocator()->Adapter());
        ir::ImportSource *import_source = nullptr;

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY) {
            ParseNameSpaceImport(&specifiers);
        } else if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
            ParseNamedImportSpecifiers(&specifiers);
        } else {
            ParseImportDefaultSpecifier(&specifiers);
        }

        std::tie(import_source, user_paths) = ParseFromClause(true);

        all_user_paths.insert(all_user_paths.end(), user_paths.begin(), user_paths.end());
        lexer::SourcePosition end_loc = import_source->Source()->End();
        auto *import_declaration = AllocNode<ir::ETSImportDeclaration>(import_source, std::move(specifiers));
        import_declaration->SetRange({start_loc, end_loc});

        if (import_declaration->Language().IsDynamic()) {
            Binder()->AsETSBinder()->AddDynamicImport(import_declaration);
        }

        ConsumeSemicolon(import_declaration);

        statements.push_back(import_declaration);
        imports.push_back(import_declaration);
    }

    sort(statements.begin(), statements.end(), [](ir::Statement const *s1, ir::Statement const *s2) -> bool {
        return s1->IsETSImportDeclaration() && s2->IsETSImportDeclaration() &&
               s1->AsETSImportDeclaration()->Specifiers()[0]->IsImportNamespaceSpecifier() &&
               !s2->AsETSImportDeclaration()->Specifiers()[0]->IsImportNamespaceSpecifier();
    });

    if ((GetContext().Status() & ParserStatus::IN_DEFAULT_IMPORTS) != 0) {
        static_cast<binder::ETSBinder *>(Binder())->SetDefaultImports(std::move(imports));
    }

    sort(all_user_paths.begin(), all_user_paths.end());
    all_user_paths.erase(unique(all_user_paths.begin(), all_user_paths.end()), all_user_paths.end());

    return all_user_paths;
}

void ETSParser::ParseNamedImportSpecifiers(ArenaVector<ir::AstNode *> *specifiers)
{
    // TODO(user): handle qualifiedName in file bindings: qualifiedName '.' '*'
    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        ThrowSyntaxError("Unexpected token, expected '{'");
    }
    Lexer()->NextToken();  // eat '{'

    auto file_name = GetProgram()->SourceFile().Mutf8();

    while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MULTIPLY) {
            ThrowSyntaxError("The '*' token is not allowed as a selective binding (between braces)");
        }

        if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
            ThrowSyntaxError("Unexpected token");
        }

        lexer::Token imported_token = Lexer()->GetToken();
        auto *imported = AllocNode<ir::Identifier>(imported_token.Ident(), Allocator());
        ir::Identifier *local = nullptr;
        imported->SetRange(Lexer()->GetToken().Loc());

        Lexer()->NextToken();  // eat import name

        if (CheckModuleAsModifier() && Lexer()->GetToken().Type() == lexer::TokenType::KEYW_AS) {
            Lexer()->NextToken();  // eat `as` literal
            local = ParseNamedImport(Lexer()->GetToken());
            Lexer()->NextToken();  // eat local name
        } else {
            local = ParseNamedImport(imported_token);
        }

        auto *specifier = AllocNode<ir::ImportSpecifier>(imported, local);
        specifier->SetRange({imported->Start(), local->End()});

        util::Helpers::CheckImportedName(specifiers, specifier, file_name);

        specifiers->push_back(specifier);

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
            Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat comma
        }
    }

    Lexer()->NextToken();  // eat '}'

    if (Lexer()->GetToken().KeywordType() != lexer::TokenType::KEYW_FROM) {
        ThrowSyntaxError("Unexpected token, expected 'from'");
    }
}

void ETSParser::ParseNameSpaceImport(ArenaVector<ir::AstNode *> *specifiers)
{
    lexer::SourcePosition namespace_start = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat `*` character

    if (!CheckModuleAsModifier()) {
        ThrowSyntaxError("Unexpected token.");
    }

    auto *local = AllocNode<ir::Identifier>(util::StringView(""), Allocator());
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA ||
        Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_FROM) {
        auto *specifier = AllocNode<ir::ImportNamespaceSpecifier>(local);
        specifier->SetRange({namespace_start, Lexer()->GetToken().End()});
        specifiers->push_back(specifier);
        return;
    }

    Lexer()->NextToken();  // eat `as` literal
    local = ParseNamedImport(Lexer()->GetToken());

    auto *specifier = AllocNode<ir::ImportNamespaceSpecifier>(local);
    specifier->SetRange({namespace_start, Lexer()->GetToken().End()});
    specifiers->push_back(specifier);

    Binder()->AddDecl<binder::ImportDecl>(local->Start(), local->Name(), local->Name(), specifier);

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
        } break;

        case lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD: {
            const auto start_loc = Lexer()->GetToken().Start();
            Lexer()->NextToken();

            if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
                ThrowSyntaxError("Unexpected token, expected an identifier.");
            }

            auto *const rest_ident = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
            rest_ident->SetRange(Lexer()->GetToken().Loc());

            parameter = AllocNode<ir::SpreadElement>(ir::AstNodeType::REST_ELEMENT, Allocator(), rest_ident);
            parameter->SetRange({start_loc, Lexer()->GetToken().End()});
        } break;

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

ir::Expression *ETSParser::ParseFunctionParameter()
{
    ir::ETSParameterExpression *param_expression;
    auto *const param_ident = GetAnnotatedExpressionFromParam();

    bool default_null = false;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_QUESTION_MARK) {
        if (param_ident->IsRestElement()) {
            ThrowSyntaxError(NO_DEFAULT_FOR_REST);
        }
        default_null = true;
        Lexer()->NextToken();  // eat '?'
    }

    const bool is_arrow = (GetContext().Status() & ParserStatus::ARROW_FUNCTION) != 0;

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'

        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        ir::TypeNode *type_annotation = ParseTypeAnnotation(&options);

        if (param_ident->IsRestElement() && !type_annotation->IsTSArrayType()) {
            ThrowSyntaxError(ONLY_ARRAY_FOR_REST);
        }

        type_annotation->SetParent(param_ident);
        param_ident->SetTsTypeAnnotation(type_annotation);
        param_ident->SetEnd(type_annotation->End());

    } else if (!is_arrow && !default_null) {
        ThrowSyntaxError(EXPLICIT_PARAM_TYPE);
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        if (param_ident->IsRestElement()) {
            ThrowSyntaxError(NO_DEFAULT_FOR_REST);
        }

        auto const lexer_pos = Lexer()->Save().Iterator();
        Lexer()->NextToken();  // eat '='

        if (default_null) {
            ThrowSyntaxError("Not enable default value with default null");
        }

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS ||
            Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
            ThrowSyntaxError("You didn't set the value.");
        }

        param_expression = AllocNode<ir::ETSParameterExpression>(param_ident->AsIdentifier(), ParseExpression());

        std::string value = Lexer()->SourceView(lexer_pos.Index(), Lexer()->Save().Iterator().Index()).Mutf8();
        while (value.back() == ' ') {
            value.pop_back();
        }
        if (value.back() == ')' || value.back() == ',') {
            value.pop_back();
        }
        param_expression->SetLexerSaved(util::UString(value, Allocator()).View());

        param_expression->SetRange({param_ident->Start(), param_expression->Initializer()->End()});
    } else if (param_ident->IsIdentifier()) {
        auto *const type_annotation = param_ident->AsIdentifier()->TypeAnnotation();

        const auto type_annotation_value = [this, type_annotation]() -> std::pair<ir::Expression *, std::string> {
            if (type_annotation == nullptr) {
                return std::make_pair(nullptr, "");
            }
            if (!type_annotation->IsETSPrimitiveType()) {
                return std::make_pair(AllocNode<ir::NullLiteral>(), "null");
            }
            // TODO(ttamas) : after nullable fix, fix this scope
            switch (type_annotation->AsETSPrimitiveType()->GetPrimitiveType()) {
                case ir::PrimitiveType::BYTE:
                case ir::PrimitiveType::INT:
                case ir::PrimitiveType::LONG:
                case ir::PrimitiveType::SHORT:
                case ir::PrimitiveType::FLOAT:
                case ir::PrimitiveType::DOUBLE:
                    return std::make_pair(AllocNode<ir::NumberLiteral>(lexer::Number(0)), "0");
                case ir::PrimitiveType::BOOLEAN:
                    return std::make_pair(AllocNode<ir::BooleanLiteral>(false), "false");
                case ir::PrimitiveType::CHAR:
                    return std::make_pair(AllocNode<ir::CharLiteral>(), "c'\\u0000'");
                default: {
                    UNREACHABLE();
                }
            }
        }();

        if (default_null && !type_annotation->IsETSPrimitiveType()) {
            type_annotation->AddModifier(ir::ModifierFlags::NULLABLE);
        }

        param_expression = AllocNode<ir::ETSParameterExpression>(
            param_ident->AsIdentifier(), default_null ? std::get<0>(type_annotation_value) : nullptr);

        if (default_null) {
            param_expression->SetLexerSaved(util::UString(std::get<1>(type_annotation_value), Allocator()).View());
        }

        param_expression->SetRange({param_ident->Start(), param_ident->End()});
    } else {
        param_expression = AllocNode<ir::ETSParameterExpression>(param_ident->AsRestElement(), nullptr);
        param_expression->SetRange({param_ident->Start(), param_ident->End()});
    }

    auto *const var = std::get<1>(Binder()->AddParamDecl(param_expression));
    param_expression->Ident()->SetVariable(var);
    var->SetScope(Binder()->GetScope());

    return param_expression;
}

void ETSParser::AddVariableDeclarationBindings(ir::Expression *init, lexer::SourcePosition start_loc,
                                               VariableParsingFlags flags)
{
    std::vector<ir::Identifier *> bindings = util::Helpers::CollectBindingNames(init);

    for (auto *binding : bindings) {
        binder::Decl *decl {};
        binder::Variable *var {};

        if ((flags & VariableParsingFlags::LET) != 0U) {
            std::tie(decl, var) = Binder()->NewVarDecl<binder::LetDecl>(start_loc, binding->Name());
        } else {
            std::tie(decl, var) = Binder()->NewVarDecl<binder::ConstDecl>(start_loc, binding->Name());
        }

        binding->SetVariable(var);
        var->SetScope(Binder()->GetScope());
        var->AddFlag(binder::VariableFlags::LOCAL);
        decl->BindNode(init);
    }
}

ir::AnnotatedExpression *ETSParser::ParseVariableDeclaratorKey([[maybe_unused]] VariableParsingFlags flags)
{
    ir::Identifier *init = ExpectIdentifier();
    ir::TypeNode *type_annotation = nullptr;

    if (auto const token_type = Lexer()->GetToken().Type(); token_type == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        type_annotation = ParseTypeAnnotation(&options);
    } else if (token_type != lexer::TokenType::PUNCTUATOR_SUBSTITUTION &&
               (flags & VariableParsingFlags::FOR_OF) == 0U) {
        ThrowSyntaxError("Variable must be initialized or it's type must be declared");
    }

    if (type_annotation != nullptr) {
        init->SetTsTypeAnnotation(type_annotation);
        type_annotation->SetParent(init);
    }

    return init;
}

ir::Expression *ETSParser::ParseInitializer()
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
        return ParseArrayLiteral();
    }

    return ParseExpression();
}

ir::ArrayExpression *ETSParser::ParseArrayLiteral()
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET);

    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();

    ArenaVector<ir::Expression *> elements(Allocator()->Adapter());

    Lexer()->NextToken();

    while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
        elements.push_back(ParseInitializer());

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
            Lexer()->NextToken();  // eat comma
            continue;
        }

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
            ThrowSyntaxError("Comma is mandatory between elements in an array literal");
        }
    }

    auto *array_literal = AllocNode<ir::ArrayExpression>(std::move(elements), Allocator());
    array_literal->SetRange({start_loc, Lexer()->GetToken().End()});
    Lexer()->NextToken();

    return array_literal;
}

ir::VariableDeclarator *ETSParser::ParseVariableDeclaratorInitializer(ir::Expression *init, VariableParsingFlags flags,
                                                                      const lexer::SourcePosition &start_loc)
{
    if ((flags & VariableParsingFlags::DISALLOW_INIT) != 0) {
        ThrowSyntaxError("for-await-of loop variable declaration may not have an initializer");
    }

    Lexer()->NextToken();

    ir::Expression *initializer = ParseInitializer();

    lexer::SourcePosition end_loc = initializer->End();

    auto *declarator = AllocNode<ir::VariableDeclarator>(init, initializer);
    declarator->SetRange({start_loc, end_loc});

    return declarator;
}

ir::VariableDeclarator *ETSParser::ParseVariableDeclarator(ir::Expression *init, lexer::SourcePosition start_loc,
                                                           VariableParsingFlags flags)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        return ParseVariableDeclaratorInitializer(init, flags, start_loc);
    }

    if ((flags & VariableParsingFlags::CONST) != 0 &&
        static_cast<uint32_t>(flags & VariableParsingFlags::ACCEPT_CONST_NO_INIT) == 0U) {
        ThrowSyntaxError("Missing initializer in const declaration");
    }

    if (init->AsIdentifier()->TypeAnnotation() == nullptr && (flags & VariableParsingFlags::FOR_OF) == 0U) {
        ThrowSyntaxError("Variable must be initialized or it's type must be declared");
    }

    lexer::SourcePosition end_loc = init->End();
    auto declarator = AllocNode<ir::VariableDeclarator>(init);
    declarator->SetRange({start_loc, end_loc});

    return declarator;
}

ir::Statement *ETSParser::ParseAssertStatement()
{
    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();
    Lexer()->NextToken();

    ir::Expression *test = ParseExpression();
    lexer::SourcePosition end_loc = test->End();
    ir::Expression *second = nullptr;

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        second = ParseExpression();
        end_loc = second->End();
    }

    auto *as_statement = AllocNode<ir::AssertStatement>(test, second);
    as_statement->SetRange({start_loc, end_loc});
    ConsumeSemicolon(as_statement);

    return as_statement;
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

    auto param_decl = Binder()->AddParamDecl(param);

    if (param->IsIdentifier()) {
        param->AsIdentifier()->SetVariable(std::get<1>(param_decl));
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
        param->SetTsTypeAnnotation(ParseTypeAnnotation(&options));
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        ThrowSyntaxError("Catch clause variable cannot have an initializer");
    }
}

ir::Statement *ETSParser::ParseTryStatement()
{
    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat the 'try' keyword

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        ThrowSyntaxError("Unexpected token, expected '{'");
    }

    ir::BlockStatement *body = ParseBlockStatement();

    ArenaVector<ir::CatchClause *> catch_clauses(Allocator()->Adapter());

    while (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_CATCH) {
        ir::CatchClause *clause {};

        clause = ParseCatchClause();

        catch_clauses.push_back(clause);
    }

    ir::BlockStatement *finalizer = nullptr;
    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_FINALLY) {
        Lexer()->NextToken();  // eat 'finally' keyword

        finalizer = ParseBlockStatement();
    }

    if (catch_clauses.empty() && finalizer == nullptr) {
        ThrowSyntaxError("A try statement should contain either finally clause or at least one catch clause.",
                         start_loc);
    }

    lexer::SourcePosition end_loc = finalizer != nullptr ? finalizer->End() : catch_clauses.back()->End();

    ArenaVector<std::pair<compiler::LabelPair, const ir::Statement *>> finalizer_insertions(Allocator()->Adapter());

    auto *try_statement = AllocNode<ir::TryStatement>(body, std::move(catch_clauses), finalizer, finalizer_insertions);
    try_statement->SetRange({start_loc, end_loc});
    ConsumeSemicolon(try_statement);

    return try_statement;
}

ir::Statement *ETSParser::ParseImportDeclaration([[maybe_unused]] StatementParsingFlags flags)
{
    ImportDeclarationContext import_ctx(Binder());

    char32_t next_char = Lexer()->Lookahead();
    if (next_char == lexer::LEX_CHAR_LEFT_PAREN || next_char == lexer::LEX_CHAR_DOT) {
        return ParseExpressionStatement();
    }

    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat import

    ArenaVector<ir::AstNode *> specifiers(Allocator()->Adapter());

    ir::ImportSource *import_source = nullptr;
    std::vector<std::string> user_paths;

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_STRING) {
        ir::AstNode *ast_node = ParseImportSpecifiers(&specifiers);
        if (ast_node != nullptr) {
            ASSERT(ast_node->IsTSImportEqualsDeclaration());
            ast_node->SetRange({start_loc, Lexer()->GetToken().End()});
            ConsumeSemicolon(ast_node->AsTSImportEqualsDeclaration());
            return ast_node->AsTSImportEqualsDeclaration();
        }
        std::tie(import_source, user_paths) = ParseFromClause(true);
    } else {
        std::tie(import_source, user_paths) = ParseFromClause(false);
    }

    lexer::SourcePosition end_loc = import_source->Source()->End();
    auto *import_declaration = AllocNode<ir::ETSImportDeclaration>(import_source, std::move(specifiers));
    import_declaration->SetRange({start_loc, end_loc});

    if (import_declaration->Language().IsDynamic()) {
        Binder()->AsETSBinder()->AddDynamicImport(import_declaration);
    }

    ConsumeSemicolon(import_declaration);

    return import_declaration;
}

ir::Statement *ETSParser::ParseExportDeclaration([[maybe_unused]] StatementParsingFlags flags)
{
    ThrowUnexpectedToken(lexer::TokenType::KEYW_EXPORT);
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
        case lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK: {
            break;
        }
        case lexer::TokenType::KEYW_LAUNCH: {
            return ParseLaunchExpression(flags);
        }
        default: {
            return ParseLeftHandSideExpression(flags);
        }
    }

    lexer::TokenType operator_type = Lexer()->GetToken().Type();
    auto start = Lexer()->GetToken().Start();
    Lexer()->NextToken();

    ir::Expression *argument = nullptr;
    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::PUNCTUATOR_PLUS:
        case lexer::TokenType::PUNCTUATOR_MINUS:
        case lexer::TokenType::PUNCTUATOR_TILDE:
        case lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK:
        case lexer::TokenType::PUNCTUATOR_PLUS_PLUS:
        case lexer::TokenType::PUNCTUATOR_MINUS_MINUS: {
            argument = ParseUnaryOrPrefixUpdateExpression();
            break;
        }
        default: {
            argument = ParseLeftHandSideExpression(flags);
            break;
        }
    }

    if (lexer::Token::IsUpdateToken(operator_type)) {
        if (!argument->IsIdentifier() && !argument->IsMemberExpression()) {
            ThrowSyntaxError("Invalid left-hand side in prefix operation");
        }
    }

    lexer::SourcePosition end = argument->End();

    ir::Expression *return_expr = nullptr;
    if (lexer::Token::IsUpdateToken(operator_type)) {
        return_expr = AllocNode<ir::UpdateExpression>(argument, operator_type, true);
    } else {
        return_expr = AllocNode<ir::UnaryExpression>(argument, operator_type);
    }

    return_expr->SetRange({start, end});

    return return_expr;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ETSParser::ParsePrimaryExpression(ExpressionParseFlags flags)
{
    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::LITERAL_TRUE:
        case lexer::TokenType::LITERAL_FALSE: {
            return ParseBooleanLiteral();
        }
        case lexer::TokenType::LITERAL_NULL: {
            return ParseNullLiteral();
        }
        case lexer::TokenType::LITERAL_NUMBER: {
            return ParseNumberLiteral();
        }
        case lexer::TokenType::LITERAL_STRING: {
            return ParseStringLiteral();
        }
        case lexer::TokenType::LITERAL_CHAR: {
            return ParseCharLiteral();
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS: {
            return ParseCoverParenthesizedExpressionAndArrowParameterList();
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
        default: {
            auto start_loc = Lexer()->GetToken().Start();
            auto saved_pos = Lexer()->Save();
            TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::POTENTIAL_CLASS_LITERAL |
                                                   TypeAnnotationParsingOptions::IGNORE_FUNCTION_TYPE;
            ir::TypeNode *potential_type = ParseTypeAnnotation(&options);

            if (potential_type != nullptr) {
                if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD) {
                    Lexer()->NextToken();  // eat '.'
                }

                if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_CLASS || IsStructKeyword()) {
                    Lexer()->NextToken();  // eat 'class' and 'struct'
                    auto *class_literal = AllocNode<ir::ETSClassLiteral>(potential_type);
                    class_literal->SetRange({start_loc, Lexer()->GetToken().End()});
                    return class_literal;
                }
            }

            Lexer()->Rewind(saved_pos);

            if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
                return ParsePrimaryExpressionIdent(flags);
            }

            break;
        }
    }

    ThrowSyntaxError({"Unexpected token '", lexer::TokenToString(Lexer()->GetToken().Type()), "'."});
    return nullptr;
}

bool ETSParser::IsArrowFunctionExpressionStart()
{
    const auto saved_pos = Lexer()->Save();
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
    Lexer()->NextToken();
    auto token_type = Lexer()->GetToken().Type();

    size_t open_brackets = 1;
    bool expect_identifier = true;
    while (token_type != lexer::TokenType::EOS && open_brackets > 0) {
        switch (token_type) {
            case lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS:
                --open_brackets;
                break;
            case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS:
                ++open_brackets;
                break;
            case lexer::TokenType::PUNCTUATOR_COMMA:
                expect_identifier = true;
                break;
            case lexer::TokenType::PUNCTUATOR_SEMI_COLON:
                Lexer()->Rewind(saved_pos);
                return false;
            default:
                if (!expect_identifier) {
                    break;
                }
                if (token_type != lexer::TokenType::LITERAL_IDENT &&
                    token_type != lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD) {
                    Lexer()->Rewind(saved_pos);
                    return false;
                }
                expect_identifier = false;
        }
        Lexer()->NextToken();
        token_type = Lexer()->GetToken().Type();
    }

    while (token_type != lexer::TokenType::EOS && token_type != lexer::TokenType::PUNCTUATOR_ARROW) {
        if (lexer::Token::IsPunctuatorToken(token_type) && token_type != lexer::TokenType::PUNCTUATOR_COLON &&
            token_type != lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET &&
            token_type != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET &&
            token_type != lexer::TokenType::PUNCTUATOR_LESS_THAN &&
            token_type != lexer::TokenType::PUNCTUATOR_GREATER_THAN &&
            token_type != lexer::TokenType::PUNCTUATOR_BITWISE_OR) {
            break;
        }
        Lexer()->NextToken();
        token_type = Lexer()->GetToken().Type();
    }
    Lexer()->Rewind(saved_pos);
    return token_type == lexer::TokenType::PUNCTUATOR_ARROW;
}

ir::ArrowFunctionExpression *ETSParser::ParseArrowFunctionExpression()
{
    auto new_status = ParserStatus::ARROW_FUNCTION;
    auto *func = ParseFunction(new_status);
    auto *arrow_func_node = AllocNode<ir::ArrowFunctionExpression>(Allocator(), func);
    arrow_func_node->SetRange(func->Range());
    return arrow_func_node;
}

ir::Expression *ETSParser::ParseCoverParenthesizedExpressionAndArrowParameterList()
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
    if (IsArrowFunctionExpressionStart()) {
        return ParseArrowFunctionExpression();
    }

    lexer::SourcePosition start = Lexer()->GetToken().Start();
    Lexer()->NextToken();

    ir::Expression *expr = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA);

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError("Unexpected token, expected ')'");
    }

    expr->SetGrouped();
    expr->SetRange({start, Lexer()->GetToken().End()});
    Lexer()->NextToken();

    return expr;
}

bool ETSParser::ParsePotentialGenericFunctionCall(ir::Expression *primary_expr, ir::Expression **return_expression,
                                                  [[maybe_unused]] const lexer::SourcePosition &start_loc,
                                                  bool ignore_call_expression)
{
    if (Lexer()->Lookahead() == lexer::LEX_CHAR_LESS_THAN ||
        (!primary_expr->IsIdentifier() && !primary_expr->IsMemberExpression())) {
        return true;
    }

    const auto saved_pos = Lexer()->Save();

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SHIFT) {
        Lexer()->BackwardToken(lexer::TokenType::PUNCTUATOR_LESS_THAN, 1);
    }

    TypeAnnotationParsingOptions options =
        TypeAnnotationParsingOptions::ALLOW_WILDCARD | TypeAnnotationParsingOptions::IGNORE_FUNCTION_TYPE;
    ir::TSTypeParameterInstantiation *type_params = ParseTypeParameterInstantiation(&options);

    if (type_params == nullptr) {
        Lexer()->Rewind(saved_pos);
        return true;
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::EOS) {
        ThrowSyntaxError("'(' expected");
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        if (!ignore_call_expression) {
            *return_expression = ParseCallExpression(*return_expression, false, false);
            (*return_expression)->AsCallExpression()->SetTypeParams(type_params);
            return false;
        }

        return true;
    }

    Lexer()->Rewind(saved_pos);
    return true;
}

ir::Expression *ETSParser::ParsePostPrimaryExpression(ir::Expression *primary_expr, lexer::SourcePosition start_loc,
                                                      bool ignore_call_expression,
                                                      [[maybe_unused]] bool *is_chain_expression)
{
    ir::Expression *return_expression = primary_expr;

    while (true) {
        switch (Lexer()->GetToken().Type()) {
            case lexer::TokenType::PUNCTUATOR_QUESTION_DOT: {
                Lexer()->NextToken();  // eat ?.

                if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
                    return_expression = ParseElementAccess(return_expression, true);
                    continue;
                }

                if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
                    return_expression = ParseCallExpression(return_expression, true, false);
                    continue;
                }

                return_expression = ParsePropertyAccess(return_expression, true);
                continue;
            }
            case lexer::TokenType::PUNCTUATOR_PERIOD: {
                Lexer()->NextToken();  // eat period

                return_expression = ParsePropertyAccess(return_expression);
                continue;
            }
            case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET: {
                return_expression = ParseElementAccess(return_expression);
                continue;
            }
            case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT:
            case lexer::TokenType::PUNCTUATOR_LESS_THAN: {
                if (ParsePotentialGenericFunctionCall(return_expression, &return_expression, start_loc,
                                                      ignore_call_expression)) {
                    break;
                }

                continue;
            }
            case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS: {
                if (ignore_call_expression) {
                    break;
                }

                return_expression = ParseCallExpression(return_expression, false, false);
                continue;
            }
            case lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK: {
                const bool should_break = ParsePotentialNonNullExpression(&return_expression, start_loc);

                if (should_break) {
                    break;
                }

                continue;
            }
            default: {
                break;
            }
        }

        break;
    }

    return return_expression;
}

ir::Expression *ETSParser::ParsePotentialAsExpression(ir::Expression *primary_expr)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::KEYW_AS);

    TypeAnnotationParsingOptions options =
        TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::ALLOW_INTERSECTION;
    Lexer()->NextToken();
    ir::TypeNode *type = ParseTypeAnnotation(&options);
    auto *as_expression = AllocNode<ir::TSAsExpression>(primary_expr, type, false);
    as_expression->SetRange(primary_expr->Range());
    return as_expression;
}

ir::Expression *ETSParser::ParseNewExpression()
{
    lexer::SourcePosition start = Lexer()->GetToken().Start();

    Lexer()->NextToken();  // eat new

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
    ir::TypeNode *base_type_reference = ParseBaseTypeReference(&options);
    ir::TypeNode *type_reference = base_type_reference;
    if (type_reference == nullptr) {
        options |= TypeAnnotationParsingOptions::IGNORE_FUNCTION_TYPE | TypeAnnotationParsingOptions::ALLOW_WILDCARD;
        type_reference = ParseTypeReference(&options);
    } else if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        ThrowSyntaxError("Invalid { after base types.");
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
        Lexer()->NextToken();
        ir::Expression *dimension = ParseExpression();

        auto end_loc = Lexer()->GetToken().End();
        ExpectToken(lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET);

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
            auto *arr_instance = AllocNode<ir::ETSNewArrayInstanceExpression>(type_reference, dimension);
            arr_instance->SetRange({start, end_loc});
            return arr_instance;
        }

        ArenaVector<ir::Expression *> dimensions(Allocator()->Adapter());
        dimensions.push_back(dimension);

        do {
            Lexer()->NextToken();
            dimensions.push_back(ParseExpression());

            end_loc = Lexer()->GetToken().End();
            ExpectToken(lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET);
        } while (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET);

        auto *multi_array = AllocNode<ir::ETSNewMultiDimArrayInstanceExpression>(type_reference, std::move(dimensions));
        multi_array->SetRange({start, end_loc});
        return multi_array;
    }

    ArenaVector<ir::Expression *> arguments(Allocator()->Adapter());
    lexer::SourcePosition end_loc = type_reference->End();

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        if (base_type_reference != nullptr) {
            ThrowSyntaxError("Can not use 'new' on primitive types.", base_type_reference->Start());
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

        end_loc = Lexer()->GetToken().End();
        Lexer()->NextToken();
    }

    ir::ClassDefinition *class_definition {};

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        auto *parent_class_scope = Binder()->GetScope();
        while (!parent_class_scope->IsClassScope()) {
            ASSERT(parent_class_scope->Parent());
            parent_class_scope = parent_class_scope->Parent();
        }

        auto class_ctx = binder::LexicalScope<binder::ClassScope>(Binder());
        ArenaVector<ir::TSClassImplements *> implements(Allocator()->Adapter());
        auto modifiers = ir::ClassDefinitionModifiers::ANONYMOUS | ir::ClassDefinitionModifiers::HAS_SUPER;
        auto [ctor, properties, bodyRange] = ParseClassBody(modifiers);

        auto *class_scope = class_ctx.GetScope();
        util::UString anonymous_name(util::StringView("#"), Allocator());
        anonymous_name.Append(std::to_string(parent_class_scope->AsClassScope()->GetAndIncrementAnonymousClassIdx()));
        auto new_ident = AllocNode<ir::Identifier>(anonymous_name.View(), Allocator());
        class_definition = AllocNode<ir::ClassDefinition>(
            class_scope, anonymous_name.View(), new_ident, nullptr, nullptr, std::move(implements), ctor,
            type_reference, std::move(properties), modifiers, ir::ModifierFlags::NONE, Language(Language::Id::ETS));

        class_definition->SetRange(bodyRange);
        class_scope->BindNode(class_definition);
    }

    auto *new_expr_node =
        AllocNode<ir::ETSNewClassInstanceExpression>(type_reference, std::move(arguments), class_definition);
    new_expr_node->SetRange({start, Lexer()->GetToken().End()});

    return new_expr_node;
}

ir::Expression *ETSParser::ParseAsyncExpression()
{
    Lexer()->NextToken();  // eat 'async'
    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS ||
        !IsArrowFunctionExpressionStart()) {
        ThrowSyntaxError("Unexpected token. expected '('");
    }

    auto new_status = ParserStatus::NEED_RETURN_TYPE | ParserStatus::ARROW_FUNCTION | ParserStatus::ASYNC_FUNCTION;
    auto *func = ParseFunction(new_status);
    auto *arrow_func_node = AllocNode<ir::ArrowFunctionExpression>(Allocator(), func);
    arrow_func_node->SetRange(func->Range());
    return arrow_func_node;
}

ir::Expression *ETSParser::ParseAwaitExpression()
{
    lexer::SourcePosition start = Lexer()->GetToken().Start();
    Lexer()->NextToken();
    ir::Expression *argument = ParseExpression();
    auto *await_expression = AllocNode<ir::AwaitExpression>(argument);
    await_expression->SetRange({start, Lexer()->GetToken().End()});
    return await_expression;
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
    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();

    const auto variance_modifier = [this, options] {
        switch (Lexer()->GetToken().KeywordType()) {
            case lexer::TokenType::KEYW_IN:
            case lexer::TokenType::KEYW_OUT:
                return ParseTypeVarianceModifier(options);
            default:
                return ir::ModifierFlags::NONE;
        }
    }();

    auto *param_ident = ExpectIdentifier();
    auto [decl, var] = Binder()->NewVarDecl<binder::TypeParameterDecl>(param_ident->Start(), param_ident->Name());
    param_ident->SetVariable(var);
    var->SetScope(Binder()->GetScope());
    var->AddFlag(binder::VariableFlags::TYPE_PARAMETER);

    ir::TypeNode *constraint = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_EXTENDS) {
        Lexer()->NextToken();
        TypeAnnotationParsingOptions new_options = TypeAnnotationParsingOptions::THROW_ERROR |
                                                   TypeAnnotationParsingOptions::ALLOW_INTERSECTION |
                                                   TypeAnnotationParsingOptions::IGNORE_FUNCTION_TYPE;
        constraint = ParseTypeAnnotation(&new_options);
    }

    auto *type_param = AllocNode<ir::TSTypeParameter>(param_ident, constraint, nullptr, variance_modifier);
    decl->BindNode(type_param);
    type_param->SetRange({start_loc, Lexer()->GetToken().End()});
    return type_param;
}

// NOLINTBEGIN(cert-err58-cpp)
static std::string const DUPLICATE_ENUM_VALUE = "Duplicate enum initialization value "s;
static std::string const INVALID_ENUM_TYPE = "Invalid enum initialization type"s;
static std::string const INVALID_ENUM_VALUE = "Invalid enum initialization value"s;
static std::string const MISSING_COMMA_IN_ENUM = "Missing comma between enum constants"s;
static std::string const TRAILING_COMMA_IN_ENUM = "Trailing comma is not allowed in enum constant list"s;
// NOLINTEND(cert-err58-cpp)

ir::TSEnumDeclaration *ETSParser::ParseEnumMembers(ir::Identifier *const key, const lexer::SourcePosition &enum_start,
                                                   const bool is_const, const bool is_static)
{
    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        ThrowSyntaxError("'{' expected");
    }

    Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat '{'

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        ThrowSyntaxError("An enum must have at least one enum constant");
    }

    // Lambda to check if enum underlying type is string:
    auto const is_string_enum = [this]() -> bool {
        Lexer()->NextToken();
        auto token_type = Lexer()->GetToken().Type();
        while (token_type != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE &&
               token_type != lexer::TokenType::PUNCTUATOR_COMMA) {
            if (token_type == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
                Lexer()->NextToken();
                if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_STRING) {
                    return true;
                }
            }
            Lexer()->NextToken();
            token_type = Lexer()->GetToken().Type();
        }
        return false;
    };

    // Get the underlying type of enum (number or string). It is defined from the first element ONLY!
    auto const pos = Lexer()->Save();
    auto const string_type_enum = is_string_enum();
    Lexer()->Rewind(pos);

    ArenaVector<ir::AstNode *> members(Allocator()->Adapter());
    const auto enum_ctx = binder::LexicalScope<binder::LocalScope>(Binder());

    if (string_type_enum) {
        ParseStringEnum(members);
    } else {
        ParseNumberEnum(members);
    }

    auto *const enum_declaration = AllocNode<ir::TSEnumDeclaration>(Allocator(), Binder()->GetScope()->AsLocalScope(),
                                                                    key, std::move(members), is_const, is_static);
    enum_declaration->SetRange({enum_start, Lexer()->GetToken().End()});

    Lexer()->NextToken();  // eat '}'

    return enum_declaration;
}

void ETSParser::ParseNumberEnum(ArenaVector<ir::AstNode *> &members)
{
    std::unordered_set<checker::ETSEnumType::ValueType> enum_values {};
    checker::ETSEnumType::ValueType current_value {};

    // Lambda to parse enum member (maybe with initializer)
    auto const parse_member = [this, &members, &enum_values, &current_value]() {
        auto *const ident = ExpectIdentifier();
        auto [decl, var] = Binder()->NewVarDecl<binder::LetDecl>(ident->Start(), ident->Name());
        var->SetScope(Binder()->GetScope());
        var->AddFlag(binder::VariableFlags::STATIC);
        ident->SetVariable(var);

        auto const add_value = [this, &enum_values](checker::ETSEnumType::ValueType const new_value) {
            if (auto const rc = enum_values.emplace(new_value); !rc.second) {
                ThrowSyntaxError(DUPLICATE_ENUM_VALUE + std::to_string(new_value));
            }
        };

        ir::NumberLiteral *ordinal;
        lexer::SourcePosition end_loc;

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
            // Case when user explicitly set the value for enumeration constant

            bool minus_sign = false;

            Lexer()->NextToken();
            if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PLUS) {
                Lexer()->NextToken();
            } else if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MINUS) {
                minus_sign = true;
                Lexer()->NextToken();
            }

            if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_NUMBER) {
                ThrowSyntaxError(INVALID_ENUM_TYPE);
            }

            ordinal = ParseNumberLiteral()->AsNumberLiteral();
            if (!ordinal->Number().CanGetValue<checker::ETSEnumType::ValueType>()) {
                ThrowSyntaxError(INVALID_ENUM_VALUE);
            } else if (minus_sign) {
                ordinal->Number().Negate();
            }

            current_value = ordinal->Number().GetValue<checker::ETSEnumType::ValueType>();
            add_value(current_value);

            end_loc = ordinal->End();
        } else {
            // Default enumeration constant value. Equal to 0 for the first item and = previous_value + 1 for all the
            // others.

            add_value(current_value);
            ordinal = AllocNode<ir::NumberLiteral>(lexer::Number(current_value));

            end_loc = ident->End();
        }

        auto *const member = AllocNode<ir::TSEnumMember>(ident, ordinal);
        member->SetRange({ident->Start(), end_loc});
        decl->BindNode(member);
        members.emplace_back(member);

        ++current_value;
    };

    parse_member();

    while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COMMA) {
            ThrowSyntaxError(MISSING_COMMA_IN_ENUM);
        }

        Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat ','

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
            ThrowSyntaxError("Trailing comma is not allowed in enum constant list");
        }

        parse_member();
    }
}

void ETSParser::ParseStringEnum(ArenaVector<ir::AstNode *> &members)
{
    std::unordered_set<util::StringView> enum_values {};

    // Lambda to parse enum member (maybe with initializer)
    auto const parse_member = [this, &members, &enum_values]() {
        auto *const ident = ExpectIdentifier();
        auto [decl, var] = Binder()->NewVarDecl<binder::LetDecl>(ident->Start(), ident->Name());
        var->SetScope(Binder()->GetScope());
        var->AddFlag(binder::VariableFlags::STATIC);
        ident->SetVariable(var);

        ir::StringLiteral *item_value;

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
            // Case when user explicitly set the value for enumeration constant

            Lexer()->NextToken();
            if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_STRING) {
                ThrowSyntaxError(INVALID_ENUM_TYPE);
            }

            item_value = ParseStringLiteral();
            if (auto const rc = enum_values.emplace(item_value->Str()); !rc.second) {
                ThrowSyntaxError(DUPLICATE_ENUM_VALUE + '\'' + std::string {item_value->Str()} + '\'');
            }
        } else {
            // Default item value is not allowed for string type enumerations!
            ThrowSyntaxError("All items of string-type enumeration should be explicitly initialized.");
        }

        auto *const member = AllocNode<ir::TSEnumMember>(ident, item_value);
        member->SetRange({ident->Start(), item_value->End()});
        decl->BindNode(member);
        members.emplace_back(member);
    };

    parse_member();

    while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COMMA) {
            ThrowSyntaxError(MISSING_COMMA_IN_ENUM);
        }

        Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat ','

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
            ThrowSyntaxError(TRAILING_COMMA_IN_ENUM);
        }

        parse_member();
    }
}

ir::ThisExpression *ETSParser::ParseThisExpression()
{
    auto *this_expression = TypedParser::ParseThisExpression();

    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::PUNCTUATOR_PERIOD:
        case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS:
        case lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS:
        case lexer::TokenType::PUNCTUATOR_SEMI_COLON:
        case lexer::TokenType::PUNCTUATOR_COLON:
        case lexer::TokenType::PUNCTUATOR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_COMMA:
        case lexer::TokenType::PUNCTUATOR_QUESTION_MARK:
        case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET:
        case lexer::TokenType::KEYW_AS: {
            break;
        }
        default: {
            ThrowUnexpectedToken(Lexer()->GetToken().Type());
            break;
        }
    }

    return this_expression;
}

ir::Identifier *ETSParser::ParseClassIdent([[maybe_unused]] ir::ClassDefinitionModifiers modifiers)
{
    return ExpectIdentifier();
}

// NOLINTNEXTLINE(google-default-arguments)
ir::ClassDeclaration *ETSParser::ParseClassStatement([[maybe_unused]] StatementParsingFlags flags,
                                                     [[maybe_unused]] ir::ClassDefinitionModifiers modifiers,
                                                     [[maybe_unused]] ir::ModifierFlags mod_flags)
{
    ThrowSyntaxError("Illegal start of expression", Lexer()->GetToken().Start());
}

// NOLINTNEXTLINE(google-default-arguments)
ir::ETSStructDeclaration *ETSParser::ParseStructStatement([[maybe_unused]] StatementParsingFlags flags,
                                                          [[maybe_unused]] ir::ClassDefinitionModifiers modifiers,
                                                          [[maybe_unused]] ir::ModifierFlags mod_flags)
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

        ASSERT(Binder()->GetScope()->IsClassScope());
        auto class_ctx = binder::LexicalScope<binder::LocalScope>::Enter(
            Binder(), Binder()->GetScope()->AsClassScope()->StaticMethodScope());
        auto *id = AllocNode<ir::Identifier>(compiler::Signatures::CCTOR, Allocator());
        auto [_, var] =
            Binder()->NewVarDecl<binder::FunctionDecl>(property->Start(), Allocator(), id->Name(), property);
        (void)_;
        var->AddFlag(binder::VariableFlags::METHOD);
        id->SetVariable(var);
        property->AsClassStaticBlock()->Function()->SetIdent(id);
    }

    if (property->IsTSInterfaceBody()) {
        return CheckClassElementInterfaceBody(property, properties);
    }

    return property->IsMethodDefinition() && property->AsMethodDefinition()->Function()->IsOverload();
}

void ETSParser::CreateImplicitConstructor([[maybe_unused]] ir::MethodDefinition *&ctor,
                                          ArenaVector<ir::AstNode *> &properties,
                                          [[maybe_unused]] ir::ClassDefinitionModifiers modifiers,
                                          const lexer::SourcePosition &start_loc)
{
    if (std::any_of(properties.cbegin(), properties.cend(), [](ir::AstNode *prop) {
            return prop->IsMethodDefinition() && prop->AsMethodDefinition()->IsConstructor();
        })) {
        return;
    }

    if ((modifiers & ir::ClassDefinitionModifiers::ANONYMOUS) != 0) {
        return;
    }

    auto *method_def = BuildImplicitConstructor(ir::ClassDefinitionModifiers::SET_CTOR_ID, start_loc);
    properties.push_back(method_def);

    ASSERT(Binder()->GetScope()->IsClassScope());
    auto class_ctx = binder::LexicalScope<binder::LocalScope>::Enter(
        Binder(), Binder()->GetScope()->AsClassScope()->StaticMethodScope());
    auto [_, var] = Binder()->NewVarDecl<binder::FunctionDecl>(method_def->Start(), Allocator(),
                                                               method_def->Id()->Name(), method_def);
    (void)_;
    var->AddFlag(binder::VariableFlags::METHOD);
    method_def->Function()->Id()->SetVariable(var);
}

util::StringView ETSParser::FormInterfaceOrEnumDeclarationIdBinding(ir::Identifier *id)
{
    return id->Name();
}

ir::Expression *ETSParser::ParsePotentialExpressionSequence(ir::Expression *expr, ExpressionParseFlags flags)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA &&
        (flags & ExpressionParseFlags::ACCEPT_COMMA) != 0 && (flags & ExpressionParseFlags::IN_FOR) != 0U) {
        return ParseSequenceExpression(expr, (flags & ExpressionParseFlags::ACCEPT_REST) != 0);
    }

    return expr;
}

bool ETSParser::ParsePotentialNonNullExpression(ir::Expression **expression, const lexer::SourcePosition start_loc)
{
    if (expression == nullptr || Lexer()->GetToken().NewLine()) {
        return true;
    }

    const auto non_null_expr = AllocNode<ir::TSNonNullExpression>(*expression);
    non_null_expr->SetRange({start_loc, Lexer()->GetToken().End()});
    non_null_expr->SetParent(*expression);

    *expression = non_null_expr;

    Lexer()->NextToken();

    return false;
}

bool ETSParser::IsStructKeyword() const
{
    return (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT &&
            Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_STRUCT);
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *ETSParser::ParseExpression(ExpressionParseFlags flags)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_YIELD &&
        (flags & ExpressionParseFlags::DISALLOW_YIELD) == 0U) {
        ir::YieldExpression *yield_expr = ParseYieldExpression();

        return ParsePotentialExpressionSequence(yield_expr, flags);
    }

    ir::Expression *unary_expression_node = ParseUnaryOrPrefixUpdateExpression(flags);
    ir::Expression *assignment_expression = ParseAssignmentExpression(unary_expression_node, flags);

    if (Lexer()->GetToken().NewLine()) {
        return assignment_expression;
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA &&
        (flags & ExpressionParseFlags::ACCEPT_COMMA) != 0U && (flags & ExpressionParseFlags::IN_FOR) != 0U) {
        return ParseSequenceExpression(assignment_expression, (flags & ExpressionParseFlags::ACCEPT_REST) != 0U);
    }

    return assignment_expression;
}

void ETSParser::ParseTrailingBlock(ir::CallExpression *call_expr)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        call_expr->SetIsTrailingBlockInNewLine(Lexer()->GetToken().NewLine());
        call_expr->SetTrailingBlock(ParseBlockStatement());
    }
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
        case lexer::TokenType::KEYW_ABSTRACT:
        case lexer::TokenType::KEYW_INTERFACE: {
            return;
        }
        default: {
            ThrowSyntaxError("Unexpected token.");
        }
    }
}

//================================================================================================//
//  Methods to create AST node(s) from the specified string (part of valid ETS-code!)
//================================================================================================//

ir::Statement *ETSParser::CreateStatement(std::string_view const source_code, std::string_view const file_name)
{
    util::UString source {source_code, Allocator()};
    auto const isp = InnerSourceParser(this);
    auto const lexer = InitLexer({file_name, source.View().Utf8()});

    lexer::SourcePosition const start_loc = lexer->GetToken().Start();
    lexer->NextToken();

    auto statements = ParseStatementList(StatementParsingFlags::STMT_GLOBAL_LEXICAL);
    auto const statement_number = statements.size();

    if (statement_number == 0U) {
        return nullptr;
    }

    if (statement_number == 1U) {
        return statements[0U];
    }

    auto const local_ctx = binder::LexicalScope<binder::LocalScope>(Binder());
    auto *const scope = local_ctx.GetScope();

    auto *const block_stmt = AllocNode<ir::BlockStatement>(Allocator(), scope, std::move(statements));
    scope->BindNode(block_stmt);
    block_stmt->SetRange({start_loc, lexer->GetToken().End()});

    return block_stmt;
}

ArenaVector<ir::Statement *> ETSParser::CreateStatements(std::string_view const source_code,
                                                         std::string_view const file_name)
{
    util::UString source {source_code, Allocator()};
    auto const isp = InnerSourceParser(this);
    auto const lexer = InitLexer({file_name, source.View().Utf8()});

    lexer->NextToken();
    return ParseStatementList(StatementParsingFlags::STMT_GLOBAL_LEXICAL);
}

ir::MethodDefinition *ETSParser::CreateMethodDefinition(ir::ModifierFlags modifiers, std::string_view const source_code,
                                                        std::string_view const file_name)
{
    util::UString source {source_code, Allocator()};
    auto const isp = InnerSourceParser(this);
    auto const lexer = InitLexer({file_name, source.View().Utf8()});

    auto const start_loc = Lexer()->GetToken().Start();
    Lexer()->NextToken();

    if (IsClassMethodModifier(Lexer()->GetToken().Type())) {
        modifiers |= ParseClassMethodModifiers(false);
    }

    ir::MethodDefinition *method_definition = nullptr;
    auto *method_name = ExpectIdentifier();

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS ||
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        method_definition = ParseClassMethodDefinition(method_name, modifiers);
        method_definition->SetStart(start_loc);
    }

    return method_definition;
}

ir::Expression *ETSParser::CreateExpression(ExpressionParseFlags const flags, std::string_view const source_code,
                                            std::string_view const file_name)
{
    util::UString source {source_code, Allocator()};
    auto const isp = InnerSourceParser(this);
    auto const lexer = InitLexer({file_name, source.View().Utf8()});

    lexer->NextToken();
    return ParseExpression(flags);
}

ir::TypeNode *ETSParser::CreateTypeAnnotation(TypeAnnotationParsingOptions *options, std::string_view const source_code,
                                              std::string_view const file_name)
{
    util::UString source {source_code, Allocator()};
    auto const isp = InnerSourceParser(this);
    auto const lexer = InitLexer({file_name, source.View().Utf8()});

    lexer->NextToken();
    return ParseTypeAnnotation(options);
}

//================================================================================================//
//  ExternalSourceParser class
//================================================================================================//

ExternalSourceParser::ExternalSourceParser(ETSParser *parser, Program *new_program)
    : parser_(parser),
      saved_program_(parser_->GetProgram()),
      saved_lexer_(parser_->Lexer()),
      saved_top_scope_(parser_->Binder()->TopScope())
{
    parser_->SetProgram(new_program);
    parser_->GetContext().SetProgram(new_program);
}

ExternalSourceParser::~ExternalSourceParser()
{
    parser_->SetLexer(saved_lexer_);
    parser_->SetProgram(saved_program_);
    parser_->GetContext().SetProgram(saved_program_);
    parser_->Binder()->ResetTopScope(saved_top_scope_);
}

//================================================================================================//
//  InnerSourceParser class
//================================================================================================//

InnerSourceParser::InnerSourceParser(ETSParser *parser)
    : parser_(parser),
      saved_lexer_(parser_->Lexer()),
      saved_source_code_(parser_->GetProgram()->SourceCode()),
      saved_source_file_(parser_->GetProgram()->SourceFile()),
      saved_source_file_path_(parser_->GetProgram()->SourceFilePath())
{
}

InnerSourceParser::~InnerSourceParser()
{
    parser_->SetLexer(saved_lexer_);
    parser_->GetProgram()->SetSource(saved_source_code_, saved_source_file_, saved_source_file_path_);
}
}  // namespace panda::es2panda::parser
#undef USE_UNIX_SYSCALL
