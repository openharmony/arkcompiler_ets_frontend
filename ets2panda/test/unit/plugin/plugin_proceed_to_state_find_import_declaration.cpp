/**
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <cstddef>
#include <iostream>
#include <ostream>
#include <string>
#include <vector>
#include "public/es2panda_lib.h"
#include "os/library_loader.h"

// NOLINTBEGIN

static const char *LIBNAME = "es2panda-public";
static const int MIN_ARGC = 3;
static const int NULLPTR_IMPL_ERROR_CODE = 2;

static es2panda_Impl *impl = nullptr;
static std::vector<std::string> importDeclarationIdentifiers {};

es2panda_Impl *GetImpl()
{
    if (impl != nullptr) {
        return impl;
    }

    std::string soName = ark::os::library_loader::DYNAMIC_LIBRARY_PREFIX + std::string(LIBNAME) +
                         ark::os::library_loader::DYNAMIC_LIBRARY_SUFFIX;
    auto libraryRes = ark::os::library_loader::Load(soName);
    if (!libraryRes.HasValue()) {
        std::cout << "Error in load lib" << std::endl;
        return nullptr;
    }

    auto library = std::move(libraryRes.Value());
    auto getImpl = ark::os::library_loader::ResolveSymbol(library, "es2panda_GetImpl");
    if (!getImpl.HasValue()) {
        std::cout << "Error in load func get impl" << std::endl;
        return nullptr;
    }

    auto getImplFunc = reinterpret_cast<const es2panda_Impl *(*)(int)>(getImpl.Value());
    if (getImplFunc != nullptr) {
        return const_cast<es2panda_Impl *>(getImplFunc(ES2PANDA_LIB_VERSION));
    }
    return nullptr;
}

void CheckForImportDeclaration(es2panda_AstNode *node, void *arg)
{
    auto *context = static_cast<es2panda_Context *>(arg);
    if (!impl->IsImportDeclaration(node) && !impl->IsETSImportDeclaration(node)) {
        return;
    }
    size_t n = 0;
    auto specifiers = impl->ImportDeclarationSpecifiers(context, node, &n);
    for (size_t i = 0; i < n; i++) {
        if (!impl->IsImportSpecifier(specifiers[i])) {
            std::cout << impl->IsImportSpecifier(specifiers[i]) << std::endl;
            continue;
        }
        auto id = impl->ImportSpecifierLocal(context, specifiers[i]);
        if (id == nullptr) {
            id = impl->ImportSpecifierImported(context, specifiers[i]);
        }
        importDeclarationIdentifiers.push_back(std::string(impl->IdentifierName(context, id)));
    }
    for (auto i : importDeclarationIdentifiers) {
        std::cout << "Imported name: \"" << i << "\"" << std::endl;
    }
}

void CheckForImportIdentifier(es2panda_AstNode *node, void *arg)
{
    auto *context = static_cast<es2panda_Context *>(arg);
    if (!impl->IsIdentifier(node) || (impl->AstNodeParent(context, node) != nullptr &&
                                      impl->IsImportSpecifier(impl->AstNodeParent(context, node)))) {
        return;
    }
    if (std::find(importDeclarationIdentifiers.begin(), importDeclarationIdentifiers.end(),
                  std::string(impl->IdentifierName(context, node))) == importDeclarationIdentifiers.end()) {
        return;
    }
    std::cout << "Imported identifier found: \"" << std::string(impl->IdentifierName(context, node)) << "\""
              << std::endl;
    auto variable = impl->AstNodeVariableConst(context, node);
    if (variable == nullptr) {
        std::cout << "[ERROR] Import specifier has no assigned variable" << std::endl;
        return;
    }
    auto decl = impl->VariableDeclaration(context, variable);
    if (decl == nullptr) {
        std::cout << "[ERROR] Variable has no assigned declaration" << std::endl;
        return;
    }
    auto declNode = impl->DeclNode(context, decl);
    if (declNode == nullptr) {
        std::cout << "[ERROR] Declaration has no assigned node" << std::endl;
        return;
    }
    std::cout << std::endl << "JSON dump of real declaration" << std::endl;
    std::cout << impl->AstNodeDumpJSONConst(context, declNode) << std::endl << std::endl;
    std::cout << "Src dump of real declaration" << std::endl;
    std::cout << impl->AstNodeDumpEtsSrcConst(context, declNode) << std::endl;
}

void FindImportDeclarations(es2panda_Context *context, es2panda_AstNode *ast)
{
    impl->AstNodeForEach(ast, CheckForImportDeclaration, context);
    impl->AstNodeForEach(ast, CheckForImportIdentifier, context);
}

void CheckForErrors(std::string StateName, es2panda_Context *context)
{
    if (impl->ContextState(context) == ES2PANDA_STATE_ERROR) {
        std::cout << "PROCEED TO " << StateName << " ERROR" << std::endl;
        std::cout << impl->ContextErrorMessage << std::endl;
    } else {
        std::cout << "PROCEED TO " << StateName << " SUCCESS" << std::endl;
    }
}

int main(int argc, char **argv)
{
    if (argc < MIN_ARGC) {
        return 1;
    }

    if (GetImpl() == nullptr) {
        return NULLPTR_IMPL_ERROR_CODE;
    }
    impl = GetImpl();
    std::cout << "LOAD SUCCESS" << std::endl;

    const char **args = const_cast<const char **>(&(argv[1]));
    auto src = std::string("import { PI } from \"std/math\"\n\nconsole.log(PI);");
    auto config = impl->CreateConfig(argc - 1, args);
    auto context = impl->CreateContextFromString(config, src.c_str(), argv[argc - 1]);
    if (context != nullptr) {
        std::cout << "CREATE CONTEXT SUCCESS" << std::endl;
    }

    impl->ProceedToState(context, ES2PANDA_STATE_PARSED);
    CheckForErrors("PARSE", context);

    impl->ProceedToState(context, ES2PANDA_STATE_SCOPE_INITED);
    CheckForErrors("SCOPE INITED", context);

    impl->ProceedToState(context, ES2PANDA_STATE_CHECKED);
    CheckForErrors("CHECKED", context);

    auto ast = impl->ProgramAst(impl->ContextProgram(context));
    FindImportDeclarations(context, ast);

    impl->ProceedToState(context, ES2PANDA_STATE_LOWERED);
    CheckForErrors("LOWERED", context);

    impl->ProceedToState(context, ES2PANDA_STATE_ASM_GENERATED);
    CheckForErrors("ASM", context);

    impl->ProceedToState(context, ES2PANDA_STATE_BIN_GENERATED);
    CheckForErrors("BIN", context);
    impl->DestroyConfig(config);

    return 0;
}

// NOLINTEND
