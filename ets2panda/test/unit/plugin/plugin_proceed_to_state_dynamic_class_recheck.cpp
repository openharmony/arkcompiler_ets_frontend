/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <iostream>
#include <ostream>
#include <string>
#include <cstring>

#include "os/library_loader.h"

#include "public/es2panda_lib.h"
#include "util.h"

// NOLINTBEGIN
static std::string source = R"(
class $jscall {}
class $jsnew {}
)";

static es2panda_Impl *impl = nullptr;
es2panda_Context *context = nullptr;
static es2panda_AstNode *targetAfterCheck = nullptr;
static es2panda_AstNode *targetAfterReCheck = nullptr;

static void SetTargetClass(es2panda_AstNode *ast, void *inputCtx)
{
    auto ctx = reinterpret_cast<es2panda_Context *>(inputCtx);
    if (!impl->IsClassDeclaration(ast)) {
        return;
    }

    auto *def = impl->ClassDeclarationDefinition(ctx, ast);
    if (def == nullptr) {
        return;
    }

    auto *ident = impl->ClassDefinitionIdent(ctx, def);
    if (ident == nullptr) {
        return;
    }
    auto name = impl->IdentifierName(ctx, ident);
    if (std::string(name) == "$jscall") {
        if (targetAfterCheck == nullptr) {
            targetAfterCheck = ast;
            return;
        }
        targetAfterReCheck = ast;
    }
}

int main(int argc, char **argv)
{
    if (argc < MIN_ARGC) {
        return INVALID_ARGC_ERROR_CODE;
    }

    if (GetImpl() == nullptr) {
        return NULLPTR_IMPL_ERROR_CODE;
    }
    impl = GetImpl();
    std::cout << "LOAD SUCCESS" << std::endl;

    const char **args = const_cast<const char **>(&(argv[1]));
    auto config = impl->CreateConfig(argc - 1, args);
    context = impl->CreateContextFromString(config, source.data(), argv[argc - 1]);
    if (context == nullptr) {
        std::cerr << "FAILED TO CREATE CONTEXT" << std::endl;
        return NULLPTR_CONTEXT_ERROR_CODE;
    }

    impl->ProceedToState(context, ES2PANDA_STATE_CHECKED);
    auto *program = impl->ContextProgram(context);
    auto *ast = impl->ProgramAst(context, program);
    impl->AstNodeForEach(ast, SetTargetClass, context);
    if (targetAfterCheck == nullptr) {
        std::cerr << "FAILED TO GET NODE" << std::endl;
        return NULLPTR_CONTEXT_ERROR_CODE;
    }
    size_t len;
    auto **stmts = impl->BlockStatementStatements(context, ast, &len);
    auto *newStmts = static_cast<es2panda_AstNode **>(impl->AllocMemory(context, len + 1, sizeof(es2panda_AstNode *)));
    for (size_t idx = 0; idx < len; ++idx) {
        if (stmts[idx] != targetAfterCheck) {
            newStmts[idx] = stmts[idx];
            continue;
        }

        auto *def = impl->ClassDeclarationDefinition(context, targetAfterCheck);
        targetAfterCheck = impl->UpdateClassDeclaration(context, targetAfterCheck, def);
        newStmts[idx] = targetAfterCheck;
    }
    impl->BlockStatementSetStatements(context, ast, newStmts, len);

    impl->AstNodeRecheck(context, ast);
    impl->AstNodeForEach(ast, SetTargetClass, context);
    // the orignal class declaration named "jscall" or "jsnew" should be removed.
    int res = targetAfterReCheck == nullptr ? 0 : TEST_ERROR_CODE;
    impl->DestroyConfig(config);

    return res;
}

// NOLINTEND
