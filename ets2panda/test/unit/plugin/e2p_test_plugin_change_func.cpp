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

// No linting for pure C file
// NOLINTBEGIN

#include "public/es2panda_lib.h"
#include <algorithm>
#include <cstddef>
#include <iostream>

static es2panda_Impl const *impl = nullptr;
static const std::string mainName = "main";
static const std::string funcName1 = "foo";
static const std::string funcName2 = "goo";

extern "C" {
void e2p_test_plugin_change_func_Initialize()
{
    impl = es2panda_GetImpl(ES2PANDA_LIB_VERSION);
}

static void ChangeCall(es2panda_AstNode *node, void *arg)
{
    es2panda_Context *ctx = static_cast<es2panda_Context *>(arg);
    if (impl->IsCallExpression(node)) {
        auto *callee = impl->CallExpressionCallee(ctx, node);
        if (callee == nullptr || !impl->IsIdentifier(impl->CallExpressionCallee(ctx, node))) {
            return;
        }
        std::string name = impl->IdentifierName(ctx, callee);
        if (name == funcName1) {
            auto *memForIdent = static_cast<char *>(impl->AllocMemory(ctx, funcName2.size() + 1, 1));
            std::copy_n(funcName2.c_str(), funcName2.size() + 1, memForIdent);
            auto *newIdent = impl->CreateIdentifier1(ctx, memForIdent);
            impl->CallExpressionSetCallee(ctx, node, newIdent);
        }
    }
}

void e2p_test_plugin_change_func_AfterParse(es2panda_Context *ctx)
{
    auto *ast = impl->ProgramAst(ctx, impl->ContextProgram(ctx));
    std::cout << "Origin code (False Assert):" << std::endl;
    std::cout << impl->AstNodeDumpEtsSrcConst(ctx, ast) << std::endl;
    size_t n = 0;
    auto **statements = impl->BlockStatementStatementsConst(ctx, ast, &n);
    es2panda_AstNode *mainScriptFunc = nullptr;
    for (size_t i = 0; i < n; i++) {
        if (!impl->IsFunctionDeclaration(statements[i])) {
            continue;
        }
        auto *scriptFunc = impl->FunctionDeclarationFunction(ctx, statements[i]);
        if (scriptFunc != nullptr && impl->ScriptFunctionId(ctx, scriptFunc) != nullptr &&
            impl->IdentifierName(ctx, impl->ScriptFunctionId(ctx, scriptFunc)) == mainName) {
            mainScriptFunc = scriptFunc;
            break;
        }
    }
    if (mainScriptFunc == nullptr) {
        return;
    }
    impl->AstNodeForEach(mainScriptFunc, ChangeCall, ctx);
    std::cout << "Modified code (True Assert):" << std::endl;
    std::cout << impl->AstNodeDumpEtsSrcConst(ctx, ast) << std::endl;
}

void e2p_test_plugin_change_func_AfterCheck([[maybe_unused]] es2panda_Context *ctx) {}

void e2p_test_plugin_change_func_AfterLowerings([[maybe_unused]] es2panda_Context *ctx) {}
}

// NOLINTEND
