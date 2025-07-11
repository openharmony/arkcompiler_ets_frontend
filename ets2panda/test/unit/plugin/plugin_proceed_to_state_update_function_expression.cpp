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

#include <cstring>
#include <algorithm>
#include "util.h"

// NOLINTBEGIN

static es2panda_Impl *g_impl = nullptr;
static es2panda_Context *g_ctx = nullptr;
static std::string g_source = R"(
class A {
    get x() { return 1; }
}
let add = () => { return 1;}
)";
static int g_count = 2;

bool Find(es2panda_AstNode *ast)
{
    if (g_impl->IsArrowFunctionExpression(ast)) {
        auto scriptFunc = g_impl->ArrowFunctionExpressionFunction(g_ctx, ast);
        auto newFunction = g_impl->UpdateArrowFunctionExpression(g_ctx, ast, scriptFunc);
        auto parent = g_impl->AstNodeParent(g_ctx, ast);
        g_impl->AstNodeSetParent(g_ctx, newFunction, parent);
        g_impl->ClassElementSetValue(g_ctx, parent, newFunction);
        std::string str(g_impl->AstNodeDumpEtsSrcConst(g_ctx, parent));
        if (str.find("add = (() => {") != std::string::npos) {
            g_count--;
        }
    }
    if (g_impl->IsFunctionExpression(ast)) {
        auto scriptFunc = g_impl->FunctionExpressionFunction(g_ctx, ast);
        if (strcmp(g_impl->IdentifierName(g_ctx, g_impl->ScriptFunctionId(g_ctx, scriptFunc)), "x") == 0) {
            auto newFunction = g_impl->UpdateFunctionExpression(g_ctx, ast, scriptFunc);
            auto parent = g_impl->AstNodeParent(g_ctx, ast);
            g_impl->AstNodeSetParent(g_ctx, newFunction, parent);
            g_impl->ClassElementSetValue(g_ctx, parent, newFunction);
            std::string str(g_impl->AstNodeDumpEtsSrcConst(g_ctx, ast));
            if (str.find("() {\n  return 1;") != std::string::npos) {
                g_count--;
            }
        }
    }

    return g_count == 0;
}

int main(int argc, char **argv)
{
    if (argc < MIN_ARGC) {
        return 1;
    }
    if (GetImpl() == nullptr) {
        return NULLPTR_IMPL_ERROR_CODE;
    }
    g_impl = GetImpl();
    const char **args = const_cast<const char **>(&(argv[1]));
    auto config = g_impl->CreateConfig(argc - 1, args);
    g_ctx = g_impl->CreateContextFromString(config, g_source.data(), argv[argc - 1]);
    if (g_ctx == nullptr) {
        return NULLPTR_CONTEXT_ERROR_CODE;
    }

    g_impl->ProceedToState(g_ctx, ES2PANDA_STATE_PARSED);
    if (g_impl->ContextState(g_ctx) == ES2PANDA_STATE_ERROR) {
        return PROCEED_ERROR_CODE;
    }

    auto ast = g_impl->ProgramAst(g_ctx, g_impl->ContextProgram(g_ctx));
    if (!g_impl->AstNodeIsAnyChildConst(g_ctx, ast, Find)) {
        return TEST_ERROR_CODE;
    }

    g_impl->ProceedToState(g_ctx, ES2PANDA_STATE_BIN_GENERATED);
    if (g_impl->ContextState(g_ctx) == ES2PANDA_STATE_ERROR) {
        return PROCEED_ERROR_CODE;
    }

    g_impl->DestroyContext(g_ctx);
    g_impl->DestroyConfig(config);

    return 0;
}

// NOLINTEND
