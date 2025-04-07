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
static int g_count = 4;
static std::string g_source = R"(
class A {
    x: number
    public y: number
    foo1() {}
    public foo2() {}
}
)";

bool Find(es2panda_AstNode *ast)
{
    if (g_impl->IsClassProperty(ast) &&
        strcmp(g_impl->IdentifierName(g_ctx, g_impl->ClassElementId(g_ctx, ast)), "x") == 0) {
        if (g_impl->ClassPropertyIsDefaultAccessModifierConst(g_ctx, ast)) {
            g_count--;
        }
    }
    if (g_impl->IsClassProperty(ast) &&
        strcmp(g_impl->IdentifierName(g_ctx, g_impl->ClassElementId(g_ctx, ast)), "y") == 0) {
        if (!g_impl->ClassPropertyIsDefaultAccessModifierConst(g_ctx, ast)) {
            g_count--;
        }
    }
    if (g_impl->IsMethodDefinition(ast) &&
        strcmp(g_impl->IdentifierName(g_ctx, g_impl->ClassElementId(g_ctx, ast)), "foo1") == 0) {
        if (g_impl->MethodDefinitionIsDefaultAccessModifierConst(g_ctx, ast)) {
            g_count--;
        }
    }
    if (g_impl->IsMethodDefinition(ast) &&
        strcmp(g_impl->IdentifierName(g_ctx, g_impl->ClassElementId(g_ctx, ast)), "foo2") == 0) {
        if (!g_impl->MethodDefinitionIsDefaultAccessModifierConst(g_ctx, ast)) {
            g_count--;
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
