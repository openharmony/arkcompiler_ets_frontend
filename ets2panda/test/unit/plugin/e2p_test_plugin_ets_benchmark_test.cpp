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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <cstring>

#include "public/es2panda_lib.h"

static struct es2panda_Impl const *impl = nullptr;
static int numberOfFunctions = 10000;
static es2panda_Context *globalContext = nullptr;

extern "C" {
void e2p_test_plugin_ets_benchmark_test_Initialize()
{
    impl = es2panda_GetImpl(ES2PANDA_LIB_VERSION);
}

es2panda_AstNode *CreateNewFunction(int num, es2panda_Context *ctx)
{
    auto funcNameStr = std::string("foo");
    funcNameStr += std::to_string(num);
    char *funcName = static_cast<char *>(impl->AllocMemory(ctx, funcNameStr.length() + 1, sizeof(char)));
    std::copy_n(funcNameStr.c_str(), funcNameStr.length() + 1, funcName);
    es2panda_AstNode *key = impl->CreateIdentifier1(ctx, funcName);
    es2panda_AstNode *body = impl->CreateBlockStatement(ctx, nullptr, 0);
    es2panda_AstNode *scriptFunction = impl->CreateScriptFunction(
        ctx, body,
        impl->CreateFunctionSignature(ctx, nullptr, nullptr, 0, impl->CreateETSPrimitiveType(ctx, PRIMITIVE_TYPE_VOID),
                                      false),
        SCRIPT_FUNCTION_FLAGS_NONE, MODIFIER_FLAGS_NONE);
    impl->AstNodeSetParent(ctx, body, scriptFunction);
    es2panda_AstNode *ident = impl->CreateIdentifier1(ctx, funcName);
    impl->ScriptFunctionSetIdent(ctx, scriptFunction, ident);
    impl->AstNodeSetParent(ctx, ident, scriptFunction);
    es2panda_AstNode *value = impl->CreateFunctionExpression(ctx, scriptFunction);
    impl->AstNodeSetParent(ctx, scriptFunction, value);

    es2panda_AstNode *func =
        impl->CreateMethodDefinition(ctx, METHOD_DEFINITION_KIND_METHOD, key, value, MODIFIER_FLAGS_NONE, false);
    impl->AstNodeSetParent(ctx, value, func);
    impl->AstNodeSetParent(ctx, key, func);
    return func;
}

void CreateNewFunctions(es2panda_Context *ctx, es2panda_AstNode *ast)
{
    for (int i = 0; i < numberOfFunctions; i++) {
        es2panda_AstNode *func = CreateNewFunction(i, ctx);
        impl->ClassDefinitionAddProperties(ctx, ast, &func, 1);
        impl->AstNodeSetParent(ctx, func, ast);
    }
}

void FindClass(es2panda_AstNode *ast)
{
    if (impl->IsClassDeclaration(ast)) {
        es2panda_AstNode *definition = impl->ClassDeclarationDefinition(globalContext, ast);
        if (definition == nullptr) {
            return;
        }
        es2panda_AstNode *identifier = impl->ClassDefinitionIdent(globalContext, definition);
        if (identifier == nullptr) {
            return;
        }
        if (strcmp(impl->IdentifierName(globalContext, identifier), "GoodGreeter") == 0) {
            CreateNewFunctions(globalContext, definition);
        }
    }
}

void e2p_test_plugin_ets_benchmark_test_AfterParse(es2panda_Context *ctx)
{
    globalContext = ctx;
    es2panda_AstNode *ast = impl->ProgramAst(ctx, impl->ContextProgram(ctx));
    impl->AstNodeIterateConst(ctx, ast, FindClass);
    puts(impl->AstNodeDumpEtsSrcConst(ctx, ast));
}

void e2p_test_plugin_ets_benchmark_test_AfterCheck([[maybe_unused]] es2panda_Context *ctx) {}

void e2p_test_plugin_ets_benchmark_test_AfterLowerings([[maybe_unused]] es2panda_Context *ctx) {}
}

// NOLINTEND
