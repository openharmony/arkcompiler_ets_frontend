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

// No linting for pure C file
// NOLINTBEGIN

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <algorithm>
#include <cstring>

#include "public/es2panda_lib.h"

static struct es2panda_Impl const *impl = NULL;
static int numberOfFunctions = 10000;
static es2panda_Context *globalContext = NULL;
static es2panda_AstNode *exampleFunc = NULL;

extern "C" {
void e2p_test_plugin_ets_benchmark_with_checker_func_test_Initialize()
{
    impl = es2panda_GetImpl(ES2PANDA_LIB_VERSION);
}

void FindExampleFunc(es2panda_AstNode *ast)
{
    if (impl->IsMethodDefinition(ast)) {
        es2panda_AstNode *func = impl->MethodDefinitionFunction(globalContext, ast);
        if (func == NULL) {
            return;
        }
        es2panda_AstNode *identifier = impl->ScriptFunctionId(globalContext, func);
        if (identifier == NULL) {
            return;
        }
        if (strcmp(impl->IdentifierName(globalContext, identifier), "fooExample") == 0) {
            exampleFunc = func;
        }
    }
}

es2panda_AstNode *CreateNewFunction(int num, es2panda_Context *ctx, es2panda_Scope *methodScope)
{
    auto funcNameStr = std::string("foo");
    funcNameStr += std::to_string(num);
    char *funcName = static_cast<char *>(impl->AllocMemory(ctx, funcNameStr.length() + 1, sizeof(char)));
    std::copy_n(funcNameStr.c_str(), funcNameStr.length() + 1, funcName);

    es2panda_AstNode *body = impl->CreateBlockStatement0(ctx, NULL, 0);
    es2panda_Scope *scope = impl->ETSCheckerCopyParams(ctx, NULL, 0, NULL, 0);
    es2panda_AstNode *returnType = impl->CreateETSPrimitiveType0(ctx, PRIMITIVE_TYPE_VOID);
    es2panda_AstNode *func = impl->ETSCheckerCreateMethod(ctx, funcName, MODIFIER_FLAGS_NONE,
                                                          SCRIPT_FUNCTION_FLAGS_NONE, NULL, 0, scope, returnType, body);
    impl->AstNodeSetParent(ctx, returnType, impl->MethodDefinitionFunction(ctx, func));

    es2panda_Declaration *decl = impl->CreateFunctionDecl0(ctx, funcName, func);
    es2panda_Variable *funcVariable = impl->CreateLocalVariable0(ctx, decl, (uint64_t)1U << 28U);
    impl->VariableAddFlag(ctx, funcVariable, (uint64_t)1U << 2U);
    impl->VariableSetScope(ctx, funcVariable, methodScope);
    impl->AstNodeSetVariable(ctx, impl->ClassElementId(ctx, func), funcVariable);
    impl->AstNodeSetVariable(ctx, impl->ScriptFunctionId(ctx, impl->MethodDefinitionFunction(ctx, func)), funcVariable);

    return func;
}

void CreateNewFunctions(es2panda_Context *ctx, es2panda_AstNode *ast)
{
    impl->AstNodeIterateConst(ctx, ast, FindExampleFunc);
    puts(impl->AstNodeDumpJSONConst(ctx, impl->ScriptFunctionId(ctx, exampleFunc)));
    es2panda_Variable *scriptFuncVar =
        const_cast<es2panda_Variable *>(impl->AstNodeVariableConst(ctx, impl->ScriptFunctionId(ctx, exampleFunc)));
    es2panda_Scope *method_Scope = impl->VariableGetScopeConst(ctx, scriptFuncVar);
    puts(impl->AstNodeDumpJSONConst(ctx, impl->DeclNode(ctx, impl->VariableDeclaration(ctx, scriptFuncVar))));
    for (int i = 0; i < numberOfFunctions; i++) {
        es2panda_AstNode *func = CreateNewFunction(i, ctx, method_Scope);
        impl->ClassDefinitionAddProperties(ctx, ast, &func, 1);
        impl->AstNodeSetParent(ctx, func, ast);
    }
}

void FindClass(es2panda_AstNode *ast)
{
    if (impl->IsClassDeclaration(ast)) {
        es2panda_AstNode *definition = impl->ClassDeclarationDefinition(globalContext, ast);
        if (definition == NULL) {
            return;
        }
        es2panda_AstNode *identifier = impl->ClassDefinitionIdent(globalContext, definition);
        if (identifier == NULL) {
            return;
        }
        if (strcmp(impl->IdentifierName(globalContext, identifier), "GoodGreeter") == 0) {
            CreateNewFunctions(globalContext, definition);
        }
    }
}

void e2p_test_plugin_ets_benchmark_with_checker_func_test_AfterParse([[maybe_unused]] es2panda_Context *ctx) {}

void e2p_test_plugin_ets_benchmark_with_checker_func_test_AfterCheck(es2panda_Context *ctx)
{
    globalContext = ctx;
    es2panda_AstNode *ast = impl->ProgramAst(impl->ContextProgram(ctx));
    impl->AstNodeIterateConst(ctx, ast, FindClass);
    puts(impl->AstNodeDumpEtsSrcConst(ctx, ast));
}

void e2p_test_plugin_ets_benchmark_with_checker_func_test_AfterLowerings([[maybe_unused]] es2panda_Context *ctx) {}
}

// NOLINTEND
