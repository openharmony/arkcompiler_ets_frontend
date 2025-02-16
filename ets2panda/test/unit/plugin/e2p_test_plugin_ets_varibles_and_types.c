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
#include <string.h>
#include <stdlib.h>

#include "public/es2panda_lib.h"

static struct es2panda_Impl const *impl = NULL;
static int numberOfFunctions = 10000;
static es2panda_Context *globalContext = NULL;
static es2panda_AstNode *exampleFunc = NULL;

void e2p_test_plugin_ets_varibles_and_types_Initialize()
{
    impl = es2panda_GetImpl(ES2PANDA_LIB_VERSION);
}

void e2p_test_plugin_ets_varibles_and_types_AfterParse(es2panda_Context *ctx) {}

void printVarInfo(es2panda_Context *ctx, es2panda_Variable *var)
{
    if (var == NULL) {
        return;
    }
    puts("Identifier is variable");
    es2panda_Type *varType = impl->VariableTsTypeConst(ctx, var);
    if (varType != NULL) {
        printf("Type of variable: %s\n", impl->TypeToStringConst(ctx, varType));
    }
    es2panda_Declaration *varDeclaration = impl->VariableDeclaration(ctx, var);
    if (varDeclaration != NULL) {
        puts("Variable has declaration:");
        es2panda_AstNode *declNode = impl->DeclNode(ctx, varDeclaration);
        if (declNode != NULL) {
            puts(impl->AstNodeDumpEtsSrcConst(ctx, declNode));
            puts("Declaration Node JSON:");
            puts(impl->AstNodeDumpJSONConst(ctx, declNode));
        }
    }
}

void printScopeDeclarations(es2panda_Context *ctx, es2panda_Scope *scope)
{
    if (scope == NULL) {
        return;
    }
    puts("Node has Scope");
    es2panda_AstNode *scopeNode = impl->ScopeNode(ctx, scope);
    if (scopeNode != NULL) {
        puts("Scope has bind node:");
        puts(impl->AstNodeDumpEtsSrcConst(ctx, scopeNode));
    }
    size_t *declsNums = impl->AllocMemory(ctx, 1, sizeof(size_t));
    es2panda_Declaration **scopeDecls = impl->ScopeDecls(ctx, scope, declsNums);
    if (*declsNums > 0) {
        puts("Declarations in this scope:");
        for (int i = 0; i < *declsNums; i++) {
            printf("Declaration №%d:\n", i);
            es2panda_AstNode *declNode = impl->DeclNode(ctx, scopeDecls[i]);
            if (declNode != NULL) {
                puts("Declaration Node:");
                puts(impl->AstNodeDumpEtsSrcConst(ctx, declNode));
                puts("Declaration Node JSON:");
                puts(impl->AstNodeDumpJSONConst(ctx, declNode));
            }
        }
    }
}

static void FindAllVaribles(es2panda_AstNode *node, void *arg)
{
    es2panda_Context *ctx = arg;
    puts("-------------------------------------");
    puts("Node Src:");
    puts(impl->AstNodeDumpEtsSrcConst(ctx, node));
    puts("---------");
    if (impl->IsIdentifier(node)) {
        puts("Node is Identifier");
        puts("Name:");
        puts(impl->IdentifierName(ctx, node));
        es2panda_AstNode *parent = impl->AstNodeParent(ctx, node);
        if (parent != NULL) {
            puts("Parent Node:");
            puts(impl->AstNodeDumpEtsSrcConst(ctx, parent));
            puts("---------");
            puts("Parent JSON:");
            puts(impl->AstNodeDumpJSONConst(ctx, parent));
            puts("---------");
        }
        puts("---------");
        es2panda_Variable *var = impl->AstNodeVariableConst(ctx, node);
        printVarInfo(ctx, var);
        puts("---------");
        if (impl->AstNodeIsScopeBearerConst(ctx, node)) {
            es2panda_Scope *scope = impl->AstNodeScopeConst(ctx, node);
            printScopeDeclarations(ctx, scope);
        }
    } else {
        if (impl->AstNodeIsScopeBearerConst(ctx, node)) {
            es2panda_Scope *scope = impl->AstNodeScopeConst(ctx, node);
            printScopeDeclarations(ctx, scope);
        }
    }
    puts("---------");
    puts("Node JSON:");
    puts(impl->AstNodeDumpJSONConst(ctx, node));
    puts("-------------------------------------");
}

void e2p_test_plugin_ets_varibles_and_types_AfterCheck(es2panda_Context *ctx)
{
    globalContext = ctx;
    es2panda_AstNode *ast = impl->ProgramAst(ctx, impl->ContextProgram(ctx));
    impl->AstNodeForEach(ast, FindAllVaribles, ctx);
}

void e2p_test_plugin_ets_varibles_and_types_AfterLowerings(es2panda_Context *ctx) {}

// NOLINTEND
