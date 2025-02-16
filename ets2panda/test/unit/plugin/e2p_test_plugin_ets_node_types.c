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

#include "public/es2panda_lib.h"

static struct es2panda_Impl const *impl = NULL;

void e2p_test_plugin_ets_node_types_Initialize()
{
    impl = es2panda_GetImpl(ES2PANDA_LIB_VERSION);
}

void DumpEtsNodesWithTypes(es2panda_AstNode *node, void *arg)
{
    es2panda_Context *ctx = arg;

    if (impl->AstNodeIsTypedConst(ctx, node)) {
        es2panda_Type *type = (es2panda_Type *)impl->TypedTsTypeConst(ctx, node);
        if (type == NULL) {
            return;
        }
        printf("Type of node: %s\n", impl->TypeToStringConst(ctx, type));
        puts("---");
        puts(impl->AstNodeDumpEtsSrcConst(ctx, node));
        puts("---");
        puts(impl->AstNodeDumpJSONConst(ctx, node));
        puts("---");
    }
}

void TypeRelationTest(es2panda_Context *ctx)
{
    es2panda_TypeRelation *relation = impl->CreateTypeRelation(ctx);
    es2panda_Type *doubleType = impl->CreateDoubleType(ctx);
    es2panda_Type *doubleType1 = impl->CreateDoubleType(ctx);

    puts("Check assignment double to double type: ");
    if (impl->TypeRelationIsAssignableTo(ctx, relation, doubleType, doubleType1)) {
        puts("Conversion allowed");
    } else {
        puts("Conversion denied");
    }
}

void e2p_test_plugin_ets_node_types_AfterParse(es2panda_Context *ctx) {}

void e2p_test_plugin_ets_node_types_AfterCheck(es2panda_Context *ctx)
{
    puts("Node typecheck test:");
    puts("---------------------");
    es2panda_AstNode *ast = impl->ProgramAst(ctx, impl->ContextProgram(ctx));
    impl->AstNodeForEach(ast, DumpEtsNodesWithTypes, ctx);
    puts("---------------------");
    puts("");
    puts("Type relation test:");
    puts("---------------------");
    TypeRelationTest(ctx);
}

void e2p_test_plugin_ets_node_types_AfterLowerings(es2panda_Context *ctx) {}

// NOLINTEND
