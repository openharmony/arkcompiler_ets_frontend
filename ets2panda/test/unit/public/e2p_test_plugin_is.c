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

#include "public/es2panda_lib.h"

static struct es2panda_Impl const *impl = NULL;

void e2p_test_plugin_is_Initialize()
{
    puts("Hi there!");
    puts("---");
    impl = es2panda_GetImpl(ES2PANDA_LIB_VERSION);
}

static void IsIdentifier(es2panda_AstNode *node, void *arg)
{
    es2panda_Context *ctx = arg;
    if (impl->AstNodeIsExpression(ctx, node)) {
        puts("Found Expression:");
        puts(impl->AstNodeDumpJSON(ctx, node));
        puts("---");
    }
}

void e2p_test_plugin_is_AfterParse(es2panda_Context *ctx)
{
    puts("After parse:");
    puts("---");
    es2panda_AstNode *ast = impl->ProgramAst(impl->ContextProgram(ctx));
    impl->AstNodeForEach(ast, IsIdentifier, ctx);
}

void e2p_test_plugin_is_AfterCheck(es2panda_Context *ctx)
{
    puts("After check:");
    puts("---");
}

void e2p_test_plugin_is_AfterLowerings(es2panda_Context *ctx)
{
    puts("After lowerings:");
    puts("---");
}

// NOLINTEND
