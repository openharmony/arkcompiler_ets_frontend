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
#include <algorithm>
#include <cstring>

#include "public/es2panda_lib.h"
#include "compiler/lowering/util.h"

static struct es2panda_Impl const *impl = NULL;

void HasScope(es2panda_AstNode *ast, void *arg)
{
    es2panda_Context *ctx = reinterpret_cast<es2panda_Context *>(arg);
    auto scope = impl->AstNodeFindNearestScope(ctx, ast);
    if (scope != nullptr && impl->ScopeIsGlobalScope(scope)) {
        puts(impl->AstNodeDumpJSONConst(ctx, ast));
    }
}

extern "C" {
void e2p_test_plugin_after_bind_Initialize()
{
    impl = es2panda_GetImpl(ES2PANDA_LIB_VERSION);
}

void e2p_test_plugin_after_bind_AfterParse([[maybe_unused]] es2panda_Context *ctx) {}

void e2p_test_plugin_after_bind_AfterBind(es2panda_Context *ctx)
{
    es2panda_AstNode *ast = impl->ProgramAst(ctx, impl->ContextProgram(ctx));
    impl->AstNodeForEach(ast, HasScope, ctx);
}

void e2p_test_plugin_after_bind_AfterCheck([[maybe_unused]] es2panda_Context *ctx) {}

void e2p_test_plugin_after_bind__AfterLowerings([[maybe_unused]] es2panda_Context *ctx) {}
}
// NOLINTEND