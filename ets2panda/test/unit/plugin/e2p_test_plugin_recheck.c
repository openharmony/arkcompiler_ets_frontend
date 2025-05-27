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

// No linting for pure C file
// NOLINTBEGIN

#include <stddef.h>
#include <stdlib.h>

#include "public/es2panda_lib.h"

static struct es2panda_Impl const *impl = NULL;

void e2p_test_plugin_recheck_Initialize()
{
    impl = es2panda_GetImpl(ES2PANDA_LIB_VERSION);
}

void e2p_test_plugin_recheck_AfterCheck(es2panda_Context *ctx)
{
    if (impl->IsAnyError(ctx)) {
        exit(0);
    }
    es2panda_AstNode *ast = impl->ProgramAst(ctx, impl->ContextProgram(ctx));
    impl->AstNodeRecheck(ctx, ast);
}

// NOLINTEND