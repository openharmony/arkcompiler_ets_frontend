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

#include <algorithm>
#include <cstddef>
#include <iostream>
#include <ostream>
#include <string>
#include <cstring>
#include <vector>
#include "util.h"
#include "public/es2panda_lib.h"

// NOLINTBEGIN

static es2panda_Impl *impl = nullptr;

static bool NotNullAndPresentsInFoundAll(es2panda_AstNode *current, es2panda_AstNode **all, size_t all_len)
{
    if (current == nullptr || all == nullptr) {
        return false;
    }

    for (size_t i = 0; i < all_len; ++i) {
        if (current == all[i]) {
            return true;
        }
    }

    return false;
}

static int TestFindMethodDeclByName(es2panda_Context *context)
{
    auto program = impl->ContextProgram(context);
    auto Ast = impl->ProgramAst(context, program);

    size_t len = 0;
    es2panda_AstNode **all_found = impl->AllDeclarationsByNameFromNode(context, Ast, "goo", &len);
    es2panda_AstNode *found = impl->FirstDeclarationByNameFromNode(context, Ast, "goo");
    if (!NotNullAndPresentsInFoundAll(found, all_found, len)) {
        std::cerr << "CANT FIND METHOD IN AST: goo" << std::endl;
        return TEST_ERROR_CODE;
    }

    std::vector<std::string> names = {"too", "foo", "goo"};
    for (auto &name : names) {
        all_found = impl->AllDeclarationsByNameFromProgram(context, program, name.c_str(), &len);
        found = impl->FirstDeclarationByNameFromProgram(context, program, name.c_str());
        if (!NotNullAndPresentsInFoundAll(found, all_found, len)) {
            std::cerr << "CANT FIND METHOD IN PROGRAM: " << name << std::endl;
            return TEST_ERROR_CODE;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    if (argc < MIN_ARGC) {
        return 1;
    }

    if (GetImpl() == nullptr) {
        return NULLPTR_IMPL_ERROR_CODE;
    }
    impl = GetImpl();
    const char **args = const_cast<const char **>(&(argv[1]));
    auto config = impl->CreateConfig(argc - 1, args);
    auto context = impl->CreateContextFromFile(config, argv[argc - 1]);
    if (context == nullptr) {
        return NULLPTR_CONTEXT_ERROR_CODE;
    }

    impl->ProceedToState(context, ES2PANDA_STATE_PARSED);
    CheckForErrors("PARSE", context);

    impl->ProceedToState(context, ES2PANDA_STATE_BOUND);
    CheckForErrors("BOUND", context);

    int result = TestFindMethodDeclByName(context);

    impl->DestroyContext(context);
    impl->DestroyConfig(config);

    return result;
}

// NOLINTEND
