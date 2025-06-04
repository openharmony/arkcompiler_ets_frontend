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

#include <iostream>
#include <string>
#include "util.h"
#include "public/es2panda_lib.h"

// NOLINTBEGIN

static es2panda_Impl *impl = nullptr;
static constexpr int NUMBER_OF_COMPILATION = 5;

static std::string source = R"(
function foo() {
    main();
}
let c: number = 2;
function main() {
    foo();
    console.log(c);
    let b: number = c + 1;
    let a: () => void = foo;
    let d: number = b + 1;
}
class A {
    goo() {
        foo();
    }
}
)";

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
    es2panda_Config *config;
    es2panda_Context *context;

    for (int i = 0; i < NUMBER_OF_COMPILATION; i++) {
        config = impl->CreateConfig(argc - 1, args);
        context = impl->CreateContextFromString(config, source.data(), argv[argc - 1]);
        if (context == nullptr) {
            return TEST_ERROR_CODE;
        }

        impl->ProceedToState(context, ES2PANDA_STATE_CHECKED);
        CheckForErrors("CHECKED", context);

        // Run es2panda on new source(src dump)
        source = std::string(
            impl->AstNodeDumpEtsSrcConst(context, impl->ProgramAst(context, impl->ContextProgram(context))));
        std::cout << source << std::endl;
        impl->ProceedToState(context, ES2PANDA_STATE_BIN_GENERATED);
        if (impl->ContextState(context) == ES2PANDA_STATE_ERROR) {
            impl->DestroyContext(context);
            impl->DestroyConfig(config);
            return TEST_ERROR_CODE;
        }
        impl->DestroyContext(context);
        impl->DestroyConfig(config);
    }

    return 0;
}

// NOLINTEND
