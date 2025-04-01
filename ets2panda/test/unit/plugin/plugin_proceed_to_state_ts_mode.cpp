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

// Test case: run plugin in .ts mode should not crash with Segfault.

#include <iostream>

#include "public/es2panda_lib.h"
#include "util.h"

// NOLINTBEGIN

static es2panda_Impl *impl = nullptr;
static const char *source = "console.log('asjflajfla')";

int main(int argc, char **argv)
{
    if (argc < MIN_ARGC) {
        return INVALID_ARGC_ERROR_CODE;
    }

    const char *args[] = {argv[1], "--extension=ts", argv[argc - 1]};  // es2panda path, --extension=ts, file path

    if (GetImpl() == nullptr) {
        return NULLPTR_IMPL_ERROR_CODE;
    }
    impl = GetImpl();

    auto config = impl->CreateConfig(3, args);
    auto context = impl->CreateContextFromString(config, source, args[2]);
    auto result_code = 0;

    impl->ProceedToState(context, ES2PANDA_STATE_CHECKED);
    if (impl->ContextState(context) != ES2PANDA_STATE_ERROR) {
        result_code = TEST_ERROR_CODE;
    }

    impl->DestroyContext(context);
    impl->DestroyConfig(config);
    return result_code;
}

// NOLINTEND
