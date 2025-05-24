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

#include <gtest/gtest.h>
#include "lsp/include/refactor_provider.h"
#include "lsp/include/refactors/convert_function.h"
#include "lsp/include/types.h"
#include "lsp_api_test.h"  // LSPAPITests header file

namespace {
class RefactorProviderRegistrationTest : public LSPAPITests {};

TEST(RefactorProviderRegistrationTest, RegistersConvertFunctionRefactor)
{
    const auto &provider = ark::es2panda::lsp::RefactorProvider::Instance();
    const auto &refactors = provider.GetRefactors();

    auto it = refactors.find("ConvertFunctionRefactor");

    ASSERT_NE(it, refactors.end()) << "ConvertFunctionRefactor was not registered in RefactorProvider.";
}
}  // namespace