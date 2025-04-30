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
#include <cstddef>
#include <string>
#include <vector>
#include "lsp_api_test.h"
#include "lsp/include/internal_api.h"
#include "lsp/include/api.h"
#include "public/es2panda_lib.h"

using ark::es2panda::lsp::Initializer;
namespace {

class LspGetSafeDeleteInfoTest : public LSPAPITests {};

TEST_F(LspGetSafeDeleteInfoTest, GetSafeDeleteInfoCase1)
{
    using ark::es2panda::public_lib::Context;

    std::vector<std::string> fileNames = {"firstFile.ets", "secondFile.ets"};
    std::vector<std::string> fileContents = {
        "const greet = (name: string) => {\n"
        "return 'Hello, ${name}!';\n};\n"
        "export default greet;\n",
        "import greet from \"./firstFile.ets\""};

    auto filePaths = CreateTempFile(fileNames, fileContents);
    const int fileIndex = 1;

    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext(filePaths[fileIndex].c_str(), ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(ContextState(ctx), ES2PANDA_STATE_CHECKED);
    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 7;
    bool result = lspApi->getSafeDeleteInfo(ctx, offset, "");
    ASSERT_EQ(result, true);

    initializer.DestroyContext(ctx);
}

TEST_F(LspGetSafeDeleteInfoTest, GetSafeDeleteInfoCase2)
{
    Initializer initializer = Initializer();
    es2panda_Context *ctx =
        initializer.CreateContext("get-safe-delete-info-case2.ets", ES2PANDA_STATE_CHECKED, "class A<T> {\n\n}");
    ASSERT_EQ(ContextState(ctx), ES2PANDA_STATE_CHECKED);
    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 8;
    bool result = lspApi->getSafeDeleteInfo(ctx, offset, "");
    ASSERT_EQ(result, true);
    initializer.DestroyContext(ctx);
}

TEST_F(LspGetSafeDeleteInfoTest, GetSafeDeleteInfoCase3)
{
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("get-safe-delete-info-case3.ets", ES2PANDA_STATE_CHECKED,
                                                      "let arr: Array<number>;\n");
    ASSERT_EQ(ContextState(ctx), ES2PANDA_STATE_CHECKED);
    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 10;
    bool result = lspApi->getSafeDeleteInfo(ctx, offset, "stdlib/escompat/Array.ets");
    ASSERT_EQ(result, true);
    initializer.DestroyContext(ctx);
}
}  // namespace
