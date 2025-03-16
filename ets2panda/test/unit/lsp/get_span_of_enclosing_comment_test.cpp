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

#include "lsp_api_test.h"
#include <string>
#include <vector>

class LspGetSpanTests : public LSPAPITests {};

TEST_F(LspGetSpanTests, getSpanOfEnclosingComment1)
{
    std::vector<std::string> files = {"get_span_1.ets"};
    std::vector<std::string> texts = {"function A(a:number, b:number) {\n  return a + b;  // add\n}\nA(1, 2);"};
    auto filePaths = CreateTempFile(files, texts);
    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 60;
    auto result = lspApi->getSpanOfEnclosingComment(filePaths[0].c_str(), offset, false);
    size_t const startPostion = 0;
    size_t const length = 0;
    ASSERT_EQ(result.start, startPostion);
    ASSERT_EQ(result.length, length);
    auto result1 = lspApi->getSpanOfEnclosingComment(filePaths[0].c_str(), offset, true);
    ASSERT_EQ(result1.start, startPostion);
    ASSERT_EQ(result1.length, length);
}

TEST_F(LspGetSpanTests, getSpanOfEnclosingComment2)
{
    std::vector<std::string> files = {"get_span_2.ets"};
    std::vector<std::string> texts = {"function A(a:number, b:number) {\n  return a + b;  // add\n}\nA(1, 2);"};
    auto filePaths = CreateTempFile(files, texts);
    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 54;
    auto result = lspApi->getSpanOfEnclosingComment(filePaths[0].c_str(), offset, false);
    size_t const startPostion = 50;
    size_t const length = 6;
    ASSERT_EQ(result.start, startPostion);
    ASSERT_EQ(result.length, length);
    auto result1 = lspApi->getSpanOfEnclosingComment(filePaths[0].c_str(), offset, true);
    size_t const startPostion1 = 0;
    size_t const length1 = 0;
    ASSERT_EQ(result1.start, startPostion1);
    ASSERT_EQ(result1.length, length1);
}

TEST_F(LspGetSpanTests, getSpanOfEnclosingComment3)
{
    std::vector<std::string> files = {"get_span_3.ets"};
    std::vector<std::string> texts = {"function A(a:number, b:number) {\n  return a + b;  /* add */\n}\nA(1, 2);"};
    auto filePaths = CreateTempFile(files, texts);
    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 54;
    auto result = lspApi->getSpanOfEnclosingComment(filePaths[0].c_str(), offset, false);
    size_t const startPostion = 50;
    size_t const length = 9;
    ASSERT_EQ(result.start, startPostion);
    ASSERT_EQ(result.length, length);
    auto result1 = lspApi->getSpanOfEnclosingComment(filePaths[0].c_str(), offset, true);
    ASSERT_EQ(result1.start, startPostion);
    ASSERT_EQ(result1.length, length);
}
