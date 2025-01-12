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

#include "lsp/include/api.h"
#include <gtest/gtest.h>
#include <string>
#include <vector>

class LSPPublicAPITests : public testing::Test {
public:
    LSPPublicAPITests() = default;
    ~LSPPublicAPITests() override = default;

    NO_COPY_SEMANTIC(LSPPublicAPITests);
    NO_MOVE_SEMANTIC(LSPPublicAPITests);

    std::vector<std::string> CreateTempFile(std::vector<std::string> files, std::vector<std::string> texts)
    {
        std::vector<std::string> result = {};
        auto tempDir = testing::TempDir();
        for (size_t i = 0; i < files.size(); i++) {
            auto outPath = tempDir + files[i];
            std::ofstream outStream(outPath);
            if (outStream.fail()) {
                std::cerr << "Failed to open file: " << outPath << std::endl;
                return result;
            }
            outStream << texts[i];
            outStream.close();
            result.push_back(outPath);
        }
        return result;
    }
};

TEST_F(LSPPublicAPITests, GetCurrentTokenValue1)
{
    std::vector<std::string> files = {"current_token.sts"};
    std::vector<std::string> texts = {"ab"};
    auto filePaths = CreateTempFile(files, texts);
    LSPAPI const *lspApi = GetImpl();
    size_t offset = 2;
    std::string result = lspApi->getCurrentTokenValue(filePaths[0].c_str(), offset);
    ASSERT_EQ(result, "ab");
}

TEST_F(LSPPublicAPITests, getSpanOfEnclosingComment1)
{
    std::vector<std::string> files = {"file1.sts"};
    std::vector<std::string> texts = {"function A(a:number, b:number) {\n  return a + b;  // add\n}\nA(1, 2);"};
    auto filePaths = CreateTempFile(files, texts);
    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 60;
    auto result = lspApi->getSpanOfEnclosingComment(filePaths[0].c_str(), offset, false);
    ASSERT_EQ(result, nullptr);
    auto result1 = lspApi->getSpanOfEnclosingComment(filePaths[0].c_str(), offset, true);
    ASSERT_EQ(result1, nullptr);
}

TEST_F(LSPPublicAPITests, getSpanOfEnclosingComment2)
{
    std::vector<std::string> files = {"file2.sts"};
    std::vector<std::string> texts = {"function A(a:number, b:number) {\n  return a + b;  // add\n}\nA(1, 2);"};
    auto filePaths = CreateTempFile(files, texts);
    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 54;
    auto result = lspApi->getSpanOfEnclosingComment(filePaths[0].c_str(), offset, false);
    size_t const startPostion = 50;
    size_t const length = 6;
    ASSERT_EQ(result->start, startPostion);
    ASSERT_EQ(result->length, length);
    auto result1 = lspApi->getSpanOfEnclosingComment(filePaths[0].c_str(), offset, true);
    ASSERT_EQ(result1, nullptr);
}

TEST_F(LSPPublicAPITests, getSpanOfEnclosingComment3)
{
    std::vector<std::string> files = {"file3.sts"};
    std::vector<std::string> texts = {"function A(a:number, b:number) {\n  return a + b;  /* add */\n}\nA(1, 2);"};
    auto filePaths = CreateTempFile(files, texts);
    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 54;
    auto result = lspApi->getSpanOfEnclosingComment(filePaths[0].c_str(), offset, false);
    size_t const startPostion = 50;
    size_t const length = 9;
    ASSERT_EQ(result->start, startPostion);
    ASSERT_EQ(result->length, length);
    auto result1 = lspApi->getSpanOfEnclosingComment(filePaths[0].c_str(), offset, true);
    ASSERT_EQ(result1->start, startPostion);
    ASSERT_EQ(result1->length, length);
}