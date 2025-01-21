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
