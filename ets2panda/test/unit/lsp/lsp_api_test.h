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

#ifndef ES2PANDA_TEST_LSP_API_TEST_H
#define ES2PANDA_TEST_LSP_API_TEST_H

#include "lsp/include/api.h"
#include "lsp/include/internal_api.h"
#include <gtest/gtest.h>
#include "test/utils/ast_verifier_test.h"

class LSPAPITests : public test::utils::AstVerifierTest {
public:
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

    Range CreateTestRange()
    {
        int const endPos = 10;
        Position start(1, 0);
        Position end(1, endPos);
        return Range(start, end);
    }

    void SetUp() override
    {
        range_ = CreateTestRange();
        message_ = R"(Test message)";
    }

protected:
    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    Range range_;
    std::string message_;
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

#endif
