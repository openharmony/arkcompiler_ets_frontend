/**
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include <vector>

#include "driver/dependency_analyzer/dep_analyzer.h"
#include "macros.h"
#include "path_getter.h"
#include "os/filesystem.h"

namespace {

class DepAnalyzerTest : public testing::Test {
public:
    DepAnalyzerTest() = default;
    ~DepAnalyzerTest() override = default;
    NO_COPY_SEMANTIC(DepAnalyzerTest);
    NO_MOVE_SEMANTIC(DepAnalyzerTest);

    void RunDepAnalyzer(size_t testFolderNum)
    {
        std::string binPath = test::utils::DepAnalyzerTestsBinPathGet();
        std::string testPath = test::utils::DepAnalyzerTestsPathGet(testFolderNum, 1);
        options_ = {binPath.c_str(), testPath.c_str()};

        depAnalyzer_.AnalyzeDeps(optionsSize_, options_.data());
    }

    void GetExpectedAns(std::vector<std::string> &expected, size_t testFolderNum, size_t testFileCounter)
    {
        for (size_t i = 1; i < testFileCounter + 1; ++i) {
            std::string expPath = test::utils::DepAnalyzerTestsPathGet(testFolderNum, i);
            expected.push_back(ark::os::GetAbsolutePath(expPath));
        }
    }

    const std::vector<std::string> &GetTestSourcePaths()
    {
        return depAnalyzer_.GetSourcePaths();
    }

private:
    DepAnalyzer depAnalyzer_;

    const size_t optionsSize_ = 2;
    std::vector<const char *> options_ = {};
};

TEST_F(DepAnalyzerTest, Subtestv1)
{
    size_t testFolderNum = 1;
    size_t testFileCounter = 1;
    RunDepAnalyzer(testFolderNum);
    std::vector<std::string> expected;
    GetExpectedAns(expected, testFolderNum, testFileCounter);
    ASSERT(GetTestSourcePaths() == expected);
}

TEST_F(DepAnalyzerTest, Subtestv2)
{
    size_t testFolderNum = 2;
    size_t testFileCounter = 4;
    RunDepAnalyzer(testFolderNum);
    std::vector<std::string> expected;
    GetExpectedAns(expected, testFolderNum, testFileCounter);
    ASSERT(GetTestSourcePaths() == expected);
}

TEST_F(DepAnalyzerTest, Subtestv3)
{
    size_t testFolderNum = 3;
    size_t testFileCounter = 2;
    RunDepAnalyzer(testFolderNum);
    std::vector<std::string> expected;
    GetExpectedAns(expected, testFolderNum, testFileCounter);
    ASSERT(GetTestSourcePaths() == expected);
}

TEST_F(DepAnalyzerTest, Subtestv4)
{
    size_t testFolderNum = 4;
    size_t testFileCounter = 2;
    RunDepAnalyzer(testFolderNum);
    std::vector<std::string> expected;
    GetExpectedAns(expected, testFolderNum, testFileCounter);
    ASSERT(GetTestSourcePaths() == expected);
}

}  // namespace
