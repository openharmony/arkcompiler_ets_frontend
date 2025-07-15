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
#include "lsp_api_test.h"
#include "lsp/include/navigate_to.h"

namespace {

using ark::es2panda::SourceFile;
using ark::es2panda::lsp::GetNavigateToItems;
using ark::es2panda::lsp::Initializer;
using std::string;
using std::vector;

class NavigateToTest : public LSPAPITests {};

TEST_F(NavigateToTest, ExactMatchFromSingleFile)
{
    std::vector<SourceFile> files = {{"exatchMatch.sts", R"(
         class Test {
             yeke: number = 2;
             method() {
                 let b = 3;
                 return b;
             }
         }
         )"}};
    Initializer initializer;
    std::vector<ark::es2panda::lsp::NavigateToItem> allResults;
    const int maxResultCount = 10;
    const int expectedResultSize = 1;
    std::string searchTerm = "yeke";
    std::string containerName = "Test";

    for (const auto &file : files) {
        std::string sourceStr(file.source);
        es2panda_Context *ctx =
            initializer.CreateContext(file.filePath.data(), ES2PANDA_STATE_CHECKED, sourceStr.c_str());
        ASSERT_NE(ctx, nullptr);

        std::vector<SourceFile> singleFile = {{file.filePath, sourceStr}};
        auto results = GetNavigateToItems(ctx, singleFile, maxResultCount, searchTerm, false);
        allResults.insert(allResults.end(), results.begin(), results.end());
    }

    ASSERT_EQ(allResults.size(), expectedResultSize);
    ASSERT_EQ(allResults[0].name, searchTerm);
    ASSERT_EQ(allResults[0].matchKind, ark::es2panda::lsp::MatchKind::EXACT);
    ASSERT_EQ(allResults[0].containerName, containerName);
}

TEST_F(NavigateToTest, ExactPrefixAndSubstringMatch)
{
    std::vector<SourceFile> files = {{"ExactPrefixAndSubstringMatch1.sts", R"(
         function foo() {
             let a = 1;
             return a;
         }
         )"},
                                     {"ExactPrefixAndSubstringMatch2.sts", R"(
         function foobar() {
             let b = 2;
             return b;
         }
         )"},
                                     {"ExactPrefixAndSubstringMatch3.sts", R"(
         function my_foo() {
             let c = 3;
             return c;
         }
         )"}};
    Initializer initializer;
    std::vector<ark::es2panda::lsp::NavigateToItem> allResults;
    const int maxResultCount = 10;
    const int expectedResultSize = 3;
    std::string searchTerm = "foo";
    const int thirdValueOfArray = 2;
    std::string searchTermFoobar = "foobar";
    std::string searchTermMyFoo = "my_foo";

    for (const auto &file : files) {
        std::string sourceStr(file.source);
        es2panda_Context *ctx =
            initializer.CreateContext(file.filePath.data(), ES2PANDA_STATE_CHECKED, sourceStr.c_str());
        ASSERT_NE(ctx, nullptr);

        std::vector<SourceFile> singleFile = {{file.filePath, sourceStr}};
        auto results = GetNavigateToItems(ctx, singleFile, maxResultCount, searchTerm, false);
        allResults.insert(allResults.end(), results.begin(), results.end());

        initializer.DestroyContext(ctx);
    }
    ASSERT_EQ(allResults.size(), expectedResultSize);  // "foo", "foobar", "my_foo"
    ASSERT_EQ(allResults[0].name, searchTerm);
    ASSERT_EQ(allResults[0].matchKind, ark::es2panda::lsp::MatchKind::EXACT);
    ASSERT_EQ(allResults[1].name, searchTermFoobar);
    ASSERT_EQ(allResults[1].matchKind, ark::es2panda::lsp::MatchKind::PREFIX);
    ASSERT_EQ(allResults[thirdValueOfArray].name, searchTermMyFoo);
    ASSERT_EQ(allResults[thirdValueOfArray].matchKind, ark::es2panda::lsp::MatchKind::SUBSTRING);
}

TEST_F(NavigateToTest, CaseInsensitiveMatch)
{
    std::vector<SourceFile> files = {{"caseInsensitiveMatch1.sts", R"(
         function foo() {
             let a = 1;
             return a;
         }
         )"},
                                     {"caseInsensitiveMatch2.sts", R"(
         function foobar() {
             let b = 2;
             return b;
         }
         )"},
                                     {"caseInsensitiveMatch3.sts", R"(
         function my_foo() {
             let c = 3;
             return c;
         }
         )"}};
    Initializer initializer;
    std::vector<ark::es2panda::lsp::NavigateToItem> allResults;
    const int maxResultCount = 10;
    const int expectedResultSize = 3;
    std::string searchTerm = "FOO";

    for (const auto &file : files) {
        std::string sourceStr(file.source);
        es2panda_Context *ctx =
            initializer.CreateContext(file.filePath.data(), ES2PANDA_STATE_CHECKED, sourceStr.c_str());
        ASSERT_NE(ctx, nullptr);

        std::vector<SourceFile> singleFile = {{file.filePath, sourceStr}};
        auto results = GetNavigateToItems(ctx, singleFile, maxResultCount, searchTerm, false);  // case-insensitive
        allResults.insert(allResults.end(), results.begin(), results.end());

        initializer.DestroyContext(ctx);
    }
    ASSERT_EQ(allResults.size(), expectedResultSize);
}

TEST_F(NavigateToTest, CaseSensitiveMismatch)
{
    std::vector<SourceFile> files = {{"caseSensitiveMismatch1.sts", R"(
         function foo() {
             let a = 1;
             return a;
         }
         )"},
                                     {"caseSensitiveMismatch2.sts", R"(
         function foobar() {
             let b = 2;
             return b;
         }
         )"},
                                     {"caseSensitiveMismatch3.sts", R"(
         function my_foo() {
             let c = 3;
             return c;
         }
         )"}};
    Initializer initializer;
    std::vector<ark::es2panda::lsp::NavigateToItem> allResults;
    const int maxResultCount = 10;
    std::string searchTerm = "FOO";

    for (const auto &file : files) {
        std::string sourceStr(file.source);
        es2panda_Context *ctx =
            initializer.CreateContext(file.filePath.data(), ES2PANDA_STATE_CHECKED, sourceStr.c_str());
        ASSERT_NE(ctx, nullptr);

        std::vector<SourceFile> singleFile = {{file.filePath, sourceStr}};
        auto results = GetNavigateToItems(ctx, singleFile, maxResultCount, searchTerm, true);  // case-sensitive
        allResults.insert(allResults.end(), results.begin(), results.end());

        initializer.DestroyContext(ctx);
    }
    ASSERT_TRUE(allResults.empty());
}

TEST_F(NavigateToTest, NoMatchFound)
{
    std::vector<SourceFile> files = {{"noMatchFound1.sts", R"(
         function foo() {
             let a = 1;
             return a;
         }
         )"},
                                     {"noMatchFound2.sts", R"(
         function foobar() {
             let b = 2;
             return b;
         }
         )"},
                                     {"noMatchFound3.sts", R"(
         function my_foo() {
             let c = 3;
             return c;
         }
         )"}};
    Initializer initializer;
    std::vector<ark::es2panda::lsp::NavigateToItem> allResults;
    const int maxResultCount = 10;
    std::string searchTerm = "nonexistent";

    for (const auto &file : files) {
        std::string sourceStr(file.source);
        es2panda_Context *ctx =
            initializer.CreateContext(file.filePath.data(), ES2PANDA_STATE_CHECKED, sourceStr.c_str());
        ASSERT_NE(ctx, nullptr);

        std::vector<SourceFile> singleFile = {{file.filePath, sourceStr}};
        auto results = GetNavigateToItems(ctx, singleFile, maxResultCount, searchTerm, false);
        allResults.insert(allResults.end(), results.begin(), results.end());

        initializer.DestroyContext(ctx);
    }
    ASSERT_TRUE(allResults.empty());
}

}  // namespace