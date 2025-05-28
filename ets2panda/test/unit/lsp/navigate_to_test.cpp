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

TEST_F(NavigateToTest, EmptySourceFiles)
{
    std::vector<SourceFile> srcFiles;
    Initializer initializer;
    std::vector<ark::es2panda::lsp::NavigateToItem> allResults;
    const int maxResultCount = 10;
    std::string searchTerm = "foo";

    for (const auto &file : srcFiles) {
        std::string sourceStr(file.source);
        es2panda_Context *ctx =
            initializer.CreateContext(file.filePath.data(), ES2PANDA_STATE_CHECKED, sourceStr.c_str());
        ASSERT_NE(ctx, nullptr);

        std::vector<SourceFile> singleFile = {{file.filePath, sourceStr}};
        auto results = GetNavigateToItems(ctx, singleFile, maxResultCount, searchTerm, false);
        allResults.insert(allResults.end(), results.begin(), results.end());
    }
    ASSERT_TRUE(allResults.empty());
}

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

TEST_F(NavigateToTest, MatchLimitRespected)
{
    std::vector<SourceFile> files = {{"matchLimitRespected1.sts", R"(
         function foo() {
             let a = 1;
             return a;
         }
         )"},
                                     {"matchLimitRespected2.sts", R"(
         function foobar() {
             let b = 2;
             return b;
         }
         )"},
                                     {"matchLimitRespected3.sts", R"(
         function my_foo() {
             let c = 3;
             return c;
         }
         )"}};
    const int maxResultCountTwo = 2;
    const int expectedResultSize = 2;
    std::string searchTerm = "foo";

    Initializer initializer;
    std::vector<ark::es2panda::lsp::NavigateToItem> allResults;

    for (const auto &file : files) {
        std::string sourceStr(file.source);
        es2panda_Context *ctx =
            initializer.CreateContext(file.filePath.data(), ES2PANDA_STATE_CHECKED, sourceStr.c_str());
        ASSERT_NE(ctx, nullptr);

        std::vector<SourceFile> singleFile = {{file.filePath, sourceStr}};
        auto matches = GetNavigateToItems(ctx, singleFile, maxResultCountTwo, searchTerm, false);
        allResults.insert(allResults.end(), matches.begin(), matches.end());

        initializer.DestroyContext(ctx);
    }

    ASSERT_LE(allResults.size(), expectedResultSize);
}

TEST_F(NavigateToTest, MultiFileSubstringMatch)
{
    std::vector<SourceFile> files = {{"multiFileSubstringMatch1.sts", R"(
         function foo() {
             let a = 1;
             return a;
         }
         )"},
                                     {"multiFileSubstringMatch2.sts", R"(
         function foobar() {
             let b = 2;
             return b;
         }
         )"},
                                     {"multiFileSubstringMatch3.sts", R"(
         function my_foo() {
             let c = 3;
             return c;
         }
         )"}};
    Initializer initializer;
    const int maxResultCount = 10;
    size_t totalMatches = 0;
    std::string searchTerm = "_foo";
    const int expectedResultSize = 1;

    for (const auto &file : files) {
        std::string sourceStr(file.source);
        es2panda_Context *ctx =
            initializer.CreateContext(file.filePath.data(), ES2PANDA_STATE_CHECKED, sourceStr.c_str());
        ASSERT_NE(ctx, nullptr);

        std::vector<SourceFile> singleFile = {{file.filePath, sourceStr}};
        auto matches = GetNavigateToItems(ctx, singleFile, maxResultCount, searchTerm, false);
        totalMatches += matches.size();

        initializer.DestroyContext(ctx);
    }

    ASSERT_EQ(totalMatches, expectedResultSize);
}

TEST_F(NavigateToTest, PrefixMatchOnly)
{
    std::vector<SourceFile> files = {{"prefixMatchOnly1.sts", R"(
         function foo() {
             let a = 1;
             return a;
         }
         )"},
                                     {"prefixMatchOnly2.sts", R"(
         function foobar() {
             let b = 2;
             return b;
         }
         )"},
                                     {"prefixMatchOnly3.sts", R"(
         function my_foo() {
             let c = 3;
             return c;
         }
         )"}};
    Initializer initializer;
    const int maxResultCount = 10;
    size_t prefixCount = 0;
    const int expectedResultSize = 1;
    std::string searchTerm = "foo";

    for (const auto &file : files) {
        std::string sourceStr(file.source);
        es2panda_Context *ctx =
            initializer.CreateContext(file.filePath.data(), ES2PANDA_STATE_CHECKED, sourceStr.c_str());
        ASSERT_NE(ctx, nullptr);

        std::vector<SourceFile> singleFile = {{file.filePath, sourceStr}};
        auto matches = GetNavigateToItems(ctx, singleFile, maxResultCount, searchTerm, false);
        for (const auto &match : matches) {
            if (match.matchKind == ark::es2panda::lsp::MatchKind::PREFIX) {
                ++prefixCount;
            }
        }

        initializer.DestroyContext(ctx);
    }

    ASSERT_EQ(prefixCount, expectedResultSize);  // Only "foobar" is a PREFIX of "foo"
}

TEST_F(NavigateToTest, MatchFromSecondFile)
{
    std::vector<SourceFile> files = {{"matchFromSecondFile1.sts", R"(
         function foo() {
             let a = 1;
             return a;
         }
         )"},
                                     {"matchFromSecondFile2.sts", R"(
         function foobar() {
             let b = 2;
             return b;
         }
         )"},
                                     {"matchFromSecondFile3.sts", R"(
         function my_foo() {
             let c = 3;
             return c;
         }
         )"}};
    Initializer initializer;
    const int maxResultCount = 10;
    const int expectedResultSize = 1;
    std::string searchTerm = "foobar";
    std::vector<ark::es2panda::lsp::NavigateToItem> matches;

    for (const auto &file : files) {
        std::string sourceStr(file.source);
        es2panda_Context *ctx =
            initializer.CreateContext(file.filePath.data(), ES2PANDA_STATE_CHECKED, sourceStr.c_str());
        ASSERT_NE(ctx, nullptr);

        std::vector<SourceFile> singleFile = {{file.filePath, sourceStr}};
        auto results = GetNavigateToItems(ctx, singleFile, maxResultCount, searchTerm, false);
        matches.insert(matches.end(), results.begin(), results.end());

        initializer.DestroyContext(ctx);
    }
    ASSERT_EQ(matches.size(), expectedResultSize);
    ASSERT_EQ(matches[0].name, searchTerm);
}

TEST_F(NavigateToTest, MatchOnClassMember)
{
    std::vector<SourceFile> files = {{"matchOnClassMember1.sts", R"(
         class Test {
             yeke: number = 2;
             method() {
                 let b = 3;
                 return b;
             }
         }
         )"},
                                     {"matchOnClassMember2.sts", R"(
         function foobar() {
             let b = 2;
             return b;
         }
         )"},
                                     {"matchOnClassMember3.sts", R"(
         function my_foo() {
             let c = 3;
             return c;
         }
         )"}};
    Initializer initializer;
    const int maxResultCount = 10;
    const int expectedResultSize = 1;
    std::string searchTerm = "yeke";
    std::string containerName = "Test";
    std::vector<ark::es2panda::lsp::NavigateToItem> results;

    for (const auto &file : files) {
        std::string sourceStr(file.source);
        es2panda_Context *ctx =
            initializer.CreateContext(file.filePath.data(), ES2PANDA_STATE_CHECKED, sourceStr.c_str());
        ASSERT_NE(ctx, nullptr);

        std::vector<SourceFile> singleFile = {{file.filePath, sourceStr}};
        auto items = GetNavigateToItems(ctx, singleFile, maxResultCount, searchTerm, false);
        results.insert(results.end(), items.begin(), items.end());

        initializer.DestroyContext(ctx);
    }

    ASSERT_EQ(results.size(), expectedResultSize);
    ASSERT_EQ(results[0].name, searchTerm);
    ASSERT_EQ(results[0].containerName, containerName);
}

}  // namespace