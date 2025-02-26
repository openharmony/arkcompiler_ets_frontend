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
#include "lsp/include/completions.h"

class LSPCompletionsTests : public LSPAPITests {};

using ark::es2panda::lsp::CompletionEntry;
using ark::es2panda::lsp::sort_text::GLOBALS_OR_KEYWORDS;

void AssertCompletionsContainAndNotContainEntries(const std::vector<CompletionEntry> &entries,
                                                  const std::vector<CompletionEntry> &expectedEntries,
                                                  const std::vector<CompletionEntry> &unexpectedEntries)
{
    for (const auto &expectedEntry : expectedEntries) {
        bool found = false;
        for (const auto &entry : entries) {
            if (entry.GetName() == expectedEntry.GetName() &&
                entry.GetCompletionKind() == expectedEntry.GetCompletionKind()) {
                found = true;
                break;
            }
        }
        ASSERT_TRUE(found) << "Expected completion '" << expectedEntry.GetName() << "' not found";
    }

    for (const auto &unexpectedEntry : unexpectedEntries) {
        bool found = false;
        for (const auto &entry : entries) {
            if (entry.GetName() == unexpectedEntry.GetName() &&
                entry.GetCompletionKind() == unexpectedEntry.GetCompletionKind()) {
                found = true;
                break;
            }
        }
        ASSERT_FALSE(found) << "Unexpected completion '" << unexpectedEntry.GetName() << "' found";
    }
}

TEST_F(LSPCompletionsTests, getCompletionsAtPosition1)
{
    std::vector<std::string> files = {"getCompletionsAtPosition1.sts"};
    std::vector<std::string> texts = {R"delimiter(
function num1() {
    return 1;
}

function num2() {
    return 2;
}

let a = n
)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 80;  // after 'n' in 'let a = n'
    auto res = lspApi->getCompletionsAtPosition(filePaths[0].c_str(), offset);
    auto expectedEntries = std::vector<CompletionEntry> {
        CompletionEntry("num1", ark::es2panda::lsp::CompletionEntryKind::FUNCTION, std::string(GLOBALS_OR_KEYWORDS)),
        CompletionEntry("num2", ark::es2panda::lsp::CompletionEntryKind::FUNCTION, std::string(GLOBALS_OR_KEYWORDS)),
    };
    AssertCompletionsContainAndNotContainEntries(res.GetEntries(), expectedEntries, {});
}

TEST_F(LSPCompletionsTests, getCompletionsAtPosition2)
{
    std::vector<std::string> files = {"getCompletionsAtPosition2.sts"};
    std::vector<std::string> texts = {R"delimiter(
let aaa = 123;
const abb = 333;

function axx() {
    return 444;
}

function foo() {
    let bbb = 222;
    let ccc = bbb + a
    return bbb + ccc;
}
)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 127;  // after 'a' in 'let ccc = bbb + a'
    auto res = lspApi->getCompletionsAtPosition(filePaths[0].c_str(), offset);
    auto expectedEntries = std::vector<CompletionEntry> {
        CompletionEntry("aaa", ark::es2panda::lsp::CompletionEntryKind::VARIABLE, std::string(GLOBALS_OR_KEYWORDS)),
        CompletionEntry("abb", ark::es2panda::lsp::CompletionEntryKind::CONSTANT, std::string(GLOBALS_OR_KEYWORDS)),
        CompletionEntry("axx", ark::es2panda::lsp::CompletionEntryKind::FUNCTION, std::string(GLOBALS_OR_KEYWORDS)),
    };
    AssertCompletionsContainAndNotContainEntries(res.GetEntries(), expectedEntries, {});
}

TEST_F(LSPCompletionsTests, getCompletionsAtPosition3)
{
    std::vector<std::string> files = {"getCompletionsAtPosition3.sts"};
    std::vector<std::string> texts = {R"delimiter(
class Foo {
    bar: number = 1;
}

let foo = new Foo();
foo.bar = 2;
let baa = 3;
let bbb = 4;

function bxx() {
    return 5;
}

function fxx() {
    let bcc = 6;
    let axx = b
}
)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 181;  // after 'b' in 'let axx = b'
    auto res = lspApi->getCompletionsAtPosition(filePaths[0].c_str(), offset);
    auto expectedEntries = std::vector<CompletionEntry> {
        CompletionEntry("baa", ark::es2panda::lsp::CompletionEntryKind::VARIABLE, std::string(GLOBALS_OR_KEYWORDS)),
        CompletionEntry("bbb", ark::es2panda::lsp::CompletionEntryKind::VARIABLE, std::string(GLOBALS_OR_KEYWORDS)),
        CompletionEntry("bcc", ark::es2panda::lsp::CompletionEntryKind::VARIABLE, std::string(GLOBALS_OR_KEYWORDS)),
        CompletionEntry("bxx", ark::es2panda::lsp::CompletionEntryKind::FUNCTION, std::string(GLOBALS_OR_KEYWORDS)),
    };
    auto unexpectedEntries = std::vector<CompletionEntry> {
        CompletionEntry("bar", ark::es2panda::lsp::CompletionEntryKind::VARIABLE, std::string(GLOBALS_OR_KEYWORDS)),
    };
    AssertCompletionsContainAndNotContainEntries(res.GetEntries(), expectedEntries, unexpectedEntries);
}

TEST_F(LSPCompletionsTests, getCompletionsAtPosition4)
{
    std::vector<std::string> files = {"getCompletionsAtPosition4.sts"};
    std::vector<std::string> texts = {R"delimiter(
class Foo {
    bar: number = 1;
}

let foo = new Foo();
foo.bar = 2;
let baa = 3;
let bbb = 4;

function bxx() {
    let bcc = 6;
    return 5;
}
let axx = b
)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 159;  // after 'b' in 'let axx = b'
    auto res = lspApi->getCompletionsAtPosition(filePaths[0].c_str(), offset);
    auto expectedEntries = std::vector<CompletionEntry> {
        CompletionEntry("baa", ark::es2panda::lsp::CompletionEntryKind::VARIABLE, std::string(GLOBALS_OR_KEYWORDS)),
        CompletionEntry("bbb", ark::es2panda::lsp::CompletionEntryKind::VARIABLE, std::string(GLOBALS_OR_KEYWORDS)),
        CompletionEntry("bxx", ark::es2panda::lsp::CompletionEntryKind::FUNCTION, std::string(GLOBALS_OR_KEYWORDS)),
    };
    auto unexpectedEntries = std::vector<CompletionEntry> {
        CompletionEntry("bar", ark::es2panda::lsp::CompletionEntryKind::PROPERTY, std::string(GLOBALS_OR_KEYWORDS)),
        CompletionEntry("bcc", ark::es2panda::lsp::CompletionEntryKind::VARIABLE, std::string(GLOBALS_OR_KEYWORDS)),
    };
    AssertCompletionsContainAndNotContainEntries(res.GetEntries(), expectedEntries, unexpectedEntries);
}