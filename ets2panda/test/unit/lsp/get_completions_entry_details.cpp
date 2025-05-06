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
#include "lsp/include/internal_api.h"
#include "lsp/include/api.h"
#include "lsp/include/completions_details.h"

namespace {

class LSPCompletionsEntryDetailsTests : public LSPAPITests {};

using ark::es2panda::lsp::Initializer;

TEST_F(LSPCompletionsEntryDetailsTests, GetCompletionEntryDetails0)
{
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("completion_entry_details.ets", ES2PANDA_STATE_CHECKED,
                                                      R"(enum MyStrings { A = 'hello' };)");
    size_t const offset = 17;
    LSPAPI const *lspApi = GetImpl();
    const char *entryName = "MyStrings";
    auto completionEntryDetails =
        lspApi->getCompletionEntryDetails(entryName, "completion_entry_details.ets", ctx, offset);
    ASSERT_NE(completionEntryDetails, CompletionEntryDetails());
    std::vector<SymbolDisplayPart> source {};
    std::vector<SymbolDisplayPart> sourceDisplay {};
    std::vector<SymbolDisplayPart> document {};
    const std::string kind = "class";
    const std::string kindModifiers = "final";
    const std::string expectedFileName = "completion_entry_details.ets";

    std::vector<SymbolDisplayPart> expected;
    expected.emplace_back("enum", "keyword");
    expected.emplace_back(" ", "space");
    expected.emplace_back("MyStrings", "className");

    auto expectedCompletionEntryDetails = CompletionEntryDetails(entryName, kind, kindModifiers, expected, document,
                                                                 source, sourceDisplay, expectedFileName);
    initializer.DestroyContext(ctx);
    ASSERT_EQ(completionEntryDetails, expectedCompletionEntryDetails);
}

TEST_F(LSPCompletionsEntryDetailsTests, GetCompletionEntryDetails1)
{
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("completion_entry_details1.ets", ES2PANDA_STATE_CHECKED,
                                                      "class MyClass {\n  public myProp: number = 0;\n}");
    ASSERT_EQ(ContextState(ctx), ES2PANDA_STATE_CHECKED);
    size_t const offset = 9;
    LSPAPI const *lspApi = GetImpl();
    const char *entryName = "MyClass";
    const std::string fileName = "completion_entry_details1.ets";
    auto completionEntryDetails =
        lspApi->getCompletionEntryDetails(entryName, "completion_entry_details1.ets", ctx, offset);
    ASSERT_NE(completionEntryDetails, CompletionEntryDetails());
    std::vector<SymbolDisplayPart> source {};
    std::vector<SymbolDisplayPart> sourceDisplay {};
    std::vector<SymbolDisplayPart> document {};
    const std::string kind = "class";
    const std::string kindModifiers;
    const std::string expectedFileName = "completion_entry_details1.ets";

    std::vector<SymbolDisplayPart> expected;
    expected.emplace_back("class", "keyword");
    expected.emplace_back(" ", "space");
    expected.emplace_back("MyClass", "className");

    auto expectedCompletionEntryDetails = CompletionEntryDetails(entryName, kind, kindModifiers, expected, document,
                                                                 source, sourceDisplay, expectedFileName);
    ASSERT_EQ(completionEntryDetails, expectedCompletionEntryDetails);

    initializer.DestroyContext(ctx);
}

TEST_F(LSPCompletionsEntryDetailsTests, GetCompletionEntryDetails2)
{
    Initializer initializer = Initializer();
    es2panda_Context *ctx =
        initializer.CreateContext("completion_entry_details2.ets", ES2PANDA_STATE_CHECKED,
                                  "interface objI { key : string; }\nlet obj : objI = { key:\"valueaaaaaaaaa,\" }");
    ASSERT_EQ(ContextState(ctx), ES2PANDA_STATE_CHECKED);
    size_t const offset = 7;
    LSPAPI const *lspApi = GetImpl();
    const char *entryName = "objI";
    const std::string fileName = "completion_entry_details2.ets";
    auto completionEntryDetails =
        lspApi->getCompletionEntryDetails(entryName, "completion_entry_details2.ets", ctx, offset);
    ASSERT_NE(completionEntryDetails, CompletionEntryDetails());
    std::vector<SymbolDisplayPart> source {};
    std::vector<SymbolDisplayPart> sourceDisplay {};
    std::vector<SymbolDisplayPart> document {};
    const std::string kind = "interface";
    const std::string kindModifiers = "static public";
    const std::string expectedFileName = "completion_entry_details2.ets";
    std::vector<SymbolDisplayPart> expected;

    expected.emplace_back("interface", "keyword");
    expected.emplace_back(" ", "space");
    expected.emplace_back("objI", "className");

    auto expectedCompletionEntryDetails = CompletionEntryDetails(entryName, kind, kindModifiers, expected, document,
                                                                 source, sourceDisplay, expectedFileName);
    ASSERT_EQ(completionEntryDetails, expectedCompletionEntryDetails);

    initializer.DestroyContext(ctx);
}

}  // namespace